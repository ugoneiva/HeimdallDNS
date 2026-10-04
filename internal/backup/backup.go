// Package backup gera e restaura cópias do HeimdallDNS: um .tar.gz com o
// banco, a configuração e um manifesto; com senha, o arquivo inteiro é
// cifrado no formato age (scrypt + ChaCha20-Poly1305), que também abre com a
// ferramenta "age -d".
//
// A restauração é em duas etapas: Stage confere o arquivo e o deixa em
// <data_dir>/restaurar; na próxima partida, ApplyStaged troca o banco antes de
// abri-lo (o atual fica guardado ao lado).
package backup

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

const (
	dbName       = "heimdall.db"
	configName   = "heimdalldns.yaml"
	manifestName = "manifest.json"
	stageDir     = "restaurar"
	ageMagic     = "age-encryption.org/v1"
	maxDBSize    = 4 << 30 // 4 GiB: barreira contra arquivos maliciosos
	maxSmallSize = 1 << 20
)

// ErrPassphrase indica um backup cifrado sem senha ou com a senha errada.
var ErrPassphrase = errors.New("backup cifrado: senha ausente ou incorreta")

// Manifest descreve o conteúdo do backup.
type Manifest struct {
	App       string    `json:"app"`
	Version   string    `json:"version"`
	Schema    int       `json:"schema"`
	Created   time.Time `json:"created"`
	Hostname  string    `json:"hostname"`
	Full      bool      `json:"full"`       // com o histórico de consultas
	HasConfig bool      `json:"has_config"` // inclui o arquivo de configuração
	Encrypted bool      `json:"encrypted"`
}

type Options struct {
	Store      *store.Store
	TempDir    string // onde montar a cópia do banco (o data_dir)
	ConfigPath string // "" = sem configuração
	Full       bool
	Passphrase string // "" = sem cifra
	Version    string
}

// Write gera o backup em w.
func Write(w io.Writer, o Options) (Manifest, error) {
	tmp, err := os.CreateTemp(o.TempDir, ".backup-*.db")
	if err != nil {
		return Manifest{}, err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	if err := o.Store.SnapshotTo(tmp.Name(), o.Full); err != nil {
		return Manifest{}, err
	}
	host, _ := os.Hostname()
	m := Manifest{App: "heimdalldns", Version: o.Version, Schema: store.SchemaVersion(), Created: time.Now().UTC(),
		Hostname: host, Full: o.Full, Encrypted: o.Passphrase != ""}
	var cfg []byte
	if o.ConfigPath != "" {
		if cfg, err = os.ReadFile(o.ConfigPath); err == nil {
			m.HasConfig = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return m, fmt.Errorf("configuração: %w", err)
		}
	}

	out := w
	var enc io.WriteCloser
	if o.Passphrase != "" {
		r, err := age.NewScryptRecipient(o.Passphrase)
		if err != nil {
			return m, err
		}
		if enc, err = age.Encrypt(w, r); err != nil {
			return m, err
		}
		out = enc
	}
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	mb, _ := json.MarshalIndent(m, "", "  ")
	if err := addBytes(tw, manifestName, mb); err != nil {
		return m, err
	}
	if err := addFile(tw, dbName, tmp.Name()); err != nil {
		return m, err
	}
	if m.HasConfig {
		if err := addBytes(tw, configName, cfg); err != nil {
			return m, err
		}
	}
	if err := tw.Close(); err != nil {
		return m, err
	}
	if err := gz.Close(); err != nil {
		return m, err
	}
	if enc != nil {
		if err := enc.Close(); err != nil {
			return m, err
		}
	}
	return m, nil
}

func addBytes(tw *tar.Writer, name string, b []byte) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), ModTime: time.Now()}); err != nil {
		return err
	}
	_, err := tw.Write(b)
	return err
}

func addFile(tw *tar.Writer, name, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: fi.Size(), ModTime: fi.ModTime()}); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

// Archive é um backup aberto e conferido, com o banco num arquivo temporário.
type Archive struct {
	Manifest Manifest
	Config   []byte // nil = sem configuração
	dbPath   string
	dir      string
}

// Close apaga os temporários.
func (a *Archive) Close() error { return os.RemoveAll(a.dir) }

// Open lê e confere um backup (cifrado ou não). tempDir deve estar no mesmo
// sistema de arquivos do data_dir, para Stage só renomear.
func Open(r io.Reader, passphrase, tempDir string) (*Archive, error) {
	br := bufio.NewReader(r)
	head, _ := br.Peek(len(ageMagic))
	var in io.Reader = br
	encrypted := string(head) == ageMagic
	if encrypted {
		if passphrase == "" {
			return nil, ErrPassphrase
		}
		id, err := age.NewScryptIdentity(passphrase)
		if err != nil {
			return nil, err
		}
		dec, err := age.Decrypt(br, id)
		if err != nil {
			var nm *age.NoIdentityMatchError
			if errors.As(err, &nm) || strings.Contains(err.Error(), "incorrect") {
				return nil, ErrPassphrase
			}
			return nil, fmt.Errorf("backup cifrado: %w", err)
		}
		in = dec
	}
	gz, err := gzip.NewReader(in)
	if err != nil {
		return nil, errors.New("o arquivo não é um backup do HeimdallDNS (.tar.gz ou cifrado com age)")
	}
	dir, err := os.MkdirTemp(tempDir, ".restaurar-*")
	if err != nil {
		return nil, err
	}
	a := &Archive{dir: dir, dbPath: filepath.Join(dir, dbName)}
	fail := func(err error) (*Archive, error) {
		a.Close()
		return nil, err
	}
	var gotManifest, gotDB bool
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fail(fmt.Errorf("backup danificado: %w", err))
		}
		switch h.Name {
		case manifestName:
			b, err := io.ReadAll(io.LimitReader(tr, maxSmallSize))
			if err != nil {
				return fail(err)
			}
			if err := json.Unmarshal(b, &a.Manifest); err != nil || a.Manifest.App != "heimdalldns" {
				return fail(errors.New("manifesto inválido: não é um backup do HeimdallDNS"))
			}
			gotManifest = true
		case configName:
			if a.Config, err = io.ReadAll(io.LimitReader(tr, maxSmallSize)); err != nil {
				return fail(err)
			}
		case dbName:
			if h.Size > maxDBSize {
				return fail(errors.New("banco grande demais"))
			}
			f, err := os.OpenFile(a.dbPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return fail(err)
			}
			_, err = io.Copy(f, io.LimitReader(tr, maxDBSize))
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return fail(err)
			}
			gotDB = true
		} // outros nomes são ignorados (nunca extraídos para o disco)
	}
	if !gotManifest || !gotDB {
		return fail(errors.New("backup incompleto: falta o manifesto ou o banco"))
	}
	if _, err := store.CheckFile(a.dbPath); err != nil {
		return fail(err)
	}
	a.Manifest.Encrypted = encrypted
	return a, nil
}

// Stage deixa o banco do backup pronto para entrar na próxima partida.
func (a *Archive) Stage(dataDir string) error {
	dir := filepath.Join(dataDir, stageDir)
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Rename(a.dbPath, filepath.Join(dir, dbName)); err != nil {
		return err
	}
	mb, _ := json.Marshal(a.Manifest)
	return os.WriteFile(filepath.Join(dir, manifestName), mb, 0o600)
}

// Staged devolve o manifesto da restauração pendente, se houver.
func Staged(dataDir string) (*Manifest, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, stageDir, manifestName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var m Manifest
	return &m, json.Unmarshal(b, &m)
}

// CancelStaged desiste da restauração pendente.
func CancelStaged(dataDir string) error { return os.RemoveAll(filepath.Join(dataDir, stageDir)) }

// ApplyStaged troca o banco pelo da restauração pendente. Chame antes de
// abrir o banco. O banco anterior fica em heimdall.db.antes-<data>.
func ApplyStaged(dataDir string) (*Manifest, string, error) {
	m, err := Staged(dataDir)
	if err != nil || m == nil {
		return nil, "", err
	}
	staged := filepath.Join(dataDir, stageDir, dbName)
	if _, err := store.CheckFile(staged); err != nil {
		return nil, "", fmt.Errorf("restauração pendente inválida: %w", err)
	}
	cur := filepath.Join(dataDir, dbName)
	keep := cur + ".antes-" + time.Now().Format("20060102-150405")
	for _, suf := range []string{"", "-wal", "-shm"} {
		if err := os.Rename(cur+suf, keep+suf); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, "", err
		}
	}
	if err := os.Rename(staged, cur); err != nil {
		return nil, "", err
	}
	return m, keep, CancelStaged(dataDir)
}

// Auto mantém cópias automáticas em dir, guardando as keep mais novas.
type Auto struct {
	Options
	Dir  string
	Keep int
}

const autoPrefix = "heimdalldns-auto-"

// RunOnce gera uma cópia e apaga as excedentes.
func (a Auto) RunOnce() (string, error) {
	if err := os.MkdirAll(a.Dir, 0o700); err != nil {
		return "", err
	}
	name := filepath.Join(a.Dir, autoPrefix+time.Now().Format("20060102-150405")+".tar.gz")
	f, err := os.OpenFile(name+".parcial", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	_, err = Write(f, a.Options)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(name + ".parcial")
		return "", err
	}
	if err := os.Rename(name+".parcial", name); err != nil {
		return "", err
	}
	return name, a.prune()
}

func (a Auto) prune() error {
	files, err := List(a.Dir)
	if err != nil {
		return err
	}
	for i, f := range files {
		if i >= max(1, a.Keep) {
			if err := os.Remove(filepath.Join(a.Dir, f.Name)); err != nil {
				return err
			}
		}
	}
	return nil
}

// File é uma cópia automática.
type File struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	Created time.Time `json:"created"`
}

// List devolve as cópias automáticas, a mais nova primeiro.
func List(dir string) ([]File, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return []File{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []File{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), autoPrefix) || !strings.HasSuffix(e.Name(), ".tar.gz") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, File{Name: e.Name(), Size: fi.Size(), Created: fi.ModTime()})
	}
	slices.SortFunc(out, func(x, y File) int { return strings.Compare(y.Name, x.Name) }) // o nome leva a data
	return out, nil
}

// ValidName diz se name é uma cópia automática (sem caminho).
func ValidName(name string) bool {
	return strings.HasPrefix(name, autoPrefix) && strings.HasSuffix(name, ".tar.gz") &&
		!strings.ContainsAny(name, "/\\") && !bytes.Contains([]byte(name), []byte(".."))
}
