// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package backup

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

func newStore(t *testing.T, dir string) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(dir, "heimdall.db"))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestRoundTrip(t *testing.T) {
	for _, pass := range []string{"", "frase longa de teste"} {
		t.Run("senha="+pass, func(t *testing.T) {
			src := t.TempDir()
			st := newStore(t, src)
			if _, err := st.AddList("Minha lista", "https://exemplo.com/l.txt", ""); err != nil {
				t.Fatal(err)
			}
			if err := st.CreateSession("hash-da-sessao", 1, timeFar()); err != nil {
				t.Fatal(err)
			}
			cfg := filepath.Join(src, "heimdalldns.yaml")
			os.WriteFile(cfg, []byte("dns:\n  listen: [':53']\n"), 0o600)

			var buf bytes.Buffer
			m, err := Write(&buf, Options{Store: st, TempDir: src, ConfigPath: cfg, Passphrase: pass, Version: "teste"})
			if err != nil {
				t.Fatal(err)
			}
			st.Close()
			if m.Encrypted != (pass != "") || !m.HasConfig || m.Schema != store.SchemaVersion() {
				t.Errorf("manifesto = %+v", m)
			}
			raw := buf.Bytes()
			if pass != "" {
				if bytes.Contains(raw, []byte("Minha lista")) {
					t.Fatal("cifrado não pode ter texto aberto")
				}
				if _, err := Open(bytes.NewReader(raw), "", t.TempDir()); !errors.Is(err, ErrPassphrase) {
					t.Errorf("sem senha: %v", err)
				}
				if _, err := Open(bytes.NewReader(raw), "errada", t.TempDir()); !errors.Is(err, ErrPassphrase) {
					t.Errorf("senha errada: %v", err)
				}
			}

			dst := t.TempDir()
			old := newStore(t, dst) // banco atual que será trocado
			old.Close()
			a, err := Open(bytes.NewReader(raw), pass, dst)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(a.Config), "listen") {
				t.Error("configuração não veio")
			}
			if err := a.Stage(dst); err != nil {
				t.Fatal(err)
			}
			a.Close()
			if m, _ := Staged(dst); m == nil || m.Version != "teste" {
				t.Fatalf("pendente = %+v", m)
			}
			m2, keep, err := ApplyStaged(dst)
			if err != nil || m2 == nil {
				t.Fatal(m2, err)
			}
			if _, err := os.Stat(keep); err != nil {
				t.Error("o banco anterior deveria ficar guardado")
			}
			st2 := newStore(t, dst)
			defer st2.Close()
			ls, _ := st2.Lists()
			if len(ls) != 1 || ls[0].Name != "Minha lista" {
				t.Errorf("listas restauradas = %+v", ls)
			}
			if _, ok, _ := st2.Session("hash-da-sessao"); ok {
				t.Error("sessões não podem ir no backup")
			}
			if m, _ := Staged(dst); m != nil {
				t.Error("a pendência deveria sumir")
			}
		})
	}
}

func TestRejectsGarbage(t *testing.T) {
	if _, err := Open(strings.NewReader("isto não é backup"), "", t.TempDir()); err == nil {
		t.Error("lixo deveria falhar")
	}
}

func TestAutoKeep(t *testing.T) {
	dir := t.TempDir()
	st := newStore(t, dir)
	defer st.Close()
	bdir := filepath.Join(dir, "backups")
	for _, n := range []string{"20260101-000000", "20260102-000000", "20260103-000000"} {
		os.MkdirAll(bdir, 0o700)
		os.WriteFile(filepath.Join(bdir, autoPrefix+n+".tar.gz"), []byte("x"), 0o600)
	}
	name, err := Auto{Options: Options{Store: st, TempDir: dir}, Dir: bdir, Keep: 2}.RunOnce()
	if err != nil {
		t.Fatal(err)
	}
	files, _ := List(bdir)
	if len(files) != 2 || files[0].Name != filepath.Base(name) || files[1].Name != autoPrefix+"20260103-000000.tar.gz" {
		t.Errorf("cópias = %+v", files)
	}
	if !ValidName(files[0].Name) || ValidName("../"+files[0].Name) || ValidName("x.tar.gz") {
		t.Error("ValidName")
	}
}

func timeFar() time.Time { return time.Now().Add(time.Hour) }
