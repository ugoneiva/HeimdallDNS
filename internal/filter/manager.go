package filter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxListSize = 64 << 20 // 64 MiB por lista

// ListSpec descreve uma lista de bloqueio. Fixed = veio do arquivo de
// configuração (não pode ser alterada pela interface); as demais têm ID no banco.
type ListSpec struct {
	ID       int64
	Name     string
	URL      string
	Enabled  bool
	Fixed    bool
	Category string // "" ou CategoryThreat
}

func (l ListSpec) key() string { return fmt.Sprintf("%t|%d|%s", l.Fixed, l.ID, l.URL) }

// ListStatus é o estado de uma lista, para a API e o dashboard.
type ListStatus struct {
	ID        int64     `json:"id,omitempty"`
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Enabled   bool      `json:"enabled"`
	Fixed     bool      `json:"fixed"`
	Category  string    `json:"category"`
	Rules     int       `json:"rules"`
	Invalid   int       `json:"invalid"`
	UpdatedAt time.Time `json:"updated_at,omitzero"` // última cópia baixada com sucesso
	Error     string    `json:"error,omitempty"`
}

type ManagerOptions struct {
	Lists    []ListSpec // do arquivo de configuração
	Allow    []string   // regras próprias do arquivo de configuração
	Deny     []string
	CacheDir string // onde ficam as cópias baixadas
	Interval time.Duration
	Logger   *slog.Logger
}

// Manager baixa as listas, guarda uma cópia local e mantém o Matcher atual.
type Manager struct {
	opts   ManagerOptions
	client *http.Client
	log    *slog.Logger

	cur atomic.Pointer[Matcher]

	refreshMu sync.Mutex // um Refresh/Apply por vez
	mu        sync.Mutex // protege os campos abaixo
	userLists []ListSpec
	userAllow []string
	userDeny  []string
	status    map[string]*ListStatus
}

func NewManager(opts ManagerOptions) *Manager {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	for i := range opts.Lists {
		opts.Lists[i].Fixed = true
	}
	return &Manager{
		opts:   opts,
		client: &http.Client{Timeout: 2 * time.Minute},
		log:    opts.Logger,
		status: map[string]*ListStatus{},
	}
}

// Matcher devolve o conjunto de regras em uso (nunca nil depois de Start).
func (m *Manager) Matcher() *Matcher { return m.cur.Load() }

// lists devolve as listas do arquivo seguidas das da interface.
func (m *Manager) lists() []ListSpec {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append(slices.Clone(m.opts.Lists), m.userLists...)
}

// Status devolve o estado de todas as listas, na ordem em que são aplicadas.
func (m *Manager) Status() []ListStatus {
	ls := m.lists()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ListStatus, len(ls))
	for i, l := range ls {
		st := ListStatus{ID: l.ID, Name: l.Name, URL: l.URL, Enabled: l.Enabled, Fixed: l.Fixed, Category: l.Category}
		if s := m.status[l.key()]; s != nil {
			st.Rules, st.Invalid, st.UpdatedAt, st.Error = s.Rules, s.Invalid, s.UpdatedAt, s.Error
		}
		if !l.Enabled {
			st.Rules, st.Invalid = 0, 0
		}
		out[i] = st
	}
	return out
}

// UserRules devolve as regras próprias: as do arquivo (só leitura) e as da interface.
func (m *Manager) UserRules() (cfgAllow, cfgDeny, allow, deny []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.opts.Allow), slices.Clone(m.opts.Deny), slices.Clone(m.userAllow), slices.Clone(m.userDeny)
}

// SetUser troca as listas e regras definidas pela interface. Elas passam a
// valer no próximo Apply (ou Start).
func (m *Manager) SetUser(lists []ListSpec, allow, deny []string) {
	m.mu.Lock()
	m.userLists = slices.Clone(lists)
	m.userAllow, m.userDeny = slices.Clone(allow), slices.Clone(deny)
	m.mu.Unlock()
}

// Apply baixa as listas habilitadas que ainda não têm cópia local e remonta as regras.
func (m *Manager) Apply(ctx context.Context) {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()
	for _, l := range m.lists() {
		if l.Enabled && isRemote(l.URL) {
			if _, err := os.Stat(m.cachePath(l.URL)); err != nil {
				m.fetch(ctx, l)
			}
		}
	}
	m.rebuild()
}

// Start carrega as cópias locais (início rápido, sem rede), depois baixa as
// listas em segundo plano e repete a cada Interval.
func (m *Manager) Start(ctx context.Context) {
	// Downloads interrompidos (serviço parado no meio) deixam temporários.
	if tmps, _ := filepath.Glob(filepath.Join(m.opts.CacheDir, ".baixando-*")); len(tmps) > 0 {
		for _, t := range tmps {
			_ = os.Remove(t)
		}
	}
	m.rebuild()
	go func() {
		m.Refresh(ctx)
		if m.opts.Interval <= 0 {
			return
		}
		t := time.NewTicker(m.opts.Interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.Refresh(ctx)
			}
		}
	}()
}

// Refresh baixa as listas remotas e remonta o Matcher. Uma lista que falhar
// continua valendo pela última cópia baixada.
func (m *Manager) Refresh(ctx context.Context) {
	m.refreshMu.Lock()
	defer m.refreshMu.Unlock()
	for _, l := range m.lists() {
		if l.Enabled && isRemote(l.URL) {
			m.fetch(ctx, l)
		}
	}
	if ctx.Err() == nil {
		m.rebuild()
	}
}

func (m *Manager) fetch(ctx context.Context, l ListSpec) {
	err := m.download(ctx, l.URL)
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.statusLocked(l)
	if err != nil {
		st.Error = err.Error()
		m.log.Warn("falha ao baixar lista", "lista", l.Name, "erro", err)
		return
	}
	st.Error = ""
}

func (m *Manager) statusLocked(l ListSpec) *ListStatus {
	st := m.status[l.key()]
	if st == nil {
		st = &ListStatus{}
		m.status[l.key()] = st
	}
	return st
}

func (m *Manager) rebuild() {
	start := time.Now()
	cfgAllow, cfgDeny, allow, deny := m.UserRules()
	b := NewBuilder()
	for _, r := range b.AddUserRules(append(cfgAllow, allow...), append(cfgDeny, deny...)) {
		m.log.Warn("regra própria inválida", "regra", r)
	}
	for _, l := range m.lists() {
		if !l.Enabled {
			continue
		}
		st, mod, err := m.readList(l.URL, l.Category == CategoryThreat, b)
		m.mu.Lock()
		s := m.statusLocked(l)
		switch {
		case err != nil && !errors.Is(err, os.ErrNotExist):
			s.Error = err.Error()
			m.log.Warn("falha ao ler lista", "lista", l.Name, "erro", err)
		case err == nil:
			s.Rules, s.Invalid, s.UpdatedAt = st.Rules, st.Invalid, mod
		}
		m.mu.Unlock()
	}
	mt := b.Build()
	m.cur.Store(mt)
	// A montagem gera muito lixo temporário (listas grandes passam de 2 milhões
	// de domínios); devolve a memória ao sistema em vez de esperar o GC.
	debug.FreeOSMemory()
	block, exc := mt.Rules()
	m.log.Info("regras carregadas", "bloqueio", block, "excecoes", exc, "tempo", time.Since(start).Round(time.Millisecond))
}

func (m *Manager) readList(src string, threat bool, b *Builder) (ListStats, time.Time, error) {
	path := localPath(src)
	if isRemote(src) {
		path = m.cachePath(src)
	}
	f, err := os.Open(path)
	if err != nil {
		return ListStats{}, time.Time{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return ListStats{}, time.Time{}, err
	}
	var st ListStats
	if threat {
		st, err = b.AddThreatList(f)
	} else {
		st, err = b.AddList(f)
	}
	return st, fi.ModTime(), err
}

func (m *Manager) download(ctx context.Context, src string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "HeimdallDNS")
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	if err := os.MkdirAll(m.opts.CacheDir, 0o755); err != nil {
		return err
	}
	dst := m.cachePath(src)
	tmp, err := os.CreateTemp(m.opts.CacheDir, ".baixando-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxListSize+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > maxListSize {
		return fmt.Errorf("lista maior que %d MiB", maxListSize>>20)
	}
	if n == 0 {
		return errors.New("lista vazia")
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

func (m *Manager) cachePath(src string) string {
	h := sha256.Sum256([]byte(src))
	return filepath.Join(m.opts.CacheDir, hex.EncodeToString(h[:8])+".txt")
}

func isRemote(src string) bool {
	return strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://")
}

func localPath(src string) string {
	if u, err := url.Parse(src); err == nil && u.Scheme == "file" {
		return u.Path
	}
	return src
}
