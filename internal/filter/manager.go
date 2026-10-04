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
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxListSize = 64 << 20 // 64 MiB por lista

// ListSpec descreve uma lista de bloqueio configurada.
type ListSpec struct {
	Name    string
	URL     string
	Enabled bool
}

// ListStatus é o estado de uma lista, para a API e o dashboard.
type ListStatus struct {
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Enabled   bool      `json:"enabled"`
	Rules     int       `json:"rules"`
	Invalid   int       `json:"invalid"`
	UpdatedAt time.Time `json:"updated_at"` // última cópia baixada com sucesso
	Error     string    `json:"error,omitempty"`
}

type ManagerOptions struct {
	Lists    []ListSpec
	Allow    []string // regras próprias de exceção
	Deny     []string // regras próprias de bloqueio
	CacheDir string   // onde ficam as cópias baixadas
	Interval time.Duration
	Logger   *slog.Logger
}

// Manager baixa as listas, guarda uma cópia local e mantém o Matcher atual.
type Manager struct {
	opts   ManagerOptions
	client *http.Client
	log    *slog.Logger

	cur atomic.Pointer[Matcher]

	refreshMu sync.Mutex // um Refresh por vez
	mu        sync.Mutex
	status    []ListStatus
}

func NewManager(opts ManagerOptions) *Manager {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	m := &Manager{
		opts:   opts,
		client: &http.Client{Timeout: 2 * time.Minute},
		log:    opts.Logger,
	}
	m.status = make([]ListStatus, len(opts.Lists))
	for i, l := range opts.Lists {
		m.status[i] = ListStatus{Name: l.Name, URL: l.URL, Enabled: l.Enabled}
	}
	return m
}

// Matcher devolve o conjunto de regras em uso (nunca nil depois de Start).
func (m *Manager) Matcher() *Matcher { return m.cur.Load() }

// Status devolve uma cópia do estado das listas.
func (m *Manager) Status() []ListStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]ListStatus(nil), m.status...)
}

// Start carrega as cópias locais (início rápido, sem rede), depois baixa as
// listas em segundo plano e repete a cada Interval.
func (m *Manager) Start(ctx context.Context) {
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
	for i, l := range m.opts.Lists {
		if !l.Enabled || !isRemote(l.URL) {
			continue
		}
		err := m.download(ctx, l.URL)
		m.mu.Lock()
		if err != nil {
			m.status[i].Error = err.Error()
			m.log.Warn("falha ao baixar lista", "lista", l.Name, "erro", err)
		} else {
			m.status[i].Error = ""
		}
		m.mu.Unlock()
	}
	if ctx.Err() == nil {
		m.rebuild()
	}
}

func (m *Manager) rebuild() {
	start := time.Now()
	b := NewBuilder()
	for _, line := range m.opts.Deny {
		if b.AddLine(line, true) == lineBad {
			m.log.Warn("regra própria inválida em deny", "regra", line)
		}
	}
	for _, line := range m.opts.Allow {
		// Na lista de exceções, a regra simples já é uma exceção.
		if !strings.HasPrefix(strings.TrimSpace(line), "@@") {
			line = "@@" + strings.TrimSpace(line)
		}
		if b.AddLine(line, true) == lineBad {
			m.log.Warn("regra própria inválida em allow", "regra", line)
		}
	}
	for i, l := range m.opts.Lists {
		if !l.Enabled {
			continue
		}
		st, mod, err := m.readList(l.URL, b)
		m.mu.Lock()
		switch {
		case err != nil && !errors.Is(err, os.ErrNotExist):
			m.status[i].Error = err.Error()
			m.log.Warn("falha ao ler lista", "lista", l.Name, "erro", err)
		case err == nil:
			m.status[i].Rules, m.status[i].Invalid, m.status[i].UpdatedAt = st.Rules, st.Invalid, mod
		}
		m.mu.Unlock()
	}
	mt := b.Build()
	m.cur.Store(mt)
	block, allow := mt.Rules()
	m.log.Info("regras carregadas", "bloqueio", block, "excecoes", allow, "tempo", time.Since(start).Round(time.Millisecond))
}

func (m *Manager) readList(src string, b *Builder) (ListStats, time.Time, error) {
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
	st, err := b.AddList(f)
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
