// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package webfilter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/filter"
)

const maxListSize = 64 << 20

// Settings são as escolhas globais do filtro web.
type Settings struct {
	Global     []string `json:"global"`     // categorias bloqueadas para todos
	SafeSearch bool     `json:"safesearch"` // busca segura para todos
	YouTube    string   `json:"youtube"`    // strict ou moderate (modo restrito do YouTube)
}

// Status é o estado de uma categoria carregada.
type Status struct {
	Loaded    bool      `json:"loaded"`
	Rules     int       `json:"rules"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
	Error     string    `json:"error,omitempty"`
}

type Options struct {
	CacheDir string
	Interval time.Duration // nova cópia das listas (0 = só na partida)
	Logger   *slog.Logger
	Client   *http.Client
}

// Manager mantém as listas das categorias em uso (só as usadas ficam na
// memória) e as configurações globais.
type Manager struct {
	opts     Options
	log      *slog.Logger
	sets     atomic.Pointer[map[string]*filter.Matcher]
	settings atomic.Pointer[Settings]

	mu     sync.Mutex
	used   []string
	status map[string]Status
	load   sync.Mutex // uma carga por vez
	kick   chan struct{}
}

func New(o Options) *Manager {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 2 * time.Minute}
	}
	m := &Manager{opts: o, log: o.Logger, status: map[string]Status{}, kick: make(chan struct{}, 1)}
	m.sets.Store(&map[string]*filter.Matcher{})
	m.settings.Store(&Settings{YouTube: "strict"})
	return m
}

func (m *Manager) Settings() Settings {
	s := *m.settings.Load()
	s.Global = append([]string{}, s.Global...)
	return s
}

// SetSettings troca as configurações globais (sem carregar listas; chame
// SetUsed depois).
func (m *Manager) SetSettings(s Settings) error {
	if id, ok := Valid(s.Global); !ok {
		return fmt.Errorf("categoria desconhecida: %s", id)
	}
	if s.YouTube == "" {
		s.YouTube = "strict"
	}
	if s.YouTube != "strict" && s.YouTube != "moderate" {
		return errors.New(`youtube: use "strict" ou "moderate"`)
	}
	s.Global = slices.Compact(slices.Sorted(slices.Values(s.Global)))
	m.settings.Store(&s)
	return nil
}

// SetUsed diz quais categorias estão em uso (globais + grupos); as novas são
// carregadas em segundo plano e as que saíram são liberadas.
func (m *Manager) SetUsed(ids []string) {
	ids = slices.Compact(slices.Sorted(slices.Values(ids)))
	m.mu.Lock()
	changed := !slices.Equal(ids, m.used)
	m.used = ids
	m.mu.Unlock()
	if changed {
		select {
		case m.kick <- struct{}{}:
		default:
		}
	}
}

// Run carrega as categorias em uso e as atualiza a cada Interval.
func (m *Manager) Run(ctx context.Context) {
	m.reload(ctx, false)
	var tick <-chan time.Time
	if m.opts.Interval > 0 {
		t := time.NewTicker(m.opts.Interval)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.kick:
			m.reload(ctx, false)
		case <-tick:
			m.reload(ctx, true)
		}
	}
}

// Refresh baixa de novo as listas das categorias em uso.
func (m *Manager) Refresh(ctx context.Context) { m.reload(ctx, true) }

func (m *Manager) reload(ctx context.Context, download bool) {
	m.load.Lock()
	defer m.load.Unlock()
	m.mu.Lock()
	used := slices.Clone(m.used)
	m.mu.Unlock()
	old := *m.sets.Load()
	next := map[string]*filter.Matcher{}
	for _, id := range used {
		c, ok := Find(id)
		if !ok {
			continue
		}
		if mt, ok := old[id]; ok && !download {
			next[id] = mt // já carregada
			continue
		}
		mt, st := m.build(ctx, c, download)
		next[id] = mt
		m.mu.Lock()
		m.status[id] = st
		m.mu.Unlock()
		if st.Error != "" {
			m.log.Warn("categoria do filtro web com problema", "categoria", c.Name, "erro", st.Error)
		}
	}
	m.mu.Lock()
	for id := range m.status {
		if !slices.Contains(used, id) {
			delete(m.status, id)
		}
	}
	m.mu.Unlock()
	m.sets.Store(&next)
	debug.FreeOSMemory() // listas grandes geram muito lixo temporário
	if len(used) > 0 {
		m.log.Info("filtro web carregado", "categorias", used)
	}
}

// build monta o Matcher de uma categoria. Sem cópia local (ou com download
// pedido), baixa as listas; se o download falhar, usa a cópia anterior.
func (m *Manager) build(ctx context.Context, c Category, download bool) (*filter.Matcher, Status) {
	b := filter.NewBuilder()
	st := Status{Loaded: true}
	if len(c.Rules) > 0 {
		if bad := b.AddUserRules(nil, c.Rules); len(bad) > 0 {
			st.Error = "regras internas inválidas: " + strings.Join(bad, ", ")
		}
	}
	var errs []string
	for _, src := range c.Sources {
		path := m.cachePath(src.URL)
		if _, err := os.Stat(path); err != nil || download {
			if err := m.download(ctx, src.URL, path); err != nil {
				errs = append(errs, src.Name+": "+err.Error())
			}
		}
		n, mod, err := readInto(b, path, src.Wildcard)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, src.Name+": "+err.Error())
			}
			continue
		}
		st.Rules += n
		if mod.After(st.UpdatedAt) {
			st.UpdatedAt = mod
		}
	}
	if len(errs) > 0 {
		st.Error = strings.Join(errs, "; ")
	}
	mt := b.Build()
	if block, _ := mt.Rules(); block > st.Rules {
		st.Rules = block // inclui as regras do catálogo interno
	}
	return mt, st
}

func readInto(b *filter.Builder, path string, wildcard bool) (int, time.Time, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, time.Time{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, time.Time{}, err
	}
	add := b.AddList
	if wildcard {
		add = b.AddWildcardList
	}
	st, err := add(f)
	return st.Rules, fi.ModTime(), err
}

func (m *Manager) cachePath(url string) string {
	h := sha256.Sum256([]byte(url))
	return filepath.Join(m.opts.CacheDir, "web-"+hex.EncodeToString(h[:8])+".txt")
}

func (m *Manager) download(ctx context.Context, url, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "HeimdallDNS")
	resp, err := m.opts.Client.Do(req)
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
	tmp, err := os.CreateTemp(m.opts.CacheDir, ".baixando-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxListSize+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	switch {
	case err != nil:
		return err
	case n > maxListSize:
		return fmt.Errorf("lista maior que %d MiB", maxListSize>>20)
	case n == 0:
		return errors.New("lista vazia")
	}
	return os.Rename(tmp.Name(), dst)
}

// Status devolve o estado das categorias carregadas.
func (m *Manager) Status() map[string]Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]Status, len(m.status))
	for k, v := range m.status {
		out[k] = v
	}
	return out
}

// Check aplica as categorias globais (se global) e as extras (do grupo e dos
// horários ativos). Devolve a regra, a categoria e se bloqueia.
func (m *Manager) Check(name string, global bool, extra []string) (rule, category string, blocked bool) {
	sets := *m.sets.Load()
	if len(sets) == 0 {
		return "", "", false
	}
	try := func(id string) bool {
		mt := sets[id]
		if mt == nil {
			return false
		}
		if res := mt.Match(name); res.Verdict == filter.Blocked {
			rule, category = res.Rule, id
			return true
		}
		return false
	}
	if global {
		for _, id := range m.settings.Load().Global {
			if try(id) {
				return rule, category, true
			}
		}
	}
	for _, id := range extra {
		if try(id) {
			return rule, category, true
		}
	}
	return "", "", false
}
