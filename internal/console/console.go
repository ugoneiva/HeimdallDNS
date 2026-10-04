// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

// Package console é o painel de MSP: acompanha vários HeimdallDNS (um por
// cliente) pela API de cada um e junta status e alertas num lugar só.
//
// O console guarda o token da API de cada cliente: proteja-o como um cofre.
package console

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	pollEvery = 30 * time.Second
	reqWait   = 10 * time.Second
	maxBody   = 4 << 20
)

// Tenant é um cliente acompanhado (um HeimdallDNS).
type Tenant struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	Token       string `json:"-"`
	InsecureTLS bool   `json:"insecure_tls"`
}

// Persister guarda os clientes do console.
type Persister interface {
	ConsoleTenants() ([]Tenant, error)
	SaveConsoleTenant(Tenant) error
	DeleteConsoleTenant(id string) error
}

// Alert é um alerta aberto de um cliente.
type Alert struct {
	TenantID   string    `json:"tenant_id"`
	TenantName string    `json:"tenant_name"`
	ID         int64     `json:"id"`
	Kind       string    `json:"kind"`
	Severity   string    `json:"severity"`
	Summary    string    `json:"summary"`
	ClientName string    `json:"client_name,omitempty"`
	ClientIP   string    `json:"client_ip,omitempty"`
	Domain     string    `json:"domain,omitempty"`
	Count      int       `json:"count"`
	LastSeen   time.Time `json:"last_seen"`
}

// State é o retrato de um cliente na última leitura.
type State struct {
	Tenant
	Online      bool           `json:"online"`
	Error       string         `json:"error,omitempty"`
	LastOK      time.Time      `json:"last_ok,omitzero"`
	Checked     time.Time      `json:"checked,omitzero"`
	Version     string         `json:"version,omitempty"`
	UptimeS     int            `json:"uptime_s"`
	Clients     int            `json:"clients"`
	Rules       int            `json:"rules"`
	Queries24h  int64          `json:"queries_24h"`
	BlockedPct  float64        `json:"blocked_pct"`
	ActiveDev   int            `json:"active_devices"`
	OpenAlerts  map[string]int `json:"open_alerts"`
	OpenTotal   int            `json:"open_total"`
	UpstreamsOK int            `json:"upstreams_ok"`
	Upstreams   int            `json:"upstreams"`
	HARole      string         `json:"ha_role"`
	Alerts      []Alert        `json:"-"`
}

type Options struct {
	Store  Persister
	Logger *slog.Logger
}

type Console struct {
	opts Options
	log  *slog.Logger

	mu      sync.Mutex
	tenants map[string]Tenant
	states  map[string]*State
	wake    chan struct{}
}

func New(o Options) (*Console, error) {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	c := &Console{opts: o, log: o.Logger, tenants: map[string]Tenant{}, states: map[string]*State{}, wake: make(chan struct{}, 1)}
	if o.Store != nil {
		ts, err := o.Store.ConsoleTenants()
		if err != nil {
			return nil, err
		}
		for _, t := range ts {
			c.tenants[t.ID] = t
		}
	}
	return c, nil
}

func client(insecure bool) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Transport: tr, Timeout: reqWait}
}

func (c *Console) call(ctx context.Context, t Tenant, method, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(t.URL, "/")+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+t.Token)
	resp, err := client(t.InsecureTLS).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s: %s", resp.Status, e.Error)
		}
		return errors.New(resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(out)
}

// fetch lê o cliente inteiro.
func (c *Console) fetch(ctx context.Context, t Tenant) *State {
	st := &State{Tenant: t, Checked: time.Now(), OpenAlerts: map[string]int{}}
	var status struct {
		Version   string              `json:"version"`
		UptimeS   int                 `json:"uptime_s"`
		Clients   int                 `json:"clients"`
		Rules     struct{ Block int } `json:"rules"`
		Upstreams []struct {
			Healthy bool `json:"healthy"`
		} `json:"upstreams"`
	}
	if err := c.call(ctx, t, "GET", "/api/status", &status); err != nil {
		st.Error = err.Error()
		return st
	}
	st.Online, st.LastOK = true, time.Now()
	st.Version, st.UptimeS, st.Clients, st.Rules = status.Version, status.UptimeS, status.Clients, status.Rules.Block
	st.Upstreams = len(status.Upstreams)
	for _, u := range status.Upstreams {
		if u.Healthy {
			st.UpstreamsOK++
		}
	}
	var sum struct {
		Counts struct {
			Total int64 `json:"total"`
		} `json:"counts"`
		BlockedPct    float64 `json:"blocked_pct"`
		ActiveClients int     `json:"active_clients"`
	}
	if err := c.call(ctx, t, "GET", "/api/stats/summary?range=24h", &sum); err == nil {
		st.Queries24h, st.BlockedPct, st.ActiveDev = sum.Counts.Total, sum.BlockedPct, sum.ActiveClients
	}
	var sec struct {
		Open      map[string]int `json:"open"`
		OpenTotal int            `json:"open_total"`
	}
	if err := c.call(ctx, t, "GET", "/api/security/summary", &sec); err == nil {
		st.OpenAlerts, st.OpenTotal = sec.Open, sec.OpenTotal
	}
	var evs []struct {
		ID         int64     `json:"id"`
		Kind       string    `json:"kind"`
		Severity   string    `json:"severity"`
		Summary    string    `json:"summary"`
		ClientName string    `json:"client_name"`
		ClientIP   string    `json:"client_ip"`
		Domain     string    `json:"domain"`
		Count      int       `json:"count"`
		LastSeen   time.Time `json:"last_seen"`
	}
	if err := c.call(ctx, t, "GET", "/api/security/events?status=open&range=30d&limit=50", &evs); err == nil {
		for _, e := range evs {
			st.Alerts = append(st.Alerts, Alert{TenantID: t.ID, TenantName: t.Name, ID: e.ID, Kind: e.Kind,
				Severity: e.Severity, Summary: e.Summary, ClientName: e.ClientName, ClientIP: e.ClientIP,
				Domain: e.Domain, Count: e.Count, LastSeen: e.LastSeen})
		}
	}
	var ha struct {
		Role string `json:"role"`
	}
	if err := c.call(ctx, t, "GET", "/api/ha", &ha); err == nil {
		st.HARole = ha.Role
	}
	return st
}

// Run lê todos os clientes a cada 30 s (e logo depois de um cadastro).
func (c *Console) Run(ctx context.Context) {
	t := time.NewTicker(pollEvery)
	defer t.Stop()
	for {
		c.pollAll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-c.wake:
		}
	}
}

func (c *Console) pollAll(ctx context.Context) {
	c.mu.Lock()
	ts := make([]Tenant, 0, len(c.tenants))
	for _, t := range c.tenants {
		ts = append(ts, t)
	}
	c.mu.Unlock()
	var wg sync.WaitGroup
	for _, t := range ts {
		wg.Go(func() {
			st := c.fetch(ctx, t)
			c.mu.Lock()
			if prev := c.states[t.ID]; prev != nil && !st.Online {
				st.LastOK = prev.LastOK
				if prev.Online {
					c.log.Warn("cliente fora do ar", "cliente", t.Name, "erro", st.Error)
				}
			}
			if _, still := c.tenants[t.ID]; still {
				c.states[t.ID] = st
			}
			c.mu.Unlock()
		})
	}
	wg.Wait()
}

// States devolve o retrato de todos os clientes, por nome.
func (c *Console) States() []State {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]State, 0, len(c.tenants))
	for id, t := range c.tenants {
		if st := c.states[id]; st != nil {
			s := *st
			s.Tenant = t
			out = append(out, s)
		} else {
			out = append(out, State{Tenant: t, OpenAlerts: map[string]int{}})
		}
	}
	slices.SortFunc(out, func(a, b State) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	return out
}

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

// Alerts junta os alertas abertos de todos: mais graves e mais recentes primeiro.
func (c *Console) Alerts() []Alert {
	c.mu.Lock()
	var out []Alert
	for _, st := range c.states {
		out = append(out, st.Alerts...)
	}
	c.mu.Unlock()
	slices.SortFunc(out, func(a, b Alert) int {
		if d := sevRank[a.Severity] - sevRank[b.Severity]; d != 0 {
			return d
		}
		return b.LastSeen.Compare(a.LastSeen)
	})
	if out == nil {
		out = []Alert{}
	}
	return out
}

// Add testa a conexão e cadastra o cliente.
func (c *Console) Add(ctx context.Context, t Tenant) (Tenant, error) {
	t.Name, t.URL, t.Token = strings.TrimSpace(t.Name), strings.TrimSuffix(strings.TrimSpace(t.URL), "/"), strings.TrimSpace(t.Token)
	u, err := url.Parse(t.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return t, errors.New("URL inválida: use http(s)://endereço:porta da API do cliente")
	}
	if t.Name == "" || t.Token == "" {
		return t, errors.New("informe nome e token da API do cliente")
	}
	if err := c.call(ctx, t, "GET", "/api/status", nil); err != nil {
		return t, fmt.Errorf("não consegui falar com o cliente: %w", err)
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	t.ID = hex.EncodeToString(b)
	if c.opts.Store != nil {
		if err := c.opts.Store.SaveConsoleTenant(t); err != nil {
			return t, err
		}
	}
	c.mu.Lock()
	c.tenants[t.ID] = t
	c.mu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
	return t, nil
}

func (c *Console) Remove(id string) error {
	c.mu.Lock()
	_, ok := c.tenants[id]
	delete(c.tenants, id)
	delete(c.states, id)
	c.mu.Unlock()
	if !ok {
		return errors.New("cliente não encontrado")
	}
	if c.opts.Store != nil {
		return c.opts.Store.DeleteConsoleTenant(id)
	}
	return nil
}

// Ack reconhece o alerta no próprio cliente e atualiza o retrato.
func (c *Console) Ack(ctx context.Context, tenantID string, eventID int64) error {
	c.mu.Lock()
	t, ok := c.tenants[tenantID]
	c.mu.Unlock()
	if !ok {
		return errors.New("cliente não encontrado")
	}
	if err := c.call(ctx, t, "POST", fmt.Sprintf("/api/security/events/%d/ack", eventID), nil); err != nil {
		return err
	}
	st := c.fetch(ctx, t)
	c.mu.Lock()
	c.states[tenantID] = st
	c.mu.Unlock()
	return nil
}
