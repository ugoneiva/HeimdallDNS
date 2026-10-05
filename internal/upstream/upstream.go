// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

// Package upstream encaminha as consultas para os resolvedores externos
// (DNS comum, DoH, DoT, DoQ), mede a latência de cada um e escolhe o melhor.
package upstream

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	dp "github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
)

// Modos de escolha (iguais aos da configuração).
const (
	ModeFastest  = "fastest"
	ModeParallel = "parallel"
	ModeFailover = "failover"
)

const ewmaAlpha = 0.3

type Options struct {
	Servers   []string
	Bootstrap []string
	Mode      string
	Timeout   time.Duration
	Logger    *slog.Logger
	// RequireDNSSEC usa só os upstreams que validam DNSSEC (testados na
	// partida e a cada 6 h). Se nenhum validar, usa todos e avisa no log.
	RequireDNSSEC bool
}

type member struct {
	ups  dp.Upstream
	addr string

	latency atomic.Uint64 // média móvel em ns (bits de float64); 0 = sem medida
	ok      atomic.Uint64
	fail    atomic.Uint64
	healthy atomic.Bool
	dnssec  atomic.Int32 // dnssecUnknown, dnssecYes ou dnssecNo
}

// Resultado do teste de validação DNSSEC de cada upstream.
const (
	dnssecUnknown int32 = iota
	dnssecYes
	dnssecNo
)

func (m *member) record(d time.Duration, err error) {
	if err != nil {
		m.fail.Add(1)
		m.healthy.Store(false)
		return
	}
	m.ok.Add(1)
	m.healthy.Store(true)
	for {
		old := m.latency.Load()
		v := float64(d)
		if old != 0 {
			v = ewmaAlpha*v + (1-ewmaAlpha)*math.Float64frombits(old)
		}
		if m.latency.CompareAndSwap(old, math.Float64bits(v)) {
			return
		}
	}
}

func (m *member) latencyNS() float64 { return math.Float64frombits(m.latency.Load()) }

// set é uma configuração completa de upstreams; Reconfigure troca o set
// inteiro de uma vez, sem parar as consultas em andamento.
type set struct {
	members       []*member
	mode          string
	closers       []dp.Upstream // bootstraps
	requireDNSSEC bool
}

type Group struct {
	cur     atomic.Pointer[set]
	timeout time.Duration
	log     *slog.Logger
	kick    chan struct{} // pede uma medição já (depois de trocar os servidores)
	mu      sync.Mutex    // serializa Reconfigure
	// onHealth avisa quando todos os upstreams caem (up=false) e quando
	// algum volta (up=true).
	onHealth atomic.Pointer[func(up bool, servers []string)]
}

// SetOnHealth registra o aviso de queda geral e volta dos upstreams.
func (g *Group) SetOnHealth(f func(up bool, servers []string)) { g.onHealth.Store(&f) }

func New(opts Options) (*Group, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	g := &Group{timeout: opts.Timeout, log: opts.Logger, kick: make(chan struct{}, 1)}
	st, err := newSet(opts)
	if err != nil {
		return nil, err
	}
	g.cur.Store(st)
	return g, nil
}

// Validate confere se os endereços são aceitos, sem abrir conexões.
func Validate(servers []string, mode string) error {
	switch mode {
	case "", ModeFastest, ModeParallel, ModeFailover:
	default:
		return fmt.Errorf("modo %q: use fastest, parallel ou failover", mode)
	}
	if len(servers) == 0 {
		return errors.New("informe ao menos um upstream")
	}
	for _, s := range servers {
		u, err := dp.AddressToUpstream(s, &dp.Options{Timeout: time.Second})
		if err != nil {
			return fmt.Errorf("upstream %q: %w", s, err)
		}
		u.Close()
	}
	return nil
}

// Reconfigure troca servidores e modo. As consultas em andamento terminam no
// set antigo, que é fechado depois de um tempo.
func (g *Group) Reconfigure(opts Options) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if opts.Timeout == 0 {
		opts.Timeout = g.timeout
	}
	if opts.Logger == nil {
		opts.Logger = g.log
	}
	// A exigência de DNSSEC vem da configuração: trocar os servidores pelo
	// painel não a desliga.
	opts.RequireDNSSEC = opts.RequireDNSSEC || g.cur.Load().requireDNSSEC
	st, err := newSet(opts)
	if err != nil {
		return err
	}
	old := g.cur.Swap(st)
	time.AfterFunc(2*g.timeout+time.Second, func() { old.close() })
	select {
	case g.kick <- struct{}{}:
	default:
	}
	g.log.Info("upstreams trocados", "servidores", opts.Servers, "modo", opts.Mode)
	return nil
}

// Config devolve os servidores e o modo em uso.
func (g *Group) Config() ([]string, string) {
	st := g.cur.Load()
	out := make([]string, len(st.members))
	for i, m := range st.members {
		out[i] = m.addr
	}
	return out, st.mode
}

func newSet(opts Options) (*set, error) {
	g := &set{mode: opts.Mode, requireDNSSEC: opts.RequireDNSSEC}
	if g.mode == "" {
		g.mode = ModeFastest
	}
	var boot multiResolver
	for _, b := range opts.Bootstrap {
		r, err := dp.NewUpstreamResolver(b, &dp.Options{Timeout: opts.Timeout, Logger: opts.Logger})
		if err != nil {
			g.close()
			return nil, fmt.Errorf("bootstrap %q: %w", b, err)
		}
		g.closers = append(g.closers, r.Upstream)
		boot = append(boot, r)
	}
	upOpts := &dp.Options{Timeout: opts.Timeout, Logger: opts.Logger}
	if len(boot) > 0 {
		upOpts.Bootstrap = boot
	}
	for _, s := range opts.Servers {
		u, err := dp.AddressToUpstream(s, upOpts)
		if err != nil {
			g.close()
			return nil, fmt.Errorf("upstream %q: %w", s, err)
		}
		m := &member{ups: u, addr: s}
		m.healthy.Store(true)
		g.members = append(g.members, m)
	}
	if len(g.members) == 0 {
		return nil, errors.New("nenhum upstream configurado")
	}
	return g, nil
}

// Exchange envia a consulta e devolve a resposta e o upstream que respondeu.
func (g *Group) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, string, error) {
	st := g.cur.Load()
	members := st.usable()
	if st.mode == ModeParallel && len(members) > 1 {
		return g.parallel(ctx, members, req)
	}
	order := members
	if st.mode == ModeFastest {
		order = byLatency(members)
	}
	var (
		last     *dns.Msg
		lastAddr string
		errs     []error
	)
	for _, m := range order {
		resp, err := g.exchange(ctx, m, req)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", m.addr, err))
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if resp.Rcode == dns.RcodeServerFailure { // tenta o próximo
			last, lastAddr = resp, m.addr
			continue
		}
		return resp, m.addr, nil
	}
	if last != nil {
		return last, lastAddr, nil
	}
	return nil, "", errors.Join(errs...)
}

func (g *Group) exchange(ctx context.Context, m *member, req *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	start := time.Now()
	resp, err := m.ups.Exchange(ctx, req)
	if err == nil && resp == nil {
		err = errors.New("resposta vazia")
	}
	m.record(time.Since(start), err)
	return resp, err
}

func (g *Group) parallel(ctx context.Context, members []*member, req *dns.Msg) (*dns.Msg, string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		resp *dns.Msg
		addr string
		err  error
	}
	ch := make(chan result, len(members))
	for _, m := range members {
		go func() {
			resp, err := g.exchange(ctx, m, req)
			ch <- result{resp, m.addr, err}
		}()
	}
	var errs []error
	var servfail *result
	for range members {
		r := <-ch
		switch {
		case r.err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", r.addr, r.err))
		case r.resp.Rcode == dns.RcodeServerFailure:
			servfail = &r
		default:
			return r.resp, r.addr, nil
		}
	}
	if servfail != nil {
		return servfail.resp, servfail.addr, nil
	}
	return nil, "", errors.Join(errs...)
}

// byLatency ordena: saudáveis primeiro; entre eles, a menor latência medida.
// Quem ainda não foi medido vai para o fim: a medição é papel do HealthCheck,
// não das consultas dos clientes.
func byLatency(members []*member) []*member {
	out := slices.Clone(members)
	slices.SortStableFunc(out, func(a, b *member) int {
		ha, hb := a.healthy.Load(), b.healthy.Load()
		if ha != hb {
			if ha {
				return -1
			}
			return 1
		}
		la, lb := a.latencyNS(), b.latencyNS()
		if (la == 0) != (lb == 0) {
			if la == 0 {
				return 1
			}
			return -1
		}
		switch {
		case la < lb:
			return -1
		case la > lb:
			return 1
		}
		return 0
	})
	return out
}

// HealthCheck consulta todos os upstreams periodicamente, para manter a
// latência e o estado em dia mesmo dos que não estão sendo usados.
func (g *Group) HealthCheck(ctx context.Context, every time.Duration) {
	if every <= 0 {
		return
	}
	// Mede todos em paralelo (também abre as conexões DoH/DoT antes da
	// primeira consulta de um cliente).
	wasUp := true
	probe := func() {
		var wg sync.WaitGroup
		for _, m := range g.cur.Load().members {
			wg.Go(func() {
				req := new(dns.Msg)
				req.SetQuestion("example.com.", dns.TypeA)
				req.RecursionDesired = true
				if _, err := g.exchange(ctx, m, req); err != nil && ctx.Err() == nil {
					g.log.Warn("upstream sem resposta", "upstream", m.addr, "erro", err)
				}
			})
		}
		wg.Wait()
		// Todos fora do ar é queda do DNS da rede inteira: avisa na mudança.
		var servers []string
		healthy := false
		for _, m := range g.cur.Load().members {
			servers = append(servers, m.addr)
			healthy = healthy || m.healthy.Load()
		}
		if ctx.Err() == nil && healthy != wasUp {
			wasUp = healthy
			if !healthy {
				g.log.Error("nenhum upstream responde: as consultas vão falhar", "upstreams", servers)
			}
			if f := g.onHealth.Load(); f != nil {
				(*f)(healthy, servers)
			}
		}
	}
	probe()
	g.CheckDNSSEC(ctx)
	lastCheck := time.Now()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			probe()
			if time.Since(lastCheck) > dnssecEvery {
				g.CheckDNSSEC(ctx)
				lastCheck = time.Now()
			}
		case <-g.kick:
			probe()
			g.CheckDNSSEC(ctx) // servidores novos
			lastCheck = time.Now()
		}
	}
}

type Stats struct {
	Address   string  `json:"address"`
	LatencyMS float64 `json:"latency_ms"`
	OK        uint64  `json:"ok"`
	Fail      uint64  `json:"fail"`
	Healthy   bool    `json:"healthy"`
	DNSSEC    string  `json:"dnssec"` // yes, no ou unknown (ainda não testado)
	InUse     bool    `json:"in_use"` // false quando excluído por não validar DNSSEC
}

func (g *Group) Stats() []Stats {
	st := g.cur.Load()
	members := st.members
	out := make([]Stats, len(members))
	for i, m := range members {
		out[i] = Stats{
			Address:   m.addr,
			LatencyMS: math.Round(m.latencyNS()/1e4) / 100,
			OK:        m.ok.Load(),
			Fail:      m.fail.Load(),
			Healthy:   m.healthy.Load(),
			DNSSEC:    [...]string{"unknown", "yes", "no"}[m.dnssec.Load()],
			InUse:     inUse(st, m),
		}
	}
	return out
}

func (g *Group) Close() error { return g.cur.Load().close() }

func (g *set) close() error {
	var errs []error
	for _, m := range g.members {
		errs = append(errs, m.ups.Close())
	}
	for _, u := range g.closers {
		errs = append(errs, u.Close())
	}
	return errors.Join(errs...)
}

// multiResolver tenta os bootstraps em ordem até um responder.
type multiResolver []dp.Resolver

func (r multiResolver) LookupNetIP(ctx context.Context, network string, host string) ([]netip.Addr, error) {
	var errs []error
	for _, res := range r {
		addrs, err := res.LookupNetIP(ctx, network, host)
		if err == nil && len(addrs) > 0 {
			return addrs, nil
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return nil, fmt.Errorf("bootstrap: %s sem endereço", host)
	}
	return nil, errors.Join(errs...)
}
