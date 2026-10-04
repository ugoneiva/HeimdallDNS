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
}

type member struct {
	ups  dp.Upstream
	addr string

	latency atomic.Uint64 // média móvel em ns (bits de float64); 0 = sem medida
	ok      atomic.Uint64
	fail    atomic.Uint64
	healthy atomic.Bool
}

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

type Group struct {
	members []*member
	mode    string
	timeout time.Duration
	log     *slog.Logger
	closers []dp.Upstream // bootstraps
}

func New(opts Options) (*Group, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	g := &Group{mode: opts.Mode, timeout: opts.Timeout, log: opts.Logger}

	var boot multiResolver
	for _, b := range opts.Bootstrap {
		r, err := dp.NewUpstreamResolver(b, &dp.Options{Timeout: opts.Timeout, Logger: opts.Logger})
		if err != nil {
			g.Close()
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
			g.Close()
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
	if g.mode == ModeParallel && len(g.members) > 1 {
		return g.parallel(ctx, req)
	}
	order := g.members
	if g.mode == ModeFastest {
		order = g.byLatency()
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

func (g *Group) parallel(ctx context.Context, req *dns.Msg) (*dns.Msg, string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		resp *dns.Msg
		addr string
		err  error
	}
	ch := make(chan result, len(g.members))
	for _, m := range g.members {
		go func() {
			resp, err := g.exchange(ctx, m, req)
			ch <- result{resp, m.addr, err}
		}()
	}
	var errs []error
	var servfail *result
	for range g.members {
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

// byLatency ordena: saudáveis primeiro; entre eles, quem ainda não foi medido
// (para ganhar uma medida) e depois a menor latência.
func (g *Group) byLatency() []*member {
	out := slices.Clone(g.members)
	slices.SortStableFunc(out, func(a, b *member) int {
		ha, hb := a.healthy.Load(), b.healthy.Load()
		if ha != hb {
			if ha {
				return -1
			}
			return 1
		}
		la, lb := a.latencyNS(), b.latencyNS()
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
	probe := func() {
		for _, m := range g.members {
			req := new(dns.Msg)
			req.SetQuestion("example.com.", dns.TypeA)
			req.RecursionDesired = true
			if _, err := g.exchange(ctx, m, req); err != nil && ctx.Err() == nil {
				g.log.Warn("upstream sem resposta", "upstream", m.addr, "erro", err)
			}
		}
	}
	probe()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			probe()
		}
	}
}

type Stats struct {
	Address   string  `json:"address"`
	LatencyMS float64 `json:"latency_ms"`
	OK        uint64  `json:"ok"`
	Fail      uint64  `json:"fail"`
	Healthy   bool    `json:"healthy"`
}

func (g *Group) Stats() []Stats {
	out := make([]Stats, len(g.members))
	for i, m := range g.members {
		out[i] = Stats{
			Address:   m.addr,
			LatencyMS: math.Round(m.latencyNS()/1e4) / 100,
			OK:        m.ok.Load(),
			Fail:      m.fail.Load(),
			Healthy:   m.healthy.Load(),
		}
	}
	return out
}

func (g *Group) Close() error {
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
