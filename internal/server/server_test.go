package server

import (
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ugoneiva/HeimdallDNS/internal/cache"
	"github.com/ugoneiva/HeimdallDNS/internal/clients"
	"github.com/ugoneiva/HeimdallDNS/internal/config"
	"github.com/ugoneiva/HeimdallDNS/internal/filter"
	"github.com/ugoneiva/HeimdallDNS/internal/upstream"
)

// fakeUpstream responde 1.2.3.4 para tudo e conta as consultas.
func fakeUpstream(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		n.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		if strings.HasPrefix(r.Question[0].Name, "nx.") {
			m.Rcode = dns.RcodeNameError
		} else if r.Question[0].Qtype == dns.TypeA {
			m.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.IPv4(1, 2, 3, 4),
			}}
		}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String(), &n
}

func start(t *testing.T, mode string, allowed []netip.Prefix, onQuery func(Event)) (string, *atomic.Int64) {
	t.Helper()
	addr, n := fakeUpstream(t)
	ups, err := upstream.New(upstream.Options{Servers: []string{addr}, Mode: upstream.ModeFastest, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ups.Close() })
	b := filter.NewBuilder()
	b.AddLine("||bloqueado.test^", false)
	mt := b.Build()
	if allowed == nil {
		allowed = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	}
	srv := New(Options{
		Listen:       []string{"127.0.0.1:0"},
		Allowed:      allowed,
		BlockMode:    mode,
		BlockTTL:     10,
		LocalRecords: map[string][]netip.Addr{"nas.casa.": {netip.MustParseAddr("192.168.0.10")}},
		Cache:        cache.New(cache.Options{Size: 100}),
		Filter:       func() *filter.Matcher { return mt },
		Upstream:     ups,
		OnQuery:      onQuery,
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Shutdown(t.Context()) })
	return srv.Addrs()[0].String(), n
}

func query(t *testing.T, addr, name string, qtype uint16, proto string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.SetEdns0(4096, false)
	c := &dns.Client{Net: proto, Timeout: 2 * time.Second}
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("%s %s: %v", proto, name, err)
	}
	return r
}

func firstA(t *testing.T, r *dns.Msg) string {
	t.Helper()
	if len(r.Answer) == 0 {
		t.Fatalf("sem resposta: %v", r)
	}
	return r.Answer[0].(*dns.A).A.String()
}

func TestForwardAndCache(t *testing.T) {
	evc := make(chan Event, 10)
	addr, n := start(t, config.BlockNull, nil, func(e Event) { evc <- e })

	if ip := firstA(t, query(t, addr, "exemplo.com", dns.TypeA, "udp")); ip != "1.2.3.4" {
		t.Errorf("IP = %s", ip)
	}
	if ip := firstA(t, query(t, addr, "EXEMPLO.com", dns.TypeA, "tcp")); ip != "1.2.3.4" {
		t.Errorf("IP (tcp) = %s", ip)
	}
	if n.Load() != 1 {
		t.Errorf("upstream consultado %d vezes; a segunda deveria vir do cache", n.Load())
	}
	// OnQuery roda depois da resposta; espera os dois eventos.
	var events []Event
	for range 2 {
		select {
		case e := <-evc:
			events = append(events, e)
		case <-time.After(2 * time.Second):
			t.Fatal("evento não chegou")
		}
	}
	if len(events) != 2 || events[0].Status != StatusForwarded || events[1].Status != StatusCached {
		t.Errorf("eventos = %+v", events)
	}
	if events[0].Client.String() != "127.0.0.1" || events[0].Upstream == "" {
		t.Errorf("evento incompleto: %+v", events[0])
	}
}

func TestBlockModes(t *testing.T) {
	cases := []struct {
		mode  string
		rcode int
		ip    string
	}{
		{config.BlockNull, dns.RcodeSuccess, "0.0.0.0"},
		{config.BlockNXDomain, dns.RcodeNameError, ""},
		{config.BlockRefused, dns.RcodeRefused, ""},
	}
	for _, c := range cases {
		t.Run(c.mode, func(t *testing.T) {
			addr, n := start(t, c.mode, nil, nil)
			r := query(t, addr, "ads.bloqueado.test", dns.TypeA, "udp")
			if r.Rcode != c.rcode {
				t.Errorf("rcode = %s", dns.RcodeToString[r.Rcode])
			}
			if c.ip != "" && firstA(t, r) != c.ip {
				t.Errorf("IP = %s", firstA(t, r))
			}
			if n.Load() != 0 {
				t.Error("domínio bloqueado não pode ir ao upstream")
			}
			opt := r.IsEdns0()
			if opt == nil || len(opt.Option) == 0 {
				t.Fatal("faltou o Extended DNS Error")
			}
			if ede, ok := opt.Option[0].(*dns.EDNS0_EDE); !ok || ede.InfoCode != dns.ExtendedErrorCodeBlocked {
				t.Errorf("EDE = %v", opt.Option[0])
			}
		})
	}
	t.Run("drop", func(t *testing.T) {
		addr, _ := start(t, config.BlockDrop, nil, nil)
		m := new(dns.Msg)
		m.SetQuestion("bloqueado.test.", dns.TypeA)
		c := &dns.Client{Timeout: 300 * time.Millisecond}
		if _, _, err := c.Exchange(m, addr); err == nil {
			t.Error("drop não deveria responder")
		}
	})
}

func TestLocalRecord(t *testing.T) {
	addr, n := start(t, config.BlockNull, nil, nil)
	r := query(t, addr, "nas.casa", dns.TypeA, "udp")
	if firstA(t, r) != "192.168.0.10" || !r.Authoritative {
		t.Errorf("resposta local = %v", r)
	}
	if r := query(t, addr, "nas.casa", dns.TypeAAAA, "udp"); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Errorf("AAAA deveria ser NODATA: %v", r)
	}
	if n.Load() != 0 {
		t.Error("registro local não pode ir ao upstream")
	}
}

func TestACL(t *testing.T) {
	addr, n := start(t, config.BlockNull, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, nil)
	if r := query(t, addr, "exemplo.com", dns.TypeA, "udp"); r.Rcode != dns.RcodeRefused {
		t.Errorf("rcode = %s; cliente fora da rede permitida", dns.RcodeToString[r.Rcode])
	}
	if n.Load() != 0 {
		t.Error("consulta recusada não pode ir ao upstream")
	}
}

func TestNXDomainCached(t *testing.T) {
	addr, n := start(t, config.BlockNull, nil, nil)
	for range 3 {
		if r := query(t, addr, "nx.exemplo.com", dns.TypeA, "udp"); r.Rcode != dns.RcodeNameError {
			t.Fatalf("rcode = %s", dns.RcodeToString[r.Rcode])
		}
	}
	if n.Load() != 1 {
		t.Errorf("NXDOMAIN consultado %d vezes", n.Load())
	}
}

func startWithClients(t *testing.T) (string, *clients.Registry, *atomic.Int64) {
	t.Helper()
	addr, n := fakeUpstream(t)
	ups, err := upstream.New(upstream.Options{Servers: []string{addr}, Mode: upstream.ModeFastest, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ups.Close() })
	reg, err := clients.NewRegistry(clients.Options{})
	if err != nil {
		t.Fatal(err)
	}
	b := filter.NewBuilder()
	b.AddLine("||bloqueado.test^", false)
	mt := b.Build()
	srv := New(Options{
		Listen:       []string{"127.0.0.1:0"},
		Allowed:      []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		BlockMode:    config.BlockNull,
		BlockTTL:     10,
		LocalRecords: map[string][]netip.Addr{"nas.casa.": {netip.MustParseAddr("192.168.0.10")}},
		Cache:        cache.New(cache.Options{Size: 100}),
		Filter:       func() *filter.Matcher { return mt },
		Upstream:     ups,
		Clients:      reg,
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Shutdown(t.Context()) })
	return srv.Addrs()[0].String(), reg, n
}

func TestIsolatedClient(t *testing.T) {
	addr, reg, n := startWithClients(t)
	query(t, addr, "exemplo.com", dns.TypeA, "udp") // registra o cliente
	c, err := reg.Find("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Isolate(c, clients.ModeRefused, "teste", []string{"liberado.com"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"exemplo.com", "nas.casa", "outro.com"} {
		if r := query(t, addr, name, dns.TypeA, "udp"); r.Rcode != dns.RcodeRefused {
			t.Errorf("%s: rcode = %s; cliente isolado", name, dns.RcodeToString[r.Rcode])
		}
	}
	if ip := firstA(t, query(t, addr, "api.liberado.com", dns.TypeA, "udp")); ip != "1.2.3.4" {
		t.Errorf("exceção do isolamento: %s", ip)
	}
	if err := reg.Isolate(c, clients.ModeNXDomain, "", nil); err != nil {
		t.Fatal(err)
	}
	if r := query(t, addr, "exemplo.com", dns.TypeA, "udp"); r.Rcode != dns.RcodeNameError {
		t.Errorf("modo nxdomain: %s", dns.RcodeToString[r.Rcode])
	}
	reg.Release(c)
	if ip := firstA(t, query(t, addr, "exemplo.com", dns.TypeA, "udp")); ip != "1.2.3.4" {
		t.Errorf("liberado: %s", ip)
	}
	v := c.View()
	if v.Blocked != 4 || v.Queries != 7 {
		t.Errorf("contadores = %d bloqueadas / %d consultas", v.Blocked, v.Queries)
	}
	_ = n
}

func TestClientRulesInServer(t *testing.T) {
	addr, reg, _ := startWithClients(t)
	query(t, addr, "exemplo.com", dns.TypeA, "udp")
	c, _ := reg.Find("127.0.0.1")
	reg.Update(c, func(s *clients.Settings) error {
		s.Deny = []string{"service:tiktok"}
		s.Allow = []string{"bloqueado.test"}
		return nil
	})
	if ip := firstA(t, query(t, addr, "www.tiktok.com", dns.TypeA, "udp")); ip != "0.0.0.0" {
		t.Errorf("regra do cliente: %s", ip)
	}
	if ip := firstA(t, query(t, addr, "ads.bloqueado.test", dns.TypeA, "udp")); ip != "1.2.3.4" {
		t.Errorf("exceção do cliente deveria vencer a lista global: %s", ip)
	}
	reg.Update(c, func(s *clients.Settings) error { s.Allow = nil; s.SkipGlobalLists = true; return nil })
	if ip := firstA(t, query(t, addr, "ads.bloqueado.test", dns.TypeA, "udp")); ip != "1.2.3.4" {
		t.Errorf("sem listas globais: %s", ip)
	}
}
