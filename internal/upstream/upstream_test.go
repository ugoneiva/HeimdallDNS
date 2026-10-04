package upstream

import (
	"math"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestByLatencyOrder(t *testing.T) {
	mk := func(addr string, lat time.Duration, healthy bool) *member {
		m := &member{addr: addr}
		if lat > 0 {
			m.latency.Store(math.Float64bits(float64(lat)))
		}
		m.healthy.Store(healthy)
		return m
	}
	members := []*member{
		mk("sem-medida", 0, true),
		mk("lento", 140*time.Millisecond, true),
		mk("caido", 5*time.Millisecond, false),
		mk("rapido", 15*time.Millisecond, true),
	}
	var got []string
	for _, m := range byLatency(members) {
		got = append(got, m.addr)
	}
	want := []string{"rapido", "lento", "sem-medida", "caido"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ordem = %v, quero %v", got, want)
		}
	}
}

func TestEWMA(t *testing.T) {
	m := &member{}
	m.record(100*time.Millisecond, nil)
	m.record(200*time.Millisecond, nil)
	if got := time.Duration(m.latencyNS()); got != 130*time.Millisecond {
		t.Errorf("média móvel = %v", got)
	}
	if !m.healthy.Load() || m.ok.Load() != 2 {
		t.Error("contagem de sucesso")
	}
}

func TestReconfigure(t *testing.T) {
	g, err := New(Options{Servers: []string{"127.0.0.1:5399"}, Mode: ModeFailover, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if err := g.Reconfigure(Options{Servers: []string{"https://dns.quad9.net/dns-query", "tls://1.1.1.1"}, Mode: ModeFastest}); err != nil {
		t.Fatal(err)
	}
	servers, mode := g.Config()
	if len(servers) != 2 || mode != ModeFastest || len(g.Stats()) != 2 {
		t.Errorf("depois de trocar: %v %s", servers, mode)
	}
	if err := g.Reconfigure(Options{Servers: []string{"nada://x"}}); err == nil {
		t.Error("endereço inválido deveria falhar")
	}
	if s, _ := g.Config(); len(s) != 2 {
		t.Error("falha na troca não pode mexer no que está em uso")
	}
	if Validate(nil, "") == nil || Validate([]string{"1.1.1.1"}, "aleatorio") == nil || Validate([]string{"1.1.1.1"}, "") != nil {
		t.Error("Validate")
	}
}

// fakeResolver imita um resolvedor que valida (ou não) DNSSEC.
func fakeResolver(t *testing.T, validates bool) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if validates && r.Question[0].Name == dnssecBroken {
			m.Rcode = dns.RcodeServerFailure
		} else {
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(1, 2, 3, 4)}}
			m.AuthenticatedData = validates
		}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestDNSSECCheck(t *testing.T) {
	good, bad := fakeResolver(t, true), fakeResolver(t, false)
	g, err := New(Options{Servers: []string{bad, good}, Mode: ModeFailover, Timeout: time.Second, RequireDNSSEC: true})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	// Antes de testar, ninguém validou: usa todos (não derruba a rede).
	if _, addr, err := g.Exchange(t.Context(), question("exemplo.com.")); err != nil || addr != bad {
		t.Fatalf("antes do teste: %s %v", addr, err)
	}
	g.CheckDNSSEC(t.Context())
	st := map[string]Stats{}
	for _, s := range g.Stats() {
		st[s.Address] = s
	}
	if st[good].DNSSEC != "yes" || st[bad].DNSSEC != "no" || st[bad].InUse || !st[good].InUse {
		t.Fatalf("resultado = %+v", st)
	}
	if _, addr, _ := g.Exchange(t.Context(), question("exemplo.com.")); addr != good {
		t.Errorf("com DNSSEC exigido, foi para %s", addr)
	}
}

func question(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	return m
}
