package upstream

import (
	"math"
	"testing"
	"time"
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
