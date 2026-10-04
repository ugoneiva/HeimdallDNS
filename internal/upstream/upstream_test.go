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
	g := &Group{members: []*member{
		mk("sem-medida", 0, true),
		mk("lento", 140*time.Millisecond, true),
		mk("caido", 5*time.Millisecond, false),
		mk("rapido", 15*time.Millisecond, true),
	}}
	var got []string
	for _, m := range g.byLatency() {
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
