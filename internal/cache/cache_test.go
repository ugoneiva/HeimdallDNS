// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package cache

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }
func newTest(o Options) (*Cache, *clock) {
	c := New(o)
	ck := &clock{t: time.Unix(1_700_000_000, 0)}
	c.now = ck.now
	return c, ck
}

func answer(name string, ttl uint32) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	m.Response = true
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.IPv4(1, 2, 3, 4),
	}}
	m.SetEdns0(1232, false)
	return m
}

func key(name string) Key { return Key{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET} }

func TestTTLCountdownAndExpiry(t *testing.T) {
	c, ck := newTest(Options{Size: 10})
	c.Set(key("a.com."), answer("a.com.", 100))

	ck.add(40 * time.Second)
	m, stale, ok := c.Get(key("a.com."))
	if !ok || stale {
		t.Fatalf("ok=%v stale=%v", ok, stale)
	}
	if ttl := m.Answer[0].Header().Ttl; ttl != 60 {
		t.Errorf("TTL = %d, quero 60", ttl)
	}
	if m.IsEdns0() != nil {
		t.Error("o OPT não deve ir para o cache")
	}
	ck.add(61 * time.Second)
	if _, _, ok := c.Get(key("a.com.")); ok {
		t.Error("deveria ter vencido")
	}
}

func TestServeStale(t *testing.T) {
	c, ck := newTest(Options{Size: 10, ServeStale: time.Hour})
	c.Set(key("a.com."), answer("a.com.", 10))
	ck.add(30 * time.Minute)
	m, stale, ok := c.Get(key("a.com."))
	if !ok || !stale {
		t.Fatalf("ok=%v stale=%v", ok, stale)
	}
	if ttl := m.Answer[0].Header().Ttl; ttl != staleTTL {
		t.Errorf("TTL vencido = %d", ttl)
	}
	ck.add(31 * time.Minute)
	if _, _, ok := c.Get(key("a.com.")); ok {
		t.Error("passou da janela de serve-stale")
	}
}

func TestMinMaxTTL(t *testing.T) {
	c, ck := newTest(Options{Size: 10, MinTTL: 60, MaxTTL: 120})
	c.Set(key("curto.com."), answer("curto.com.", 5))
	c.Set(key("longo.com."), answer("longo.com.", 3600))
	ck.add(30 * time.Second)
	if m, _, ok := c.Get(key("curto.com.")); !ok || m.Answer[0].Header().Ttl > 31 {
		t.Errorf("min_ttl não aplicado: ok=%v", ok)
	}
	ck.add(100 * time.Second)
	if _, _, ok := c.Get(key("longo.com.")); ok {
		t.Error("max_ttl não aplicado")
	}
}

func TestNegativeCache(t *testing.T) {
	c, ck := newTest(Options{Size: 10})
	m := new(dns.Msg)
	m.SetQuestion("nao.existe.", dns.TypeA)
	m.Rcode = dns.RcodeNameError
	m.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "existe.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 900}, Minttl: 30}}
	c.Set(key("nao.existe."), m)
	ck.add(20 * time.Second)
	if _, _, ok := c.Get(key("nao.existe.")); !ok {
		t.Error("NXDOMAIN deveria estar no cache")
	}
	ck.add(15 * time.Second)
	if _, _, ok := c.Get(key("nao.existe.")); ok {
		t.Error("deveria valer pelo mínimo da SOA (30 s)")
	}

	sf := new(dns.Msg)
	sf.Rcode = dns.RcodeServerFailure
	c.Set(key("falha.com."), sf)
	if _, _, ok := c.Get(key("falha.com.")); ok {
		t.Error("SERVFAIL não vai para o cache")
	}
}

func TestLRUEviction(t *testing.T) {
	c, _ := newTest(Options{Size: 2})
	c.Set(key("a."), answer("a.", 100))
	c.Set(key("b."), answer("b.", 100))
	c.Get(key("a.")) // a vira o mais recente
	c.Set(key("c."), answer("c.", 100))
	if _, _, ok := c.Get(key("b.")); ok {
		t.Error("b deveria ter saído")
	}
	if _, _, ok := c.Get(key("a.")); !ok {
		t.Error("a deveria continuar")
	}
	if c.Len() != 2 {
		t.Errorf("Len = %d", c.Len())
	}
}
