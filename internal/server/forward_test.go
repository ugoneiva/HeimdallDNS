// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

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
	"github.com/ugoneiva/HeimdallDNS/internal/forward"
	"github.com/ugoneiva/HeimdallDNS/internal/upstream"
)

func TestConditionalForward(t *testing.T) {
	pubAddr, pub := fakeUpstream(t)
	intAddr, internal := fakeUpstream(t)
	// Porta sem ninguém ouvindo: o "DC" fora do ar.
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	dead := pc.LocalAddr().String()
	pc.Close()

	ups, err := upstream.New(upstream.Options{Servers: []string{pubAddr}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ups.Close() })
	fw, err := forward.NewManager([]forward.Rule{{Domain: "empresa.local", Servers: []string{intAddr}}}, 500*time.Millisecond, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fw.Close)
	var private atomic.Bool
	evs := make(chan Event, 20)
	srv := New(Options{Listen: []string{"127.0.0.1:0"}, Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		Cache: cache.New(cache.Options{Size: 100}), Upstream: ups, Forward: fw, Timeout: time.Second,
		PrivateUpstream: func() bool { return private.Load() }, OnQuery: func(e Event) { evs <- e }})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Shutdown(t.Context()) })
	dst := srv.Addrs()[0].String()
	last := func() Event {
		select {
		case e := <-evs:
			return e
		case <-time.After(2 * time.Second):
			t.Fatal("sem evento")
			return Event{}
		}
	}

	query(t, dst, "dc01.empresa.local", dns.TypeA, "udp")
	if e := last(); internal.Load() != 1 || pub.Load() != 0 || !strings.Contains(e.Upstream, "(empresa.local)") {
		t.Fatalf("nome interno: interno=%d público=%d upstream=%q", internal.Load(), pub.Load(), e.Upstream)
	}
	query(t, dst, "www.exemplo.com", dns.TypeA, "udp")
	last()
	if pub.Load() != 1 || internal.Load() != 1 {
		t.Fatal("nome de fora vai para o upstream normal")
	}

	// Reverso de IP privado sem regra: NXDOMAIN local, nada sai.
	r := query(t, dst, "20.1.168.192.in-addr.arpa", dns.TypePTR, "udp")
	if e := last(); r.Rcode != dns.RcodeNameError || e.Status != StatusLocal || pub.Load() != 1 {
		t.Fatalf("PTR privado = %s %s (público=%d)", dns.RcodeToString[r.Rcode], e.Status, pub.Load())
	}
	// Com um upstream privado (o roteador), o reverso pode ir para ele.
	private.Store(true)
	query(t, dst, "21.1.168.192.in-addr.arpa", dns.TypePTR, "udp")
	last()
	if pub.Load() != 2 {
		t.Fatal("upstream privado recebe o reverso")
	}
	private.Store(false)

	// Rede com regra: o reverso vai para o DNS interno.
	if err := fw.Apply([]forward.Rule{{Network: "192.168.1.0/24", Servers: []string{intAddr}}}); err != nil {
		t.Fatal(err)
	}
	query(t, dst, "22.1.168.192.in-addr.arpa", dns.TypePTR, "udp")
	last()
	if internal.Load() != 2 || pub.Load() != 2 {
		t.Fatalf("reverso da rede com regra: interno=%d público=%d", internal.Load(), pub.Load())
	}

	// DNS interno fora do ar: SERVFAIL, sem vazar para a internet.
	if err := fw.Apply([]forward.Rule{{Domain: "empresa.local", Servers: []string{dead}}}); err != nil {
		t.Fatal(err)
	}
	r = query(t, dst, "srv.empresa.local", dns.TypeA, "udp")
	if e := last(); r.Rcode != dns.RcodeServerFailure || e.Status != StatusError || pub.Load() != 2 {
		t.Fatalf("interno fora do ar = %s (público=%d)", dns.RcodeToString[r.Rcode], pub.Load())
	}
}
