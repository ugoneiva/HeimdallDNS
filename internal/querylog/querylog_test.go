// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package querylog

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/server"
)

type nopSink struct {
	mu   sync.Mutex
	rows int
}

func (n *nopSink) InsertQueries(es []Entry) error {
	n.mu.Lock()
	n.rows += len(es)
	n.mu.Unlock()
	return nil
}
func (*nopSink) AddStats([]MinuteStat, []DomainCount) error { return nil }
func (*nopSink) Purge(time.Time, time.Time) (int64, error)  { return 0, nil }

func event(name, status, client string) server.Event {
	return server.Event{Time: time.Now(), Client: netip.MustParseAddr(client), ClientID: client,
		Name: name + ".", Type: "A", Status: status}
}

func TestLiveFilterAndDrop(t *testing.T) {
	r := New(Options{Sink: &nopSink{}, Retention: time.Hour, StatsRetention: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	blocked := r.Subscribe(Filter{Statuses: []string{server.StatusBlocked}})
	defer blocked.Close()
	search := r.Subscribe(Filter{Search: "git"})
	defer search.Close()

	r.Record(event("github.com", server.StatusForwarded, "10.0.0.1"))
	r.Record(event("ads.com", server.StatusBlocked, "10.0.0.2"))

	got := func(s *Subscription) Entry {
		select {
		case e := <-s.C:
			return e
		case <-time.After(2 * time.Second):
			t.Fatal("evento não chegou")
		}
		return Entry{}
	}
	if e := got(blocked); e.Name != "ads.com" || e.ClientIP != "10.0.0.2" {
		t.Errorf("filtro de status: %+v", e)
	}
	if e := got(search); e.Name != "github.com" {
		t.Errorf("busca: %+v", e)
	}

	// Assinante que não lê: o excedente é descartado e contado.
	slow := r.Subscribe(Filter{})
	for range subBuffer + 10 {
		r.Record(event("x.com", server.StatusCached, "10.0.0.3"))
	}
	deadline := time.Now().Add(2 * time.Second)
	for slow.dropped.Load() < 10 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := slow.Dropped(); n != 10 {
		t.Errorf("descartados = %d", n)
	}
	slow.Close()
	slow.Close() // fechar duas vezes não quebra
}

func TestRealtime(t *testing.T) {
	r := New(Options{Sink: &nopSink{}, Retention: time.Hour, StatsRetention: time.Hour})
	past := time.Now().Add(-2 * time.Second).Truncate(time.Second)
	for _, st := range []string{server.StatusForwarded, server.StatusBlocked, server.StatusIsolated, server.StatusStale} {
		e := event("a.com", st, "10.0.0.1")
		e.Time = past
		r.process(e)
	}
	rt := r.Realtime(5)
	var s Second
	for _, x := range rt {
		if x.Time == past.Unix() {
			s = x
		}
	}
	if s.Total != 4 || s.Blocked != 2 || s.Cached != 1 {
		t.Errorf("segundo = %+v (%v)", s, rt)
	}
	if rt[len(rt)-1].Time != time.Now().Unix()-1 {
		t.Error("o último ponto deve ser o segundo anterior")
	}
}

func TestTopCardinalityCap(t *testing.T) {
	r := New(Options{Sink: &nopSink{}, Retention: time.Hour, StatsRetention: time.Hour})
	now := time.Now()
	for i := range maxTopPerHour + 5 {
		e := event("d"+itoa(i)+".com", server.StatusForwarded, "10.0.0.1")
		e.Time = now
		r.process(e)
	}
	if len(r.tops) != maxTopPerHour+1 {
		t.Errorf("domínios distintos = %d", len(r.tops))
	}
	if r.tops[topKey{now.Unix() / 3600, otherDomains, false}] != 5 {
		t.Error("excedente deveria ir para (outros)")
	}
}

func itoa(i int) string {
	b := []byte{}
	for {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
		if i == 0 {
			return string(b)
		}
	}
}
