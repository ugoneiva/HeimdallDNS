// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package ha

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/clients"
)

func init() {
	longPoll = 600 * time.Millisecond
	retryWait = 50 * time.Millisecond
}

type primary struct {
	mu   sync.Mutex
	deny []string
}

func (p *primary) build() (Snapshot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return Snapshot{Deny: append([]string(nil), p.deny...), Clients: []clients.State{{ID: "a1"}}}, nil
}

func (p *primary) set(d ...string) {
	p.mu.Lock()
	p.deny = d
	p.mu.Unlock()
}

func TestReplicaFollowsPrimary(t *testing.T) {
	p := &primary{deny: []string{"um.com"}}
	src := NewSource("segredo-de-sincronizacao", p.build, nil)
	ts := httptest.NewServer(src)
	defer ts.Close()

	got := make(chan Snapshot, 10)
	r, err := NewReplica(ReplicaOptions{PrimaryURL: ts.URL, Token: "segredo-de-sincronizacao",
		Apply: func(s Snapshot) error { got <- s; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	wait := func() Snapshot {
		t.Helper()
		select {
		case s := <-got:
			return s
		case <-time.After(3 * time.Second):
			t.Fatal("a réplica não recebeu o snapshot")
		}
		return Snapshot{}
	}
	first := wait()
	if len(first.Deny) != 1 || first.Version == "" {
		t.Fatalf("primeiro snapshot = %+v", first)
	}
	// Sem mudança: nada novo é aplicado (o long-poll volta 304).
	select {
	case s := <-got:
		t.Fatalf("aplicou sem mudança: %+v", s)
	case <-time.After(800 * time.Millisecond):
	}
	// Mudança no principal chega rápido.
	start := time.Now()
	p.set("um.com", "dois.com")
	second := wait()
	if len(second.Deny) != 2 || second.Version == first.Version {
		t.Errorf("segundo snapshot = %+v", second)
	}
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Errorf("demorou %s para propagar", d)
	}
	if st := r.Status(); st.Version != second.Version || st.Error != "" || st.LastSync.IsZero() {
		t.Errorf("status da réplica = %+v", st)
	}
	if reps := src.Replicas(); len(reps) != 1 {
		t.Errorf("o principal deveria ver a réplica: %+v", reps)
	}
}

func TestWrongTokenAndApplyError(t *testing.T) {
	p := &primary{}
	ts := httptest.NewServer(NewSource("segredo-de-sincronizacao", p.build, nil))
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/api/sync/snapshot")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("sem token: %d", resp.StatusCode)
	}

	r, _ := NewReplica(ReplicaOptions{PrimaryURL: ts.URL, Token: "token-errado-123456",
		Apply: func(Snapshot) error { return nil }})
	if err := r.once(context.Background()); err == nil {
		t.Error("token errado deveria falhar")
	}
	r2, _ := NewReplica(ReplicaOptions{PrimaryURL: ts.URL, Token: "segredo-de-sincronizacao",
		Apply: func(Snapshot) error { return errors.New("disco cheio") }})
	if err := r2.once(context.Background()); err == nil || r2.Status().Version != "" {
		t.Error("erro ao aplicar não pode avançar a versão")
	}
}

func TestErrorClearsOnReconnect(t *testing.T) {
	p := &primary{}
	src := NewSource("segredo-de-sincronizacao", p.build, nil)
	ts := httptest.NewUnstartedServer(src)
	addr := ts.Listener.Addr().String()
	r, _ := NewReplica(ReplicaOptions{PrimaryURL: "http://" + addr, Token: "segredo-de-sincronizacao",
		Apply: func(Snapshot) error { return nil }})
	// Principal fora do ar.
	ts.Listener.Close()
	if err := r.once(context.Background()); err == nil {
		t.Fatal("deveria falhar com o principal fora")
	}
	// Principal volta. A réplica já tem a versão atual, então o pedido fica
	// esperando (long-poll de 600 ms nos testes); o erro precisa sumir antes.
	ts = httptest.NewServer(src)
	defer ts.Close()
	r.url = ts.URL
	r.ok(src.Version())
	r.mu.Lock()
	r.lastErr = "fora do ar"
	r.mu.Unlock()
	go r.once(context.Background())
	deadline := time.Now().Add(300 * time.Millisecond) // antes do fim do long-poll
	for r.Status().Error != "" {
		if time.Now().After(deadline) {
			t.Fatal("o erro só deveria durar até a conexão abrir")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
