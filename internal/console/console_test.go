// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package console

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// fakeTenant imita a API de um HeimdallDNS.
func fakeTenant(t *testing.T, token string, acked *atomic.Int64) *httptest.Server {
	t.Helper()
	now := time.Now()
	mux := http.NewServeMux()
	j := func(w http.ResponseWriter, v any) { json.NewEncoder(w).Encode(v) }
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, _ *http.Request) {
		j(w, map[string]any{"version": "v1.2", "uptime_s": 3600, "clients": 12, "rules": map[string]int{"block": 300000},
			"upstreams": []map[string]bool{{"healthy": true}, {"healthy": false}}})
	})
	mux.HandleFunc("GET /api/stats/summary", func(w http.ResponseWriter, _ *http.Request) {
		j(w, map[string]any{"counts": map[string]int{"total": 5000}, "blocked_pct": 12.5, "active_clients": 9})
	})
	mux.HandleFunc("GET /api/security/summary", func(w http.ResponseWriter, _ *http.Request) {
		j(w, map[string]any{"open": map[string]int{"high": 1, "low": 1}, "open_total": 2})
	})
	mux.HandleFunc("GET /api/security/events", func(w http.ResponseWriter, _ *http.Request) {
		j(w, []map[string]any{
			{"id": 1, "kind": "new_device", "severity": "low", "summary": "novo", "last_seen": now, "count": 1},
			{"id": 2, "kind": "dga", "severity": "high", "summary": "dga", "last_seen": now.Add(-time.Hour), "count": 3},
		})
	})
	mux.HandleFunc("GET /api/ha", func(w http.ResponseWriter, _ *http.Request) { j(w, map[string]string{"role": "primary"}) })
	mux.HandleFunc("POST /api/security/events/{id}/ack", func(w http.ResponseWriter, r *http.Request) {
		acked.Add(1)
		w.WriteHeader(200)
	})
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, `{"error":"token ausente ou inválido"}`, http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	}))
}

func TestConsole(t *testing.T) {
	var acked atomic.Int64
	ts := fakeTenant(t, "tok-a", &acked)
	defer ts.Close()
	c, _ := New(Options{})
	ctx := context.Background()

	if _, err := c.Add(ctx, Tenant{Name: "Cliente A", URL: ts.URL, Token: "errado"}); err == nil {
		t.Error("token errado deveria falhar no cadastro")
	}
	if _, err := c.Add(ctx, Tenant{Name: "X", URL: "ftp://x", Token: "t"}); err == nil {
		t.Error("URL inválida")
	}
	a, err := c.Add(ctx, Tenant{Name: "Cliente A", URL: ts.URL + "/", Token: "tok-a"})
	if err != nil {
		t.Fatal(err)
	}
	// Cliente fora do ar: cadastra direto (sem passar pelo teste) para simular a queda depois.
	c.tenants["b"] = Tenant{ID: "b", Name: "Cliente B", URL: "http://127.0.0.1:1", Token: "x"}

	c.pollAll(ctx)
	sts := c.States()
	if len(sts) != 2 || sts[0].Name != "Cliente A" {
		t.Fatalf("states = %+v", sts)
	}
	sa, sb := sts[0], sts[1]
	if !sa.Online || sa.Version != "v1.2" || sa.Queries24h != 5000 || sa.BlockedPct != 12.5 || sa.OpenTotal != 2 ||
		sa.UpstreamsOK != 1 || sa.Upstreams != 2 || sa.HARole != "primary" || sa.Rules != 300000 {
		t.Errorf("cliente A = %+v", sa)
	}
	if sb.Online || sb.Error == "" {
		t.Errorf("cliente B deveria estar fora do ar: %+v", sb)
	}
	al := c.Alerts()
	if len(al) != 2 || al[0].Severity != "high" || al[0].TenantName != "Cliente A" {
		t.Errorf("alertas (mais grave primeiro) = %+v", al)
	}
	if err := c.Ack(ctx, a.ID, 2); err != nil || acked.Load() != 1 {
		t.Errorf("ack repassado: %v %d", err, acked.Load())
	}
	if c.Remove(a.ID) != nil || len(c.States()) != 1 || len(c.Alerts()) != 0 {
		t.Error("remover cliente")
	}
}
