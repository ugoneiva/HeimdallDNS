// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package nrd

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/security"
	"github.com/ugoneiva/HeimdallDNS/internal/server"
)

// rdapServer responde como um registro: novo.com foi registrado há 3 dias,
// antigo.com há 10 anos; o resto não existe.
func rdapServer(t *testing.T, now time.Time) (*httptest.Server, *int) {
	t.Helper()
	var mu sync.Mutex
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		reg := map[string]time.Time{
			"novo.com":   now.Add(-3 * 24 * time.Hour),
			"antigo.com": now.AddDate(-10, 0, 0),
		}[strings.TrimPrefix(r.URL.Path, "/domain/")]
		if reg.IsZero() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		fmt.Fprintf(w, `{"objectClassName":"domain","events":[{"eventAction":"last changed","eventDate":"2026-01-01T00:00:00Z"},{"eventAction":"registration","eventDate":%q}]}`,
			reg.UTC().Format(time.RFC3339))
	}))
	t.Cleanup(ts.Close)
	return ts, &calls
}

func TestParseBootstrap(t *testing.T) {
	raw := `{"version":"1.0","services":[[["com","net"],["http://rdap.exemplo/com/","https://rdap.exemplo/com/"]],[["br"],["https://rdap.registro.br"]]]}`
	m, err := parseBootstrap([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if m["com"] != "https://rdap.exemplo/com/" || m["net"] != m["com"] || m["br"] != "https://rdap.registro.br/" {
		t.Errorf("mapa = %v", m)
	}
}

func TestCheckerAlertAndBlock(t *testing.T) {
	now := time.Now()
	ts, calls := rdapServer(t, now)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "rdap-dns.json"),
		[]byte(`{"services":[[["com"],["`+ts.URL+`/"]]]}`), 0o644)

	var mu sync.Mutex
	var alerts []security.Alert
	settings := security.Settings{NRD: true, NRDAction: "alert", NRDMaxDays: 30}
	c, err := New(Options{
		DataDir:  dir,
		Settings: func() security.Settings { mu.Lock(); defer mu.Unlock(); return settings },
		Raise:    func(a security.Alert) { mu.Lock(); alerts = append(alerts, a); mu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	ev := func(name string) server.Event {
		return server.Event{Time: now, Client: netip.MustParseAddr("10.0.0.20"), ClientID: "cli", Name: name + ".",
			Status: server.StatusForwarded, Rcode: "NOERROR"}
	}
	c.Observe(ev("www.novo.com"))
	c.Observe(ev("cdn.novo.com")) // mesmo domínio registrável: uma consulta RDAP só
	c.Observe(ev("antigo.com"))
	c.Observe(ev("x.naoexiste.com"))
	c.Observe(ev("algo.org")) // TLD sem servidor no mapa

	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(alerts)
		mu.Unlock()
		_, known := c.Age("antigo.com")
		if n >= 1 && known {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("RDAP não respondeu a tempo: %d alertas", n)
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(1200 * time.Millisecond) // deixa terminar as consultas da fila
	mu.Lock()
	if len(alerts) != 1 || alerts[0].Domain != "novo.com" || alerts[0].Severity != security.SevHigh {
		t.Errorf("alertas = %+v", alerts)
	}
	mu.Unlock()
	if *calls != 3 { // novo, antigo, naoexiste (org não tem servidor)
		t.Errorf("consultas RDAP = %d", *calls)
	}
	if age, ok := c.Age("qualquer.novo.com"); !ok || age > 4*24*time.Hour {
		t.Errorf("idade = %v %v", age, ok)
	}

	// Modo alerta não bloqueia; modo bloqueio sim, só os jovens.
	if _, block := c.Block("www.novo.com"); block {
		t.Error("modo alerta não bloqueia")
	}
	mu.Lock()
	settings.NRDAction = "block"
	mu.Unlock()
	if rule, block := c.Block("www.novo.com"); !block || !strings.Contains(rule, "3 dias") {
		t.Errorf("bloqueio = %q %v", rule, block)
	}
	if _, block := c.Block("antigo.com"); block {
		t.Error("domínio antigo não é bloqueado")
	}
}
