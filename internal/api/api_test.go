package api

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/clients"
	"github.com/ugoneiva/HeimdallDNS/internal/querylog"
	"github.com/ugoneiva/HeimdallDNS/internal/server"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

func setup(t *testing.T) (*httptest.Server, *clients.Registry) {
	t.Helper()
	reg, err := clients.NewRegistry(clients.Options{})
	if err != nil {
		t.Fatal(err)
	}
	reg.Observe(netip.MustParseAddr("192.168.0.50"), time.Now())
	ts := httptest.NewServer(New(Deps{Token: "segredo", Clients: reg}))
	t.Cleanup(ts.Close)
	return ts, reg
}

func call(t *testing.T, ts *httptest.Server, method, path, token, body string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func TestAuth(t *testing.T) {
	ts, _ := setup(t)
	for _, tok := range []string{"", "errado"} {
		if resp, _ := call(t, ts, "GET", "/api/clients", tok, ""); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("token %q: %d", tok, resp.StatusCode)
		}
	}
	if resp, _ := call(t, ts, "GET", "/api/clients", "segredo", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("token certo: %d", resp.StatusCode)
	}
}

func TestIsolateFlow(t *testing.T) {
	ts, reg := setup(t)
	resp, out := call(t, ts, "POST", "/api/clients/192.168.0.50/isolate", "segredo",
		`{"mode":"drop","reason":"beacon C2","exceptions":["update.av.com"]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("isolate: %d %v", resp.StatusCode, out)
	}
	c, _ := reg.Find("192.168.0.50")
	if p := c.Policy(); !p.Isolated || p.IsolateMode != "drop" {
		t.Errorf("política = %+v", p)
	}

	resp, _ = call(t, ts, "PATCH", "/api/clients/"+c.ID(), "segredo", `{"name":"PC do financeiro","deny":["service:tiktok"]}`)
	if resp.StatusCode != http.StatusOK || c.View().Display != "PC do financeiro" {
		t.Errorf("patch: %d %+v", resp.StatusCode, c.View())
	}
	if resp, _ := call(t, ts, "POST", "/api/clients/PC%20do%20financeiro/release", "segredo", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("release pelo nome: %d", resp.StatusCode)
	}
	if c.Policy().Isolated {
		t.Error("deveria estar liberado")
	}
}

func TestErrors(t *testing.T) {
	ts, _ := setup(t)
	cases := []struct {
		method, path, body string
		code               int
	}{
		{"GET", "/api/clients/naoexiste", "", http.StatusNotFound},
		{"POST", "/api/clients/192.168.0.50/isolate", `{"mode":"explodir"}`, http.StatusBadRequest},
		{"PATCH", "/api/clients/192.168.0.50", `{"deny":["service:xyz"]}`, http.StatusBadRequest},
		{"PATCH", "/api/clients/192.168.0.50", `{"campo_errado":1}`, http.StatusBadRequest},
	}
	for _, c := range cases {
		resp, out := call(t, ts, c.method, c.path, "segredo", c.body)
		if resp.StatusCode != c.code || out["error"] == nil {
			t.Errorf("%s %s: %d %v", c.method, c.path, resp.StatusCode, out)
		}
	}
}

// clientID é o id do dispositivo "Celular" criado em setupHistory.
var clientID string

func setupHistory(t *testing.T) (*httptest.Server, *querylog.Recorder, *store.Store) {
	t.Helper()
	reg, _ := clients.NewRegistry(clients.Options{})
	st, err := store.Open(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	rec := querylog.New(querylog.Options{Sink: st, StoreQueries: true, Retention: time.Hour, StatsRetention: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	go rec.Run(ctx)
	ts := httptest.NewServer(New(Deps{Context: ctx, Token: "segredo", Clients: reg, Store: st, Log: rec}))
	t.Cleanup(func() {
		ts.CloseClientConnections()
		ts.Close()
		cancel()
		<-rec.Done()
		st.Close()
	})
	c := reg.Observe(netip.MustParseAddr("192.168.0.7"), time.Now())
	reg.Update(c, func(s *clients.Settings) error { s.Name = "Celular"; return nil })
	clientID = c.ID()
	return ts, rec, st
}

func evt(name, status string) server.Event {
	return server.Event{Time: time.Now(), Client: netip.MustParseAddr("192.168.0.7"), ClientID: clientID, Name: name + ".",
		Type: "A", Status: status, Rcode: "NOERROR", Duration: time.Millisecond}
}

func TestLiveSSE(t *testing.T) {
	ts, rec, _ := setupHistory(t)
	resp, err := http.Get(ts.URL + "/api/queries/live?token=segredo&status=blocked")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); resp.StatusCode != 200 || ct != "text/event-stream" {
		t.Fatalf("%d %s", resp.StatusCode, ct)
	}
	// Dá tempo de a assinatura existir antes de publicar.
	time.Sleep(100 * time.Millisecond)
	rec.Record(evt("permitido.com", server.StatusForwarded))
	rec.Record(evt("ads.com", server.StatusBlocked))

	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	timeout := time.After(3 * time.Second)
	for {
		select {
		case l := <-lines:
			if !strings.HasPrefix(l, "data: ") {
				continue
			}
			var e querylog.Entry
			json.Unmarshal([]byte(strings.TrimPrefix(l, "data: ")), &e)
			if e.Name != "ads.com" || e.Status != "blocked" {
				t.Fatalf("o filtro deixou passar: %+v", e)
			}
			return
		case <-timeout:
			t.Fatal("evento SSE não chegou")
		}
	}
}

func TestLiveRequiresToken(t *testing.T) {
	ts, _, _ := setupHistory(t)
	resp, err := http.Get(ts.URL + "/api/queries/live?token=errado")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("token errado no SSE: %d", resp.StatusCode)
	}
	// Token na URL só vale nas rotas ao vivo.
	if resp, _ := call(t, ts, "GET", "/api/clients?token=segredo", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("token na URL fora do /live: %d", resp.StatusCode)
	}
}

func TestHistoryRoutes(t *testing.T) {
	ts, rec, st := setupHistory(t)
	for range 3 {
		rec.Record(evt("netflix.com", server.StatusForwarded))
	}
	rec.Record(evt("ads.com", server.StatusBlocked))
	// Espera o lote ser gravado.
	deadline := time.Now().Add(3 * time.Second)
	for {
		rows, _ := st.History(store.HistoryQuery{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour), Limit: 10})
		if len(rows) == 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("histórico não gravou: %d", len(rows))
		}
		time.Sleep(50 * time.Millisecond)
	}

	get := func(path string, v any) {
		t.Helper()
		req, _ := http.NewRequest("GET", ts.URL+path, nil)
		req.Header.Set("Authorization", "Bearer segredo")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
		json.NewDecoder(resp.Body).Decode(v)
	}

	var q struct {
		Queries []querylog.Entry `json:"queries"`
	}
	get("/api/queries?range=1h&client=Celular&status=blocked", &q)
	if len(q.Queries) != 1 || q.Queries[0].Name != "ads.com" || q.Queries[0].ClientName != "Celular" {
		t.Errorf("queries = %+v", q.Queries)
	}
	var sum struct {
		Counts     querylog.Counts `json:"counts"`
		BlockedPct float64         `json:"blocked_pct"`
	}
	get("/api/stats/summary?range=1h", &sum)
	if sum.Counts.Total != 4 || sum.BlockedPct != 25 {
		t.Errorf("summary = %+v", sum)
	}
	var top []struct {
		Key   string `json:"key"`
		Count int64  `json:"count"`
	}
	get("/api/stats/top?kind=domains&range=1d", &top)
	if len(top) != 1 || top[0].Key != "netflix.com" || top[0].Count != 3 {
		t.Errorf("top = %+v", top)
	}
	var tsr struct {
		Step   int `json:"step_s"`
		Points []struct {
			Total int64 `json:"total"`
		} `json:"points"`
	}
	get("/api/stats/timeseries?range=1h", &tsr)
	if tsr.Step != 60 || len(tsr.Points) < 60 {
		t.Errorf("timeseries: step %d, %d pontos", tsr.Step, len(tsr.Points))
	}

	for _, bad := range []string{"/api/stats/summary?range=xyz", "/api/stats/top?kind=nada", "/api/stats/timeseries?range=30d&step=1m"} {
		if resp, _ := call(t, ts, "GET", bad, "segredo", ""); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, resp.StatusCode)
		}
	}
}

func TestAccessTokenAndMobileconfig(t *testing.T) {
	reg, _ := clients.NewRegistry(clients.Options{})
	c := reg.Observe(netip.MustParseAddr("192.168.0.70"), time.Now())
	reg.Update(c, func(s *clients.Settings) error { s.Name = "iPhone <da Ana>"; return nil })
	ts := httptest.NewServer(New(Deps{Token: "segredo", Clients: reg,
		Encrypted: Encrypted{PublicHost: "dns.empresa.com.br", DoH: true, DoT: true, DoHPort: "443", DoTPort: "853"}}))
	defer ts.Close()

	if resp, _ := call(t, ts, "GET", "/api/clients/"+c.ID()+"/mobileconfig", "segredo", ""); resp.StatusCode != http.StatusConflict {
		t.Errorf("sem token, perfil = %d", resp.StatusCode)
	}
	resp, out := call(t, ts, "POST", "/api/clients/"+c.ID()+"/token", "segredo", "")
	tok, _ := out["token"].(string)
	if resp.StatusCode != 200 || len(tok) != 16 ||
		out["doh_url"] != "https://dns.empresa.com.br/dns-query/"+tok || out["dot_host"] != tok+".dns.empresa.com.br" {
		t.Fatalf("token: %d %v", resp.StatusCode, out)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/api/clients/"+c.ID()+"/mobileconfig", nil)
	req.Header.Set("Authorization", "Bearer segredo")
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	p := string(body)
	if r.Header.Get("Content-Type") != "application/x-apple-aspen-config" ||
		!strings.Contains(p, "<string>https://dns.empresa.com.br/dns-query/"+tok+"</string>") ||
		!strings.Contains(p, "com.apple.dnsSettings.managed") ||
		!strings.Contains(p, "iPhone &lt;da Ana&gt;") {
		t.Errorf("perfil:\n%s", p)
	}
	if err := xml.Unmarshal(body, new(struct{})); err != nil {
		t.Errorf("perfil não é XML válido: %v", err)
	}
	if resp, out := call(t, ts, "DELETE", "/api/clients/"+c.ID()+"/token", "segredo", ""); resp.StatusCode != 200 || out["token"] != nil {
		t.Errorf("revogar: %d %v", resp.StatusCode, out)
	}
	if reg.ByToken(tok) != nil {
		t.Error("token revogado continua valendo")
	}
}

func TestReplicaReadOnly(t *testing.T) {
	reg, _ := clients.NewRegistry(clients.Options{})
	reg.Observe(netip.MustParseAddr("192.168.0.80"), time.Now())
	ts := httptest.NewServer(New(Deps{Token: "segredo", Clients: reg, HA: HA{Role: "replica"}}))
	defer ts.Close()
	if resp, out := call(t, ts, "PATCH", "/api/clients/192.168.0.80", "segredo", `{"name":"x"}`); resp.StatusCode != http.StatusConflict ||
		!strings.Contains(out["error"].(string), "réplica") {
		t.Errorf("edição na réplica: %d %v", resp.StatusCode, out)
	}
	if resp, _ := call(t, ts, "GET", "/api/clients", "segredo", ""); resp.StatusCode != 200 {
		t.Errorf("leitura na réplica: %d", resp.StatusCode)
	}
	if resp, out := call(t, ts, "GET", "/api/ha", "segredo", ""); resp.StatusCode != 200 || out["role"] != "replica" {
		t.Errorf("status HA: %v", out)
	}
}
