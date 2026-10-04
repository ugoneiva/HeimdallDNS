package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/clients"
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
