package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/clients"
	"github.com/ugoneiva/HeimdallDNS/internal/filter"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
	"golang.org/x/crypto/bcrypt"
)

type panel struct {
	ts     *httptest.Server
	api    *api
	client *http.Client // com cookies, como o navegador
	reg    *clients.Registry
	flt    *filter.Manager
}

func init() { bcryptCost = bcrypt.MinCost }

func newPanel(t *testing.T) *panel {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	reg, _ := clients.NewRegistry(clients.Options{})
	flt := filter.NewManager(filter.ManagerOptions{CacheDir: t.TempDir(), Logger: slog.New(slog.DiscardHandler)})
	flt.Start(t.Context())
	ui := fstest.MapFS{
		"index.html":        {Data: []byte("<html>painel</html>")},
		"assets/app-123.js": {Data: []byte("console.log(1)")},
	}
	a, h := build(Deps{Context: context.Background(), Token: "segredo", Store: st, Clients: reg, Filter: flt, UI: ui,
		Logger: slog.New(slog.DiscardHandler)})
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	return &panel{ts: ts, api: a, client: &http.Client{Jar: jar}, reg: reg, flt: flt}
}

func (p *panel) do(t *testing.T, method, path, body string, hdr ...string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, p.ts.URL+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", p.ts.URL)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := p.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	json.Unmarshal(raw, &out)
	if out == nil && len(raw) > 0 {
		out = map[string]any{"raw": string(raw)}
	}
	return resp, out
}

func TestSetupLoginLogout(t *testing.T) {
	p := newPanel(t)
	_, st := p.do(t, "GET", "/api/auth/state", "")
	if st["setup_required"] != true || st["authenticated"] != false {
		t.Fatalf("estado inicial = %v", st)
	}
	if r, _ := p.do(t, "GET", "/api/clients", ""); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("sem login: %d", r.StatusCode)
	}
	if r, _ := p.do(t, "POST", "/api/auth/setup", `{"code":"ERRADO","password":"senha-forte-1"}`); r.StatusCode != http.StatusForbidden {
		t.Errorf("código errado: %d", r.StatusCode)
	}
	code := strings.ToLower(p.api.setupCode) // aceita minúsculas
	if r, out := p.do(t, "POST", "/api/auth/setup", `{"code":"`+code+`","password":"curta"}`); r.StatusCode != http.StatusBadRequest {
		t.Errorf("senha curta: %d %v", r.StatusCode, out)
	}
	if r, out := p.do(t, "POST", "/api/auth/setup", `{"code":"`+code+`","password":"senha-forte-1"}`); r.StatusCode != http.StatusOK {
		t.Fatalf("setup: %d %v", r.StatusCode, out)
	}
	if r, _ := p.do(t, "POST", "/api/auth/setup", `{"code":"`+code+`","password":"outra-senha-2"}`); r.StatusCode != http.StatusConflict {
		t.Errorf("setup repetido: %d", r.StatusCode)
	}
	// A sessão do setup já vale.
	if r, _ := p.do(t, "GET", "/api/clients", ""); r.StatusCode != http.StatusOK {
		t.Errorf("com sessão: %d", r.StatusCode)
	}
	// Alteração vinda de outro site é barrada mesmo com o cookie.
	if r, _ := p.do(t, "PUT", "/api/rules", `{"deny":["x.com"]}`, "Origin", "https://malicioso.example"); r.StatusCode != http.StatusForbidden {
		t.Errorf("outra origem: %d", r.StatusCode)
	}
	p.do(t, "POST", "/api/auth/logout", "")
	if r, _ := p.do(t, "GET", "/api/clients", ""); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("depois do logout: %d", r.StatusCode)
	}
	if r, _ := p.do(t, "POST", "/api/auth/login", `{"password":"errada"}`); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("senha errada: %d", r.StatusCode)
	}
	if r, _ := p.do(t, "POST", "/api/auth/login", `{"password":"senha-forte-1"}`); r.StatusCode != http.StatusOK {
		t.Errorf("login: %d", r.StatusCode)
	}
	// Troca de senha pelo painel exige a atual.
	if r, _ := p.do(t, "POST", "/api/auth/password", `{"current":"errada","password":"nova-senha-3"}`); r.StatusCode != http.StatusForbidden {
		t.Errorf("troca sem a senha atual: %d", r.StatusCode)
	}
	if r, _ := p.do(t, "POST", "/api/auth/password", `{"current":"senha-forte-1","password":"nova-senha-3"}`); r.StatusCode != http.StatusNoContent {
		t.Errorf("troca: %d", r.StatusCode)
	}
	if r, _ := p.do(t, "GET", "/api/clients", ""); r.StatusCode != http.StatusOK {
		t.Error("quem trocou continua logado")
	}
	// Pelo token (comando passwd) não precisa da atual.
	anon := &http.Client{}
	req, _ := http.NewRequest("POST", p.ts.URL+"/api/auth/password", bytes.NewBufferString(`{"password":"recuperada-4"}`))
	req.Header.Set("Authorization", "Bearer segredo")
	if r, err := anon.Do(req); err != nil || r.StatusCode != http.StatusNoContent {
		t.Errorf("passwd pelo token: %v %v", r.StatusCode, err)
	}
	if r, _ := p.do(t, "GET", "/api/clients", ""); r.StatusCode != http.StatusUnauthorized {
		t.Error("a troca pelo token derruba as sessões")
	}
}

func TestLoginLockout(t *testing.T) {
	p := newPanel(t)
	p.do(t, "POST", "/api/auth/setup", `{"code":"`+p.api.setupCode+`","password":"senha-forte-1"}`)
	p.do(t, "POST", "/api/auth/logout", "")
	for range maxFailures {
		p.do(t, "POST", "/api/auth/login", `{"password":"errada"}`)
	}
	if r, _ := p.do(t, "POST", "/api/auth/login", `{"password":"senha-forte-1"}`); r.StatusCode != http.StatusTooManyRequests {
		t.Errorf("depois de %d erros: %d", maxFailures, r.StatusCode)
	}
}

func login(t *testing.T, p *panel) {
	t.Helper()
	if r, out := p.do(t, "POST", "/api/auth/setup", `{"code":"`+p.api.setupCode+`","password":"senha-forte-1"}`); r.StatusCode != 200 {
		t.Fatalf("setup: %v", out)
	}
}

func TestRulesListsAndTest(t *testing.T) {
	p := newPanel(t)
	login(t, p)

	if r, out := p.do(t, "PUT", "/api/rules", `{"deny":["service:tiktok","ruim.com"],"allow":["bom.ruim.com"]}`); r.StatusCode != 200 {
		t.Fatalf("regras: %v", out)
	}
	if r, _ := p.do(t, "PUT", "/api/rules", `{"deny":["service:inexistente"]}`); r.StatusCode != http.StatusBadRequest {
		t.Errorf("regra inválida: %d", r.StatusCode)
	}
	check := func(name, client, want string) {
		t.Helper()
		path := "/api/filter/test?name=" + name
		if client != "" {
			path += "&client=" + client
		}
		_, out := p.do(t, "GET", path, "")
		if out["verdict"] != want {
			t.Errorf("%s (%s) = %v, quero %s", name, client, out, want)
		}
	}
	check("www.tiktok.com", "", "blocked")
	check("x.ruim.com", "", "blocked")
	check("bom.ruim.com", "", "allowed")

	// Atalho do log ao vivo: liberar um domínio bloqueado.
	p.do(t, "POST", "/api/rules/quick", `{"domain":"ruim.com","action":"allow"}`)
	check("x.ruim.com", "", "allowed")

	// Por dispositivo: isolamento vence tudo.
	c := p.reg.Observe(netip.MustParseAddr("192.168.0.9"), time.Now())
	p.reg.Isolate(c, "refused", "teste", nil)
	check("github.com", "192.168.0.9", "isolated")

	// Listas pela interface.
	dir := t.TempDir()
	lista := filepath.Join(dir, "minha.txt")
	os.WriteFile(lista, []byte("0.0.0.0 rastreador.exemplo\n"), 0o644)
	r, out := p.do(t, "POST", "/api/lists", `{"name":"Minha","url":"`+lista+`"}`)
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("adicionar lista: %d %v", r.StatusCode, out)
	}
	if r, _ := p.do(t, "POST", "/api/lists", `{"url":"`+lista+`"}`); r.StatusCode != http.StatusConflict {
		t.Errorf("lista repetida: %d", r.StatusCode)
	}
	if r, _ := p.do(t, "POST", "/api/lists", `{"url":"ftp://x"}`); r.StatusCode != http.StatusBadRequest {
		t.Errorf("url inválida: %d", r.StatusCode)
	}
	waitVerdict := func(want string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for {
			_, out := p.do(t, "GET", "/api/filter/test?name=rastreador.exemplo", "")
			if out["verdict"] == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("rastreador.exemplo = %v, quero %s", out, want)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	waitVerdict("blocked")
	st := p.flt.Status()
	if len(st) != 1 || st[0].Rules != 1 || st[0].Fixed {
		t.Errorf("status = %+v", st)
	}
	id := int(st[0].ID)
	p.do(t, "PATCH", "/api/lists/"+itoa(id), `{"enabled":false}`)
	waitVerdict("allowed")
	if r, _ := p.do(t, "DELETE", "/api/lists/"+itoa(id), ""); r.StatusCode != 200 {
		t.Errorf("apagar: %d", r.StatusCode)
	}
	if r, _ := p.do(t, "DELETE", "/api/lists/"+itoa(id), ""); r.StatusCode != http.StatusNotFound {
		t.Errorf("apagar de novo: %d", r.StatusCode)
	}
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

func TestUIServing(t *testing.T) {
	p := newPanel(t)
	get := func(path string) (*http.Response, string) {
		resp, err := http.Get(p.ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
	r, body := get("/")
	if r.StatusCode != 200 || body != "<html>painel</html>" || r.Header.Get("Cache-Control") != "no-cache" {
		t.Errorf("/ = %d %q %s", r.StatusCode, body, r.Header.Get("Cache-Control"))
	}
	if r.Header.Get("Content-Security-Policy") == "" || r.Header.Get("X-Frame-Options") != "DENY" {
		t.Error("faltam cabeçalhos de segurança")
	}
	if r, _ := get("/dispositivos"); r.StatusCode != 200 {
		t.Errorf("rota do SPA: %d", r.StatusCode)
	}
	r, body = get("/assets/app-123.js")
	if body != "console.log(1)" || !strings.Contains(r.Header.Get("Cache-Control"), "immutable") {
		t.Errorf("asset: %q %s", body, r.Header.Get("Cache-Control"))
	}
	if r, _ := get("/api/nada"); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("/api/* não cai no painel: %d", r.StatusCode)
	}
}

func TestTOTPVectors(t *testing.T) {
	// RFC 6238, apêndice B (SHA-1), segredo ASCII "12345678901234567890".
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"} {
		got, err := totpAt(secret, unix/30)
		if err != nil || got != want {
			t.Errorf("t=%d: %s, quero %s", unix, got, want)
		}
	}
}

func TestMFALoginFlow(t *testing.T) {
	p := newPanel(t)
	login(t, p)
	_, out := p.do(t, "POST", "/api/auth/mfa/setup", "")
	secret, _ := out["secret"].(string)
	if secret == "" || !strings.HasPrefix(out["uri"].(string), "otpauth://totp/") {
		t.Fatalf("setup: %v", out)
	}
	if r, _ := p.do(t, "POST", "/api/auth/mfa/enable", `{"code":"000000"}`); r.StatusCode != http.StatusBadRequest {
		t.Errorf("código errado ligou o MFA: %d", r.StatusCode)
	}
	code, _ := totpAt(secret, time.Now().Unix()/30)
	if r, out := p.do(t, "POST", "/api/auth/mfa/enable", `{"code":"`+code+`"}`); r.StatusCode != 200 {
		t.Fatalf("ligar: %v", out)
	}
	if _, st := p.do(t, "GET", "/api/auth/state", ""); st["mfa"] != true {
		t.Error("estado deveria indicar MFA")
	}
	p.do(t, "POST", "/api/auth/logout", "")
	if r, _ := p.do(t, "POST", "/api/auth/login", `{"password":"senha-forte-1"}`); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("sem código: %d", r.StatusCode)
	}
	// O código usado para ligar não vale de novo (sem reuso); o do passo seguinte vale.
	if r, _ := p.do(t, "POST", "/api/auth/login", `{"password":"senha-forte-1","code":"`+code+`"}`); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("reuso do código: %d", r.StatusCode)
	}
	next, _ := totpAt(secret, time.Now().Unix()/30+1)
	if r, out := p.do(t, "POST", "/api/auth/login", `{"password":"senha-forte-1","code":"`+next+`"}`); r.StatusCode != 200 {
		t.Fatalf("login com MFA: %v", out)
	}
	// Desligar pelo painel exige senha e código.
	if r, _ := p.do(t, "POST", "/api/auth/mfa/disable", `{"password":"senha-forte-1","code":"`+next+`"}`); r.StatusCode != http.StatusForbidden {
		t.Errorf("desligar com código reusado: %d", r.StatusCode)
	}
	// Pelo token da API (recuperação), desliga sem código.
	req, _ := http.NewRequest("POST", p.ts.URL+"/api/auth/mfa/disable", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer segredo")
	req.Header.Set("Content-Type", "application/json")
	if r, err := http.DefaultClient.Do(req); err != nil || r.StatusCode != 200 {
		t.Errorf("mfa-off pelo token: %v", r.StatusCode)
	}
	if p.api.mfaEnabled() {
		t.Error("deveria estar desligado")
	}
}
