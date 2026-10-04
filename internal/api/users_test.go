// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/ugoneiva/HeimdallDNS/internal/ad"
	"github.com/ugoneiva/HeimdallDNS/internal/console"
	"github.com/ugoneiva/HeimdallDNS/internal/querylog"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

// fresh devolve o mesmo painel com outro navegador (outra sessão).
func (p *panel) fresh() *panel {
	jar, _ := cookiejar.New(nil)
	cp := *p
	cp.client = &http.Client{Jar: jar}
	return &cp
}

func loginAs(t *testing.T, p *panel, user, pass string) *panel {
	t.Helper()
	s := p.fresh()
	if r, out := s.do(t, "POST", "/api/auth/login", fmt.Sprintf(`{"username":%q,"password":%q}`, user, pass)); r.StatusCode != 200 {
		t.Fatalf("login de %s: %d %v", user, r.StatusCode, out)
	}
	return s
}

func TestRolesAndUsers(t *testing.T) {
	p := newPanel(t)
	login(t, p) // admin
	for _, u := range []string{
		`{"username":"ana","role":"operator","password":"senha-da-ana"}`,
		`{"username":"beto","role":"viewer","password":"senha-do-beto","display":"Beto"}`,
	} {
		if r, out := p.do(t, "POST", "/api/users", u); r.StatusCode != http.StatusCreated {
			t.Fatalf("criar: %v", out)
		}
	}
	if r, _ := p.do(t, "POST", "/api/users", `{"username":"ANA","role":"viewer","password":"outra-senha"}`); r.StatusCode != 400 {
		t.Error("nome repetido (sem diferenciar maiúsculas) deveria falhar")
	}
	if r, _ := p.do(t, "POST", "/api/users", `{"username":"x","role":"chefe","password":"senha-longa-1"}`); r.StatusCode != 400 {
		t.Error("papel inválido")
	}
	c := p.reg.Observe(mustAddr("192.168.0.7"), time.Now())

	ana := loginAs(t, p, "ana", "senha-da-ana")
	beto := loginAs(t, p, "Beto", "senha-do-beto") // nome sem diferenciar maiúsculas

	cases := []struct {
		who          *panel
		name         string
		method, path string
		body         string
		want         int
	}{
		{ana, "operador isola", "POST", "/api/clients/" + c.ID() + "/isolate", `{"mode":"refused"}`, 200},
		{ana, "operador libera", "POST", "/api/clients/" + c.ID() + "/release", "", 200},
		{ana, "operador não mexe nas regras globais", "PUT", "/api/rules", `{"deny":["x.com"]}`, 403},
		{ana, "operador não vê usuários", "GET", "/api/users", "", 403},
		{ana, "operador lê o status", "GET", "/api/services", "", 200},
		{beto, "leitor lê os dispositivos", "GET", "/api/clients", "", 200},
		{beto, "leitor não isola", "POST", "/api/clients/" + c.ID() + "/isolate", `{}`, 403},
		{beto, "leitor não baixa backup", "POST", "/api/backup", `{}`, 403},
		{beto, "leitor troca a própria senha", "POST", "/api/auth/password", `{"current":"senha-do-beto","password":"nova-do-beto"}`, 204},
	}
	for _, tc := range cases {
		if r, out := tc.who.do(t, tc.method, tc.path, tc.body); r.StatusCode != tc.want {
			t.Errorf("%s: %d (quero %d) %v", tc.name, r.StatusCode, tc.want, out)
		}
	}
	// A auditoria registra o nome de quem fez.
	es, _ := p.api.Store.Audit(time.Now().Add(-time.Minute), 100)
	found := false
	for _, e := range es {
		if e.Actor == "ana" && strings.Contains(e.Action, "isolate") && e.OK {
			found = true
		}
	}
	if !found {
		t.Error("a auditoria deveria ter o isolamento feito pela ana")
	}
	denied := 0
	for _, e := range es {
		if e.Action == "auth.denied" && !e.OK {
			denied++
		}
	}
	if denied != 4 {
		t.Errorf("tentativas barradas na auditoria = %d (quero 4)", denied)
	}

	// Rebaixar a ana derruba a sessão dela.
	users := listUsers(t, p)
	if r, _ := p.do(t, "PATCH", fmt.Sprintf("/api/users/%d", users["ana"]), `{"role":"viewer"}`); r.StatusCode != 200 {
		t.Fatal("mudar papel")
	}
	if r, _ := ana.do(t, "GET", "/api/services", ""); r.StatusCode != 401 {
		t.Errorf("sessão de quem mudou de papel deveria cair: %d", r.StatusCode)
	}
	// Último administrador: não sai, não é desativado nem excluído.
	if r, _ := p.do(t, "PATCH", fmt.Sprintf("/api/users/%d", users["admin"]), `{"role":"viewer"}`); r.StatusCode != 400 {
		t.Error("rebaixar o último admin deveria falhar")
	}
	if r, _ := p.do(t, "PATCH", fmt.Sprintf("/api/users/%d", users["admin"]), `{"disabled":true}`); r.StatusCode != 400 {
		t.Error("desativar o último admin deveria falhar")
	}
	if r, _ := p.do(t, "DELETE", fmt.Sprintf("/api/users/%d", users["admin"]), ""); r.StatusCode != 400 {
		t.Error("excluir a si mesmo deveria falhar")
	}
	// Desativado não entra.
	p.do(t, "PATCH", fmt.Sprintf("/api/users/%d", users["beto"]), `{"disabled":true}`)
	if r, _ := p.fresh().do(t, "POST", "/api/auth/login", `{"username":"beto","password":"nova-do-beto"}`); r.StatusCode != 401 {
		t.Errorf("conta desativada entrou: %d", r.StatusCode)
	}
	// Usuário inexistente e senha errada dão a mesma resposta.
	_, a := p.fresh().do(t, "POST", "/api/auth/login", `{"username":"ninguem","password":"qualquer-1"}`)
	_, b := p.fresh().do(t, "POST", "/api/auth/login", `{"username":"admin","password":"errada-123"}`)
	if a["error"] != b["error"] {
		t.Errorf("mensagens diferentes revelam quem existe: %v / %v", a, b)
	}
}

func listUsers(t *testing.T, p *panel) map[string]int64 {
	t.Helper()
	req, _ := http.NewRequest("GET", p.ts.URL+"/api/users", nil)
	resp, err := p.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var us []userView
	if err := jsonDecodeBody(resp, &us); err != nil {
		t.Fatal(err)
	}
	out := map[string]int64{}
	for _, u := range us {
		out[u.Username] = u.ID
	}
	return out
}

func TestScopedTokens(t *testing.T) {
	p := newPanel(t)
	login(t, p)
	r, out := p.do(t, "POST", "/api/tokens", `{"name":"Grafana","role":"viewer","expires_days":30}`)
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("criar token: %v", out)
	}
	tok := out["token"].(string)
	if !strings.HasPrefix(tok, tokenPrefix) {
		t.Fatalf("token = %q", tok)
	}
	anon := p.fresh()
	if r, _ := anon.do(t, "GET", "/api/services", "", "Authorization", "Bearer "+tok); r.StatusCode != 200 {
		t.Errorf("leitura com token de leitor: %d", r.StatusCode)
	}
	if r, _ := anon.do(t, "PUT", "/api/rules", `{"deny":["x.com"]}`, "Authorization", "Bearer "+tok); r.StatusCode != 403 {
		t.Errorf("escrita com token de leitor: %d", r.StatusCode)
	}
	if r, _ := anon.do(t, "POST", "/api/auth/password", `{"password":"tomada-de-conta"}`, "Authorization", "Bearer "+tok); r.StatusCode != 403 {
		t.Errorf("token não pode trocar senha de ninguém: %d", r.StatusCode)
	}
	// A lista nunca mostra o hash, só o começo do token.
	_, lst := p.do(t, "GET", "/api/tokens", "")
	raw := fmt.Sprint(lst)
	if strings.Contains(raw, hashToken(tok)) {
		t.Error("o hash não pode sair na lista")
	}
	ts, _ := p.api.Store.Tokens()
	if len(ts) != 1 || ts[0].CreatedBy != "admin" || !strings.HasPrefix(tok, ts[0].Prefix) {
		t.Errorf("tokens = %+v", ts)
	}
	// Vencido não vale.
	old := timeNow
	timeNow = func() time.Time { return time.Now().Add(31 * 24 * time.Hour) }
	if r, _ := anon.do(t, "GET", "/api/services", "", "Authorization", "Bearer "+tok); r.StatusCode != 401 {
		t.Errorf("token vencido: %d", r.StatusCode)
	}
	timeNow = old
	// Revogado não vale.
	p.do(t, "DELETE", fmt.Sprintf("/api/tokens/%d", ts[0].ID), "")
	if r, _ := anon.do(t, "GET", "/api/services", "", "Authorization", "Bearer "+tok); r.StatusCode != 401 {
		t.Errorf("token revogado: %d", r.StatusCode)
	}
}

func TestLegacyPasswordMigrates(t *testing.T) {
	var hash string
	p := newPanelWith(t, func(d *Deps) {
		h, _ := bcrypt.GenerateFromPassword([]byte("senha-antiga-1"), bcrypt.MinCost)
		hash = string(h)
		d.Store.SetJSON(PasswordKey, hash)
		d.Store.SetJSON(MFAKey, store.MFA{})
	})
	if p.api.setupCode != "" {
		t.Error("instalação antiga não pode pedir o código de configuração de novo")
	}
	u, err := p.api.Store.UserByName("admin")
	if err != nil || u.Role != store.RoleAdmin || u.PasswordHash != hash {
		t.Fatalf("admin migrado = %+v %v", u, err)
	}
	if r, out := p.do(t, "POST", "/api/auth/login", `{"password":"senha-antiga-1"}`); r.StatusCode != 200 {
		t.Errorf("login com a senha antiga (sem usuário): %v", out)
	}
}

// TestADLogin roda contra o AD de laboratório (ver internal/ad).
func TestADLogin(t *testing.T) {
	url, pf := os.Getenv("HEIMDALL_AD_TEST_URL"), os.Getenv("HEIMDALL_AD_TEST_PASS_FILE")
	if url == "" || pf == "" {
		t.Skip("AD de laboratório não configurado")
	}
	pw, _ := os.ReadFile(pf)
	base := "DC=lab,DC=heimdall,DC=test"
	client, err := ad.New(ad.Options{URL: url, BindUser: "Administrator@lab.heimdall.test", BindPassword: strings.TrimSpace(string(pw)),
		InsecureTLS: true, Write: true, UserOUs: []string{"OU=Heimdall," + base}, ManagedGroups: []string{"VPN-Usuarios"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	_ = client.DeleteUser(ctx, "login.teste")
	if _, err := client.CreateUser(ctx, ad.NewUser{OU: "OU=Heimdall," + base, SAM: "login.teste", GivenName: "Login", Surname: "Teste",
		Password: "Senha-Lab-4321!", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.DeleteUser(t.Context(), "login.teste") })

	p := newPanelWith(t, func(d *Deps) {
		d.AD = client
		d.ADLogin = ADLogin{Enabled: true, AdminGroups: []string{"Domain Admins"}, OperatorGroups: []string{"VPN-Usuarios"}, RequireMFA: true}
	})
	login(t, p)

	// Sem grupo liberado: senha certa, mas não entra.
	if r, out := p.fresh().do(t, "POST", "/api/auth/login", `{"username":"login.teste","password":"Senha-Lab-4321!"}`); r.StatusCode != 401 ||
		!strings.Contains(out["error"].(string), "grupo") {
		t.Errorf("sem grupo: %d %v", r.StatusCode, out)
	}
	if _, err := client.SetMembership(ctx, "VPN-Usuarios", "login.teste", true); err != nil {
		t.Fatal(err)
	}
	if r, _ := p.fresh().do(t, "POST", "/api/auth/login", `{"username":"login.teste","password":"errada"}`); r.StatusCode != 401 {
		t.Error("senha errada no AD")
	}
	if r, _ := p.fresh().do(t, "POST", "/api/auth/login", `{"username":"login.teste","password":""}`); r.StatusCode != 401 {
		t.Error("senha vazia nunca pode entrar (bind anônimo)")
	}
	s := loginAs(t, p, `LAB\login.teste`, "Senha-Lab-4321!")
	_, st := s.do(t, "GET", "/api/auth/state", "")
	u := st["user"].(map[string]any)
	if st["role"] != "operator" || u["source"] != "ad" || u["mfa_required"] != true {
		t.Fatalf("estado = %v", st)
	}
	// Até cadastrar o MFA, só a própria conta.
	if r, _ := s.do(t, "GET", "/api/clients", ""); r.StatusCode != 403 {
		t.Errorf("sem MFA deveria ser barrado: %d", r.StatusCode)
	}
	_, out := s.do(t, "POST", "/api/auth/mfa/setup", "")
	code, _ := totpAt(out["secret"].(string), time.Now().Unix()/30)
	if r, out := s.do(t, "POST", "/api/auth/mfa/enable", `{"code":"`+code+`"}`); r.StatusCode != 200 {
		t.Fatalf("cadastrar MFA: %v", out)
	}
	if r, _ := s.do(t, "GET", "/api/clients", ""); r.StatusCode != 200 {
		t.Errorf("com MFA: %d", r.StatusCode)
	}
	// Uma conta local com o mesmo nome nunca é tomada pelo AD.
	p.do(t, "POST", "/api/users", `{"username":"Administrator","role":"viewer","password":"senha-local-1"}`)
	if r, _ := p.fresh().do(t, "POST", "/api/auth/login", fmt.Sprintf(`{"username":"Administrator","password":%q}`, strings.TrimSpace(string(pw)))); r.StatusCode != 401 {
		t.Error("a senha do AD não pode abrir uma conta local")
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func jsonDecodeBody(resp *http.Response, v any) error { return json.NewDecoder(resp.Body).Decode(v) }

func TestGroupsAPI(t *testing.T) {
	p := newPanel(t)
	login(t, p)
	body := `{"groups":[{"name":"Visitantes","deny":["service:social"],"schedules":[{"name":"sempre","start":"00:00","end":"00:00","deny":["apostas.com"]}]}]}`
	r, out := p.do(t, "PUT", "/api/groups", body)
	if r.StatusCode != 200 {
		t.Fatalf("salvar grupos: %v", out)
	}
	gs := p.reg.Groups()
	if len(gs) != 1 || gs[0].ID == "" {
		t.Fatalf("grupos = %+v", gs)
	}
	c := p.reg.Observe(mustAddr("192.168.0.44"), time.Now())
	if r, out := p.do(t, "PATCH", "/api/clients/"+c.ID(), `{"group":"nao-existe"}`); r.StatusCode != 400 {
		t.Errorf("grupo inexistente: %d %v", r.StatusCode, out)
	}
	if r, out := p.do(t, "PATCH", "/api/clients/"+c.ID(), `{"group":"`+gs[0].ID+`"}`); r.StatusCode != 200 {
		t.Fatalf("pôr no grupo: %v", out)
	}
	for name, rule := range map[string]string{"www.instagram.com": "grupo Visitantes", "apostas.com": "horário sempre"} {
		_, out := p.do(t, "GET", "/api/filter/test?name="+name+"&client=192.168.0.44", "")
		if out["verdict"] != "blocked" || !strings.Contains(fmt.Sprint(out["rule"]), rule) {
			t.Errorf("%s = %v", name, out)
		}
	}
	if r, _ := p.do(t, "PUT", "/api/groups", `{"groups":[{"name":"X","schedules":[{"name":"y","start":"99:00","end":"07:00","block_all":true}]}]}`); r.StatusCode != 400 {
		t.Error("horário inválido deveria falhar")
	}
}

func TestConsoleTemplates(t *testing.T) {
	// Dois clientes (HeimdallDNS de verdade, em memória).
	var tenants []*panel
	for range 2 {
		tp := newPanelWith(t, withDNS(t))
		login(t, tp)
		tenants = append(tenants, tp)
	}
	// Um já tem a lista e uma regra própria, que precisam continuar.
	tenants[1].do(t, "PUT", "/api/rules", `{"deny":["so-deste-cliente.com"]}`)

	st, _ := store.Open(t.TempDir() + "/console.db")
	t.Cleanup(func() { st.Close() })
	con, err := console.New(console.Options{Store: st})
	if err != nil {
		t.Fatal(err)
	}
	c := newPanelWith(t, func(d *Deps) { d.Console = con })
	login(t, c)
	var ids []string
	for i, tp := range tenants {
		r, out := c.do(t, "POST", "/api/console/tenants", fmt.Sprintf(`{"name":"Cliente %d","url":%q,"token":"segredo"}`, i, tp.ts.URL))
		if r.StatusCode != http.StatusCreated {
			t.Fatalf("cadastrar cliente: %v", out)
		}
		ids = append(ids, out["id"].(string))
	}
	tpl := `{"templates":[{"name":"Padrão Escritório","deny":["service:jogos","apostas.com"],
		"groups":[{"name":"Visitantes","deny":["service:social"]}]}]}`
	r, _ := c.do(t, "PUT", "/api/console/templates", tpl)
	if r.StatusCode != 200 {
		t.Fatal("salvar modelo")
	}
	req, _ := http.NewRequest("GET", c.ts.URL+"/api/console/templates", nil)
	resp, _ := c.client.Do(req)
	var tpls []console.Template
	jsonDecodeBody(resp, &tpls)
	resp.Body.Close()
	if len(tpls) != 1 || tpls[0].ID == "" {
		t.Fatalf("modelos = %+v", tpls)
	}

	body := fmt.Sprintf(`{"tenants":[%q,%q]}`, ids[0], ids[1])
	req, _ = http.NewRequest("POST", c.ts.URL+"/api/console/templates/"+tpls[0].ID+"/apply", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", c.ts.URL)
	resp, err = c.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var res []console.ApplyResult
	jsonDecodeBody(resp, &res)
	resp.Body.Close()
	if len(res) != 2 || !res[0].OK || !res[1].OK {
		t.Fatalf("aplicar = %+v", res)
	}
	for i, tp := range tenants {
		_, _, _, d := tp.flt.UserRules()
		if !slices.Contains(d, "apostas.com") || !slices.Contains(d, "service:jogos") {
			t.Errorf("cliente %d: regras = %v", i, d)
		}
		if gs := tp.reg.Groups(); len(gs) != 1 || gs[0].Name != "Visitantes" {
			t.Errorf("cliente %d: grupos = %+v", i, gs)
		}
	}
	if _, _, _, d := tenants[1].flt.UserRules(); !slices.Contains(d, "so-deste-cliente.com") {
		t.Error("a regra própria do cliente não pode sumir")
	}
	// Aplicar de novo não duplica nada (só atualiza o grupo pelo nome).
	resp, _ = c.client.Do(func() *http.Request {
		r, _ := http.NewRequest("POST", c.ts.URL+"/api/console/templates/"+tpls[0].ID+"/apply", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", c.ts.URL)
		return r
	}())
	resp.Body.Close()
	if gs := tenants[0].reg.Groups(); len(gs) != 1 {
		t.Errorf("grupo duplicado: %+v", gs)
	}
}

func TestTopologyAPI(t *testing.T) {
	p := newPanelWith(t, withDNS(t))
	login(t, p)
	c := p.reg.Observe(mustAddr("192.168.0.61"), time.Now())
	now := time.Now()
	var es []querylog.Entry
	for i, n := range []string{"www.youtube.com", "www.youtube.com", "i.ytimg.com", "ads.rastreio.net"} {
		st := "forwarded"
		if i == 3 {
			st = "blocked"
		}
		es = append(es, querylog.Entry{Time: now, ClientIP: "192.168.0.61", ClientID: c.ID(), Name: n, Type: "A", Status: st, Rcode: "NOERROR"})
	}
	if err := p.api.Store.InsertQueries(es); err != nil {
		t.Fatal(err)
	}
	if r, out := p.do(t, "PATCH", "/api/clients/"+c.ID(), `{"kind":"geladeira"}`); r.StatusCode != 400 {
		t.Errorf("tipo inválido: %d %v", r.StatusCode, out)
	}
	p.do(t, "PATCH", "/api/clients/"+c.ID(), `{"kind":"tv"}`)
	r, out := p.do(t, "GET", "/api/topology?range=1h", "")
	if r.StatusCode != 200 {
		t.Fatalf("topologia: %v", out)
	}
	m := out["map"].(map[string]any)
	devs := m["devices"].([]any)
	d := devs[0].(map[string]any)
	if d["kind"] != "tv" || d["kind_auto"] != false || d["queries"] != 4.0 || d["blocked"] != 1.0 {
		t.Errorf("aparelho = %v", d)
	}
	ids := map[string]float64{}
	for _, x := range m["destinations"].([]any) {
		dd := x.(map[string]any)
		ids[dd["id"].(string)] = dd["queries"].(float64)
	}
	if ids["youtube"] != 3 || ids["bloqueados"] != 1 {
		t.Errorf("destinos = %v", ids)
	}
}
