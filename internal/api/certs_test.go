// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/certs"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

func TestCertsAPI(t *testing.T) {
	var cm *certs.Manager
	p := newPanelWith(t, func(d *Deps) {
		// Diretório ACME inexistente: a emissão falha rápido, sem sair para a internet.
		cm = certs.New(certs.Options{Dir: t.TempDir(), DirectoryURL: "http://127.0.0.1:1/dir", HTTPAddr: "127.0.0.1:0"})
		d.Certs = cm
	})
	login(t, p)
	if r, out := p.do(t, "PUT", "/api/certs", `{"enabled":true,"domains":["heimdall.empresa.local"]}`); r.StatusCode != 400 || !strings.Contains(out["error"].(string), "não é um domínio público") {
		t.Errorf("domínio interno: %v", out)
	}
	body := `{"domains":["dns.exemplo.com.br"],"challenge":"dns-01-cloudflare","cloudflare_token":"cf-SEGREDO","auto_renew":true,"use_panel":true}`
	if r, out := p.do(t, "PUT", "/api/certs", body); r.StatusCode != 200 {
		t.Fatalf("salvar: %v", out)
	}
	raw := func() string {
		resp, err := p.client.Get(p.ts.URL + "/api/certs")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	if got := raw(); strings.Contains(got, "cf-SEGREDO") || !strings.Contains(got, secretMask) {
		t.Fatalf("token vazou: %s", got)
	}
	// Mandar de volta mascarado mantém o token.
	if r, _ := p.do(t, "PUT", "/api/certs", strings.Replace(body, "cf-SEGREDO", secretMask, 1)); r.StatusCode != 200 || cm.Settings().CloudflareToken != "cf-SEGREDO" {
		t.Error("token perdido")
	}
	if r, out := p.do(t, "POST", "/api/certs/issue", ""); r.StatusCode != 200 || out["settings"].(map[string]any)["enabled"] != true {
		t.Fatalf("emitir: %v", out)
	}
	for i := 0; cm.Running() && i < 100; i++ {
		time.Sleep(50 * time.Millisecond)
	}
	if st := cm.Status(); st.State != "error" || st.LastError == "" || len(st.Log) == 0 {
		t.Errorf("falha deveria aparecer no status: %+v", st)
	}
	if r, out := p.do(t, "POST", "/api/certs/disable", ""); r.StatusCode != 200 || out["settings"].(map[string]any)["enabled"] != false {
		t.Errorf("desligar: %v", out)
	}
	// Operador e leitor não chegam nem a ver.
	op := store.User{Username: "operador", Role: store.RoleOperator, Source: sourceLocal}
	op.PasswordHash, _ = hashPassword("senha-forte-3")
	p.api.Store.SaveUser(&op)
	o := asLocalhost(p)
	o.do(t, "POST", "/api/auth/login", map[string]string{"username": "operador", "password": "senha-forte-3"})
	if r, _ := o.do(t, "GET", "/api/certs", nil); r.StatusCode != http.StatusForbidden {
		t.Errorf("operador viu os certificados: %d", r.StatusCode)
	}
}
