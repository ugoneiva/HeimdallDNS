// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/ad"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

type auditSink struct{ got []store.AuditEntry }

func (a *auditSink) Audit(e store.AuditEntry) { a.got = append(a.got, e) }

// TestADWriteGuardsAndAudit roda contra o AD de laboratório (ver internal/ad).
func TestADWriteGuardsAndAudit(t *testing.T) {
	url, pf := os.Getenv("HEIMDALL_AD_TEST_URL"), os.Getenv("HEIMDALL_AD_TEST_PASS_FILE")
	if url == "" || pf == "" {
		t.Skip("AD de laboratório não configurado")
	}
	pw, _ := os.ReadFile(pf)
	base := "DC=lab,DC=heimdall,DC=test"
	client, err := ad.New(ad.Options{URL: url, BindUser: "Administrator@lab.heimdall.test", BindPassword: strings.TrimSpace(string(pw)),
		InsecureTLS: true, Write: true, UserOUs: []string{"OU=Heimdall," + base}})
	if err != nil {
		t.Fatal(err)
	}
	sink := &auditSink{}
	p := newPanelWith(t, func(d *Deps) { d.AD, d.Audit = client, sink })
	login(t, p)
	_ = client.DeleteUser(t.Context(), "api.heimdall")

	body := `{"ou":"OU=Heimdall,` + base + `","sam":"api.heimdall","given_name":"Api","surname":"Teste","password":"Senha-Forte-789!","enabled":true}`
	if r, out := p.do(t, "POST", "/api/ad/users", body); r.StatusCode != http.StatusForbidden || !strings.Contains(out["error"].(string), "duas etapas") {
		t.Fatalf("sem MFA deveria recusar: %d %v", r.StatusCode, out)
	}
	// Liga o MFA.
	_, out := p.do(t, "POST", "/api/auth/mfa/setup", "")
	code, _ := totpAt(out["secret"].(string), time.Now().Unix()/30)
	p.do(t, "POST", "/api/auth/mfa/enable", `{"code":"`+code+`"}`)

	if r, out := p.do(t, "POST", "/api/ad/users", body); r.StatusCode != 200 || out["sam"] != "api.heimdall" {
		t.Fatalf("criar com MFA: %d %v", r.StatusCode, out)
	}
	if r, _ := p.do(t, "POST", "/api/ad/users/Administrator/password", `{"password":"X-123456789!"}`); r.StatusCode != http.StatusBadRequest {
		t.Errorf("Administrator deveria ser recusado: %d", r.StatusCode)
	}
	if r, _ := p.do(t, "DELETE", "/api/ad/users/api.heimdall", ""); r.StatusCode != http.StatusNoContent {
		t.Errorf("excluir: %d", r.StatusCode)
	}

	all, _ := p.api.Store.Audit(time.Now().Add(-time.Hour), 50)
	var es []store.AuditEntry
	for _, e := range all {
		if strings.HasPrefix(e.Action, "ad.") {
			es = append(es, e)
		}
	}
	if len(es) != 3 || len(sink.got) != len(all) {
		t.Fatalf("auditoria do AD = %d (quero 3); exportadas %d de %d", len(es), len(sink.got), len(all))
	}
	raw, _ := json.Marshal(es)
	if strings.Contains(string(raw), "Senha-Forte-789!") || strings.Contains(string(raw), "X-123456789!") {
		t.Error("a senha nunca pode ir para a auditoria")
	}
	byAction := map[string]store.AuditEntry{}
	for _, e := range es {
		byAction[e.Action] = e
	}
	if e := byAction["ad.user.create"]; !e.OK || e.Target != "api.heimdall" || e.Actor != "admin" {
		t.Errorf("auditoria da criação = %+v", e)
	}
	if e := byAction["ad.user.password"]; e.OK || e.Target != "Administrator" || e.Error == "" {
		t.Errorf("auditoria da recusa = %+v", e)
	}
}
