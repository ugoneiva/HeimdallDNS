// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/cache"
	"github.com/ugoneiva/HeimdallDNS/internal/forward"
	"github.com/ugoneiva/HeimdallDNS/internal/server"
	"github.com/ugoneiva/HeimdallDNS/internal/upstream"
)

func withDNS(t *testing.T) func(*Deps) {
	return func(d *Deps) {
		ups, err := upstream.New(upstream.Options{Servers: []string{"127.0.0.1:5399"}, Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ups.Close() })
		d.Upstream = ups
		d.Cache = cache.New(cache.Options{Size: 10})
		d.Server = server.New(server.Options{Cache: d.Cache, Upstream: ups})
		d.UpstreamConfig = upstream.Options{Servers: []string{"127.0.0.1:5399"}}
		d.DataDir = t.TempDir()
		d.BackupDir = filepath.Join(d.DataDir, "backups")
		d.BackupKeep = 3
	}
}

func TestLocalRecordsAndUpstream(t *testing.T) {
	p := newPanelWith(t, withDNS(t))
	login(t, p)
	body := `{"records":[{"name":"NAS.casa.","type":"a","value":"192.168.0.10"},{"name":"fotos.casa","type":"CNAME","value":"nas.casa"}]}`
	if r, out := p.do(t, "PUT", "/api/dns/local", body); r.StatusCode != 200 {
		t.Fatalf("salvar: %v", out)
	}
	for _, bad := range []string{
		`{"records":[{"name":"x.casa","type":"A","value":"fd00::1"}]}`,
		`{"records":[{"name":"a.casa","type":"CNAME","value":"b.casa"},{"name":"b.casa","type":"CNAME","value":"a.casa"}]}`,
		`{"records":[{"name":"a.casa","type":"CNAME","value":"b.casa"},{"name":"a.casa","type":"A","value":"10.0.0.1"}]}`,
		`{"records":[{"name":"*.casa","type":"A","value":"10.0.0.1"}]}`,
	} {
		if r, _ := p.do(t, "PUT", "/api/dns/local", bad); r.StatusCode != 400 {
			t.Errorf("deveria recusar %s", bad)
		}
	}
	_, out := p.do(t, "GET", "/api/dns/local", "")
	if recs := out["records"].([]any); len(recs) != 2 || recs[0].(map[string]any)["name"] != "nas.casa" {
		t.Errorf("registros = %v", out["records"])
	}

	if r, out := p.do(t, "PUT", "/api/dns/upstream", `{"servers":["https://dns.quad9.net/dns-query","tls://1.1.1.1"],"mode":"failover"}`); r.StatusCode != 200 || out["custom"] != true {
		t.Fatalf("upstream: %v", out)
	}
	if s, m := p.api.Upstream.Config(); len(s) != 2 || m != "failover" {
		t.Errorf("em uso: %v %s", s, m)
	}
	if r, _ := p.do(t, "PUT", "/api/dns/upstream", `{"servers":["ftp://x"]}`); r.StatusCode != 400 {
		t.Error("upstream inválido deveria falhar")
	}
	if r, out := p.do(t, "DELETE", "/api/dns/upstream", ""); r.StatusCode != 200 || out["custom"] != false {
		t.Errorf("voltar ao arquivo: %v", out)
	}
	es, _ := p.api.Store.Audit(time.Now().Add(-time.Minute), 50)
	var named, refused int
	for _, e := range es {
		switch {
		case strings.HasPrefix(e.Action, "dns.") && e.OK:
			named++
		case !e.OK && e.Actor == "admin":
			refused++ // as tentativas inválidas também ficam registradas
		}
	}
	if named != 3 || refused != 5 {
		t.Errorf("auditoria: %d alterações de DNS (quero 3), %d recusas (quero 5)", named, refused)
	}
}

func upload(t *testing.T, p *panel, path string, fields map[string]string, file []byte) (*http.Response, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		mw.WriteField(k, v)
	}
	fw, _ := mw.CreateFormFile("file", "arquivo")
	fw.Write(file)
	mw.Close()
	req, _ := http.NewRequest("POST", p.ts.URL+path, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Origin", p.ts.URL)
	resp, err := p.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	json.Unmarshal(raw, &out)
	return resp, out
}

func TestImportPihole(t *testing.T) {
	p := newPanelWith(t, withDNS(t))
	login(t, p)
	files := map[string]string{
		"adlist.json":                 `[{"address":"https://lista.exemplo/a.txt","enabled":1,"comment":"Lista A"}]`,
		"blacklist.exact.json":        `[{"domain":"ruim.com","enabled":1}]`,
		"custom.list":                 "10.0.0.2 router.lan\n",
		"05-pihole-custom-cname.conf": "cname=www.lan,router.lan\ncname=router.lan,outro.lan\n",
		"04-pihole-static-dhcp.conf":  "dhcp-host=aa:bb:cc:00:00:01,10.0.0.9,tv\n",
		"setupVars.conf":              "PIHOLE_DNS_1=9.9.9.9\n",
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for n, c := range files {
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(c)), Typeflag: tar.TypeReg})
		tw.Write([]byte(c))
	}
	tw.Close()
	gz.Close()

	r, out := upload(t, p, "/api/import/pihole", nil, buf.Bytes())
	if r.StatusCode != 200 {
		t.Fatalf("prévia: %v", out)
	}
	plan := out["plan"].(map[string]any)
	if plan["lists"] != 1.0 || plan["deny"] != 1.0 || plan["hosts"] != 3.0 || plan["reservations"] != 1.0 {
		t.Errorf("plano = %v", plan)
	}
	id := out["id"].(string)
	r, out = p.do(t, "POST", "/api/import/pihole/"+id+"/apply",
		`{"lists":true,"rules":true,"hosts":true,"reservations":true,"upstreams":true}`)
	if r.StatusCode != 200 {
		t.Fatalf("aplicar: %v", out)
	}
	res := out["result"].(map[string]any)
	// router.lan já tem IP, então o CNAME router.lan → outro.lan é recusado.
	if res["lists"] != 1.0 || res["rules"] != 1.0 || res["hosts"] != 2.0 || res["reservations"] != 1.0 || res["upstreams"] != 1.0 {
		t.Errorf("resultado = %v (notas %v)", res, out["notes"])
	}
	if rs, _ := p.api.Store.DHCPReservations(); len(rs) != 1 || rs[0].Name != "tv" {
		t.Errorf("reservas = %+v", rs)
	}
	if r, _ := p.do(t, "POST", "/api/import/pihole/"+id+"/apply", `{"lists":true}`); r.StatusCode != 404 {
		t.Error("a prévia só pode ser aplicada uma vez")
	}
}

func TestBackupAPI(t *testing.T) {
	restarted := make(chan struct{}, 1)
	p := newPanelWith(t, func(d *Deps) {
		withDNS(t)(d)
		d.Restart = func() { restarted <- struct{}{} }
	})
	login(t, p)
	p.do(t, "PUT", "/api/dns/local", `{"records":[{"name":"nas.casa","type":"A","value":"192.168.0.10"}]}`)

	if r, _ := p.do(t, "POST", "/api/backup", `{"passphrase":"curta"}`); r.StatusCode != 400 {
		t.Error("senha curta deveria falhar")
	}
	req, _ := http.NewRequest("POST", p.ts.URL+"/api/backup", bytes.NewReader([]byte(`{"passphrase":"senha-de-backup-longa"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", p.ts.URL)
	resp, err := p.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	arq, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.HasPrefix(arq, []byte("age-encryption.org/v1")) {
		t.Fatalf("download: %d %q", resp.StatusCode, arq[:min(40, len(arq))])
	}

	if r, out := upload(t, p, "/api/restore", nil, arq); r.StatusCode != 401 {
		t.Errorf("sem senha deveria pedir senha: %d %v", r.StatusCode, out)
	}
	if r, out := upload(t, p, "/api/restore", map[string]string{"passphrase": "senha-de-backup-longa"}, arq); r.StatusCode != 200 || out["pending"] == nil {
		t.Fatalf("restaurar: %d %v", r.StatusCode, out)
	}
	if _, out := p.do(t, "GET", "/api/restore", ""); out["pending"] == nil || out["can_restart"] != true {
		t.Errorf("estado = %v", out)
	}
	if r, _ := p.do(t, "POST", "/api/restart", ""); r.StatusCode != 202 {
		t.Error("reiniciar")
	}
	select {
	case <-restarted:
	case <-time.After(2 * time.Second):
		t.Error("o reinício não foi chamado")
	}
	if r, _ := p.do(t, "DELETE", "/api/restore", ""); r.StatusCode != 204 {
		t.Error("cancelar")
	}
	if _, err := os.Stat(filepath.Join(p.api.DataDir, "restaurar")); !os.IsNotExist(err) {
		t.Error("a pendência deveria sumir")
	}

	if r, out := p.do(t, "POST", "/api/backups", ""); r.StatusCode != 200 || len(out["files"].([]any)) != 1 {
		t.Fatalf("cópia agora: %v", out)
	}
	if r, _ := p.do(t, "GET", "/api/backups/..%2Fheimdall.db", ""); r.StatusCode != 400 {
		t.Error("nome com caminho deveria ser recusado")
	}
}

func TestConditionalForwardAPI(t *testing.T) {
	dnsDeps := withDNS(t)
	p := newPanelWith(t, func(d *Deps) {
		dnsDeps(d)
		fw, err := forward.NewManager([]forward.Rule{{Domain: "arquivo.local", Servers: []string{"10.0.0.1"}}}, time.Second, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(fw.Close)
		d.Forward = fw
	})
	login(t, p)
	_, out := p.do(t, "GET", "/api/dns/forward", "")
	if len(out["rules"].([]any)) != 0 || len(out["config"].([]any)) != 1 || out["private_reverse"] != "upstream" { // o upstream de teste é 127.0.0.1
		t.Fatalf("inicial = %v", out)
	}
	body := `{"rules":[{"domain":"Empresa.Local","servers":["10.0.0.10"," 10.0.0.11:53 "],"comment":"AD"},{"network":"192.168.1.7/24","servers":["192.168.1.1"]}]}`
	r, out := p.do(t, "PUT", "/api/dns/forward", body)
	if r.StatusCode != 200 {
		t.Fatalf("salvar: %v", out)
	}
	rules := out["rules"].([]any)
	if len(rules) != 2 || rules[0].(map[string]any)["domain"] != "empresa.local" || rules[1].(map[string]any)["network"] != "192.168.1.0/24" {
		t.Errorf("normalizadas = %v", rules)
	}
	if _, l, ok := p.api.Forward.Match("dc.empresa.local."); !ok || l != "empresa.local" {
		t.Error("regra não aplicada")
	}
	for _, bad := range []string{
		`{"rules":[{"domain":"a.local","servers":[]}]}`,
		`{"rules":[{"domain":"a.local","servers":["dc01.a.local"]}]}`,
		`{"rules":[{"network":"10.0.0.0/4","servers":["10.0.0.1"]}]}`,
	} {
		if r, _ := p.do(t, "PUT", "/api/dns/forward", bad); r.StatusCode != 400 {
			t.Errorf("deveria recusar %s", bad)
		}
	}
	if _, _, ok := p.api.Forward.Match("dc.empresa.local."); !ok {
		t.Error("regra inválida não pode derrubar as que valem")
	}
}
