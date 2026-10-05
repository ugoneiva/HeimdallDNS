// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"bytes"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/report"
)

func TestReportsAPI(t *testing.T) {
	var sent []string
	var rs *report.Scheduler
	p := newPanelWith(t, func(d *Deps) {
		rs = report.NewScheduler(report.Options{
			Source:  report.Source{Store: d.Store, Node: "teste"},
			Dir:     t.TempDir(),
			Deliver: func(_ *report.Data, _ []byte, name string) { sent = append(sent, name) },
		})
		d.Reports = rs
	})
	login(t, p)
	req, _ := http.NewRequest("GET", p.ts.URL+"/api/reports/generate?days=3&today=1", nil)
	resp, err := p.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	pdf, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.HasPrefix(pdf, []byte("%PDF-")) || resp.Header.Get("Content-Type") != "application/pdf" {
		t.Fatalf("gerar: %d %q", resp.StatusCode, pdf[:min(len(pdf), 40)])
	}
	_, out := p.do(t, "GET", "/api/reports", "")
	list := out["reports"].([]any)
	if len(list) != 1 {
		t.Fatalf("lista = %v", out)
	}
	name := list[0].(map[string]any)["name"].(string)
	if r, _ := p.do(t, "GET", "/api/reports/file/"+name, ""); r.StatusCode != 200 {
		t.Error("baixar o guardado")
	}
	if r, _ := p.do(t, "GET", "/api/reports/file/..%2F..%2Fh.db", ""); r.StatusCode != http.StatusNotFound {
		t.Error("nome fora do padrão")
	}
	if r, out := p.do(t, "PUT", "/api/reports/settings", `{"enabled":true,"frequency":"monthly","hour":8}`); r.StatusCode != 200 || out["settings"].(map[string]any)["frequency"] != "monthly" {
		t.Fatalf("configurar: %v", out)
	}
	if r, _ := p.do(t, "PUT", "/api/reports/settings", `{"frequency":"daily"}`); r.StatusCode != 400 {
		t.Error("frequência inválida")
	}
	if r, out := p.do(t, "POST", "/api/reports/send", ""); r.StatusCode != 200 || len(sent) != 1 {
		t.Fatalf("enviar agora: %v %v", out, sent)
	}
	from, _ := report.Period(report.FreqMonthly, time.Now())
	if want := "heimdalldns-relatorio-" + from.Format("2006-01-02"); len(sent[0]) < len(want) || sent[0][:len(want)] != want {
		t.Errorf("enviado = %s", sent[0])
	}
}
