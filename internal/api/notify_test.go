// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ugoneiva/HeimdallDNS/internal/notify"
)

func TestNotifyAPI(t *testing.T) {
	var hits atomic.Int32
	var lastSig atomic.Value
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		hits.Add(1)
		lastSig.Store(r.Header.Get("X-Heimdall-Signature"))
	}))
	defer hook.Close()
	nt := notify.New(notify.Options{})
	p := newPanelWith(t, func(d *Deps) { d.Notify = nt })
	login(t, p)
	body := `{"channels":[
		{"id":"t1","name":"Telegram","type":"telegram","enabled":true,"bot_token":"123:SEGREDO","chat_id":"-1"},
		{"id":"w1","name":"SOAR","type":"webhook","enabled":true,"url":"` + hook.URL + `","secret":"hmac-secreto","events":["security"],"min_severity":"high"}
	]}`
	r, out := p.do(t, "PUT", "/api/notify", body)
	if r.StatusCode != 200 {
		t.Fatalf("salvar: %v", out)
	}
	raw := func() string {
		req, _ := http.NewRequest("GET", p.ts.URL+"/api/notify", nil)
		resp, err := p.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	if got := raw(); strings.Contains(got, "SEGREDO") || strings.Contains(got, "hmac-secreto") || !strings.Contains(got, secretMask) {
		t.Fatalf("segredos vazaram: %s", got)
	}
	// Salvar de novo com a máscara mantém os segredos.
	body2 := strings.ReplaceAll(strings.ReplaceAll(body, "123:SEGREDO", secretMask), "hmac-secreto", secretMask)
	if r, out := p.do(t, "PUT", "/api/notify", body2); r.StatusCode != 200 {
		t.Fatalf("salvar com máscara: %v", out)
	}
	if s := nt.Settings(); s.Channels[0].BotToken != "123:SEGREDO" || s.Channels[1].Secret != "hmac-secreto" {
		t.Errorf("segredos perdidos: %+v", s.Channels)
	}
	if r, out := p.do(t, "POST", "/api/notify/test/w1", ""); r.StatusCode != 200 || hits.Load() != 1 {
		t.Fatalf("teste: %v (%d)", out, hits.Load())
	}
	if sig, _ := lastSig.Load().(string); !strings.HasPrefix(sig, "sha256=") {
		t.Errorf("assinatura = %q", sig)
	}
	if r, _ := p.do(t, "POST", "/api/notify/test/nada", ""); r.StatusCode != http.StatusBadGateway {
		t.Error("canal inexistente")
	}
	if r, _ := p.do(t, "PUT", "/api/notify", `{"channels":[{"id":"x","name":"E","type":"email","enabled":true,"to":["a@b.com"]}]}`); r.StatusCode != 400 {
		t.Error("e-mail sem SMTP deveria falhar")
	}
	if _, st := p.do(t, "GET", "/api/notify", ""); len(st["history"].([]any)) != 1 {
		t.Errorf("histórico = %v", st["history"])
	}
}
