// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package notify

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type capture struct {
	mu   sync.Mutex
	reqs []*http.Request
	body [][]byte
}

func (c *capture) server(t *testing.T, status int) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.reqs, c.body = append(c.reqs, r), append(c.body, b)
		c.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(s.Close)
	return s
}

func (c *capture) n() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.reqs)
}

func TestValidate(t *testing.T) {
	for _, bad := range []Settings{
		{Channels: []Channel{{ID: "a", Name: "T", Type: TypeTelegram}}},
		{Channels: []Channel{{ID: "a", Name: "W", Type: TypeWebhook, URL: "ftp://x"}}},
		{Channels: []Channel{{ID: "a", Name: "E", Type: TypeEmail, To: []string{"x@y.com"}, Enabled: true}}}, // sem SMTP
		{Channels: []Channel{{ID: "a", Name: "E", Type: TypeEmail, To: []string{"não é e-mail"}}}},
		{Channels: []Channel{{ID: "a", Name: "W", Type: TypeWebhook, URL: "https://x", Events: []string{"nada"}}}},
		{Channels: []Channel{{ID: "a", Name: "W", Type: TypeWebhook, URL: "https://x"}, {ID: "a", Name: "Z", Type: TypeWebhook, URL: "https://x"}}},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("deveria recusar %+v", bad.Channels)
		}
	}
	ok := Settings{
		Channels: []Channel{{ID: "a", Name: "E", Type: TypeEmail, To: []string{"soc@exemplo.com"}, Enabled: true}},
		SMTP:     SMTP{Host: "smtp.exemplo.com", From: "dns@exemplo.com"},
	}
	if err := ok.Validate(); err != nil || ok.SMTP.Port != 587 || ok.SMTP.Security != "starttls" || ok.Channels[0].MinSeverity != SevMedium {
		t.Errorf("padrões = %+v %v", ok, err)
	}
}

func TestWants(t *testing.T) {
	c := Channel{Enabled: true, MinSeverity: SevHigh, Events: []string{EventSecurity}}
	for _, tc := range []struct {
		e    Event
		want bool
	}{
		{Event{Type: EventSecurity, Severity: SevCritical}, true},
		{Event{Type: EventSecurity, Severity: SevMedium}, false},
		{Event{Type: EventUpstream, Severity: SevCritical}, false}, // tipo não escolhido
		{Event{Type: EventSecurity, Severity: SevLow}, false},
		{Event{Type: EventTest}, true},
	} {
		if c.Wants(tc.e) != tc.want {
			t.Errorf("%+v = %v", tc.e, !tc.want)
		}
	}
	c.Enabled = false
	if c.Wants(Event{Type: EventSecurity, Severity: SevCritical}) {
		t.Error("canal desligado")
	}
}

func TestDeliveryAndDedup(t *testing.T) {
	var tg, teams, hook capture
	tgSrv, teamsSrv, hookSrv := tg.server(t, 200), teams.server(t, 202), hook.server(t, 200)
	m := New(Options{Node: "dns1", TelegramAPI: tgSrv.URL, Dedup: time.Minute})
	err := m.SetSettings(Settings{PanelURL: "https://heimdall.exemplo", Channels: []Channel{
		{ID: "tg", Name: "Telegram", Type: TypeTelegram, Enabled: true, BotToken: "123:ABCsecreto", ChatID: "-100"},
		{ID: "teams", Name: "Teams", Type: TypeTeams, Enabled: true, URL: teamsSrv.URL, MinSeverity: SevHigh},
		{ID: "hook", Name: "SOAR", Type: TypeWebhook, Enabled: true, URL: hookSrv.URL, Secret: "s3gredo", MinSeverity: SevLow},
	}})
	if err != nil {
		t.Fatal(err)
	}
	e := Event{Type: EventSecurity, Severity: SevMedium, Title: "Malware <bloqueado>", Text: "x", Key: "threat|pc1|ruim.com",
		Fields: [][2]string{{"Dispositivo", "pc1"}, {"Domínio", "ruim.com"}}, Time: time.Now()}
	m.dispatch(t.Context(), e, "")
	if tg.n() != 1 || teams.n() != 0 || hook.n() != 1 {
		t.Fatalf("envios: telegram=%d teams=%d webhook=%d", tg.n(), teams.n(), hook.n())
	}
	if !strings.Contains(tg.reqs[0].URL.Path, "/bot123:ABCsecreto/sendMessage") || !strings.Contains(string(tg.body[0]), "Malware \\u0026lt;bloqueado\\u0026gt;") {
		t.Errorf("telegram: %s %s", tg.reqs[0].URL.Path, tg.body[0])
	}
	// Assinatura do webhook confere.
	r := hook.reqs[0]
	if r.Header.Get("X-Heimdall-Signature") != Sign("s3gredo", r.Header.Get("X-Heimdall-Timestamp"), hook.body[0]) {
		t.Error("assinatura do webhook")
	}
	var p WebhookPayload
	json.Unmarshal(hook.body[0], &p)
	if p.Fields["Domínio"] != "ruim.com" || p.Node != "dns1" || p.Link != "https://heimdall.exemplo" {
		t.Errorf("payload = %+v", p)
	}

	// Repetição dentro da janela: nada sai; depois da janela, sai com a contagem.
	m.dispatch(t.Context(), e, "")
	m.dispatch(t.Context(), e, "")
	if tg.n() != 1 {
		t.Fatal("repetição deveria ser juntada")
	}
	e.Time = e.Time.Add(2 * time.Minute)
	m.dispatch(t.Context(), e, "")
	if tg.n() != 2 || !strings.Contains(string(tg.body[1]), "+2 repetições") {
		t.Errorf("depois da janela: %d %s", tg.n(), tg.body[len(tg.body)-1])
	}

	// Crítico chega no Teams.
	m.dispatch(t.Context(), Event{Type: EventSecurity, Severity: SevCritical, Title: "Túnel DNS", Time: time.Now(), Fields: [][2]string{{"a", "b"}}}, "")
	if teams.n() != 1 || !strings.Contains(string(teams.body[0]), "AdaptiveCard") || !strings.Contains(string(teams.body[0]), "Abrir o painel") {
		t.Errorf("teams: %d %s", teams.n(), teams.body)
	}

	// Falha: o erro aparece no histórico sem o token.
	bad := capture{}
	badSrv := bad.server(t, 401)
	m2 := New(Options{TelegramAPI: badSrv.URL})
	m2.SetSettings(Settings{Channels: []Channel{{ID: "tg", Name: "T", Type: TypeTelegram, BotToken: "999:SEGREDO", ChatID: "1"}}})
	err = m2.Test(t.Context(), "tg")
	if err == nil || strings.Contains(err.Error(), "SEGREDO") {
		t.Errorf("teste com falha: %v", err)
	}
	if h := m2.History(); len(h) != 1 || h[0].OK {
		t.Errorf("histórico = %+v", h)
	}
}

// smtpServer é um SMTP mínimo, sem TLS, que guarda a mensagem.
func smtpServer(t *testing.T) (host string, port int, got chan string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got = make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		say := func(s string) { c.Write([]byte(s + "\r\n")) }
		say("220 teste")
		var data strings.Builder
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if inData {
				if line == ".\r\n" {
					inData = false
					got <- data.String()
					say("250 ok")
					continue
				}
				data.WriteString(line)
				continue
			}
			switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				say("250 teste")
			case cmd == "DATA":
				inData = true
				say("354 vai")
			case cmd == "QUIT":
				say("221 tchau")
				return
			default:
				say("250 ok")
			}
		}
	}()
	a := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", a.Port, got
}

func TestEmail(t *testing.T) {
	host, port, got := smtpServer(t)
	m := New(Options{Node: "dns1"})
	err := m.SetSettings(Settings{
		SMTP:     SMTP{Host: host, Port: port, Security: "none", From: "dns@exemplo.com"},
		Channels: []Channel{{ID: "mail", Name: "SOC", Type: TypeEmail, Enabled: true, To: []string{"soc@exemplo.com"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	m.dispatch(t.Context(), Event{Type: EventReport, Severity: SevLow, Title: "Relatório semanal", Text: "Resumo da semana",
		Time: time.Now(), Attachment: &Attachment{Name: "relatorio.pdf", Type: "application/pdf", Data: []byte("%PDF-1.4 teste")}}, "")
	select {
	case msg := <-got:
		for _, want := range []string{"Subject: =?utf-8?q?[HeimdallDNS]_Relat=C3=B3rio_semanal?=", "To: soc@exemplo.com", "multipart/mixed", `filename="relatorio.pdf"`, "JVBERi0xLjQgdGVzdGU="} {
			if !strings.Contains(msg, want) {
				t.Errorf("faltou %q em:\n%s", want, msg)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("e-mail não chegou: %+v", m.History())
	}
}
