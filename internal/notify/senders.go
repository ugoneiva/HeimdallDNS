// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

func (m *Manager) post(ctx context.Context, url string, body []byte, hdr map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "HeimdallDNS")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := m.opts.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

func suppressedNote(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("(+%d repetições juntadas desde o último aviso)", n)
}

// --- Telegram ---------------------------------------------------------------

func (m *Manager) telegram(ctx context.Context, c Channel, e Event, suppressed int) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s <b>%s</b>\n", sevIcon(e.Severity), html.EscapeString(e.Title))
	if e.Text != "" {
		b.WriteString(html.EscapeString(e.Text) + "\n")
	}
	for _, f := range e.Fields {
		fmt.Fprintf(&b, "\n<b>%s:</b> %s", html.EscapeString(f[0]), html.EscapeString(f[1]))
	}
	if n := suppressedNote(suppressed); n != "" {
		b.WriteString("\n\n<i>" + n + "</i>")
	}
	if e.Link != "" {
		fmt.Fprintf(&b, "\n\n<a href=\"%s\">Abrir o painel</a>", html.EscapeString(e.Link))
	}
	fmt.Fprintf(&b, "\n<i>%s</i>", html.EscapeString(m.footer(e)))
	body, _ := json.Marshal(map[string]any{
		"chat_id": strings.TrimSpace(c.ChatID), "text": b.String(), "parse_mode": "HTML", "disable_web_page_preview": true,
	})
	return m.post(ctx, m.opts.TelegramAPI+"/bot"+c.BotToken+"/sendMessage", body, nil)
}

func sevIcon(s string) string {
	switch s {
	case SevCritical:
		return "🔴"
	case SevHigh:
		return "🟠"
	case SevMedium:
		return "🟡"
	}
	return "🔵"
}

// --- Microsoft Teams (fluxo do Power Automate / Workflows) --------------------

func (m *Manager) teams(ctx context.Context, c Channel, e Event, suppressed int) error {
	color := map[string]string{SevCritical: "attention", SevHigh: "attention", SevMedium: "warning"}[e.Severity]
	if color == "" {
		color = "accent"
	}
	body := []any{
		map[string]any{"type": "TextBlock", "text": e.Title, "weight": "bolder", "size": "medium", "color": color, "wrap": true},
	}
	if e.Text != "" {
		body = append(body, map[string]any{"type": "TextBlock", "text": e.Text, "wrap": true})
	}
	if len(e.Fields) > 0 {
		facts := []any{map[string]string{"title": "Gravidade", "value": SevLabel(e.Severity)}}
		for _, f := range e.Fields {
			facts = append(facts, map[string]string{"title": f[0], "value": f[1]})
		}
		body = append(body, map[string]any{"type": "FactSet", "facts": facts})
	}
	if n := suppressedNote(suppressed); n != "" {
		body = append(body, map[string]any{"type": "TextBlock", "text": n, "isSubtle": true, "wrap": true})
	}
	body = append(body, map[string]any{"type": "TextBlock", "text": "HeimdallDNS · " + m.footer(e), "isSubtle": true, "size": "small", "wrap": true})
	card := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4", "body": body,
	}
	if e.Link != "" {
		card["actions"] = []any{map[string]string{"type": "Action.OpenUrl", "title": "Abrir o painel", "url": e.Link}}
	}
	payload, _ := json.Marshal(map[string]any{
		"type":        "message",
		"attachments": []any{map[string]any{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}},
	})
	return m.post(ctx, c.URL, payload, nil)
}

// --- Webhook genérico -----------------------------------------------------------

// WebhookPayload é o corpo JSON enviado ao webhook.
type WebhookPayload struct {
	Type       string            `json:"type"`
	Severity   string            `json:"severity"`
	Title      string            `json:"title"`
	Text       string            `json:"text,omitempty"`
	Fields     map[string]string `json:"fields,omitempty"`
	Time       time.Time         `json:"time"`
	Node       string            `json:"node,omitempty"`
	Link       string            `json:"link,omitempty"`
	Suppressed int               `json:"suppressed,omitempty"`
}

// Sign calcula a assinatura do webhook: HMAC-SHA256 de "<timestamp>.<corpo>".
func Sign(secret, timestamp string, body []byte) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(timestamp + "."))
	h.Write(body)
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

func (m *Manager) webhook(ctx context.Context, c Channel, e Event, suppressed int) error {
	p := WebhookPayload{Type: e.Type, Severity: e.Severity, Title: e.Title, Text: e.Text, Time: e.Time.UTC(),
		Node: m.opts.Node, Link: e.Link, Suppressed: suppressed}
	if len(e.Fields) > 0 {
		p.Fields = map[string]string{}
		for _, f := range e.Fields {
			p.Fields[f[0]] = f[1]
		}
	}
	body, _ := json.Marshal(p)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	hdr := map[string]string{"X-Heimdall-Event": e.Type, "X-Heimdall-Timestamp": ts}
	if c.Secret != "" {
		hdr["X-Heimdall-Signature"] = Sign(c.Secret, ts, body)
	}
	return m.post(ctx, c.URL, body, hdr)
}

// --- E-mail (SMTP) --------------------------------------------------------------

func (s *SMTP) validate() error {
	s.Host = strings.TrimSpace(s.Host)
	if s.Host == "" {
		return errors.New("informe o servidor SMTP para os canais de e-mail")
	}
	switch s.Security {
	case "":
		s.Security = "starttls"
	case "starttls", "tls", "none":
	default:
		return fmt.Errorf("SMTP: segurança %q (use starttls, tls ou none)", s.Security)
	}
	if s.Port == 0 {
		s.Port = map[string]int{"starttls": 587, "tls": 465, "none": 25}[s.Security]
	}
	if s.Port < 1 || s.Port > 65535 {
		return errors.New("SMTP: porta inválida")
	}
	if !validEmail(s.From) {
		return fmt.Errorf("SMTP: remetente %q inválido", s.From)
	}
	return nil
}

func (m *Manager) email(ctx context.Context, s SMTP, c Channel, e Event, suppressed int) error {
	if err := s.validate(); err != nil {
		return err
	}
	msg, err := m.buildMail(s.From, c.To, e, suppressed)
	if err != nil {
		return err
	}
	return SendMail(ctx, s, c.To, msg)
}

// SendMail entrega a mensagem pronta (cabeçalhos + corpo).
func SendMail(ctx context.Context, s SMTP, to []string, msg []byte) error {
	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
	d := net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	var err error
	tlsCfg := &tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}
	if s.Security == "tls" {
		conn, err = (&tls.Dialer{NetDialer: &d, Config: tlsCfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	cl, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer cl.Close()
	if s.Security == "starttls" {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return errors.New("o servidor SMTP não oferece STARTTLS (use security: tls ou none)")
		}
		if err := cl.StartTLS(tlsCfg); err != nil {
			return err
		}
	}
	if s.Username != "" {
		if err := cl.Auth(smtp.PlainAuth("", s.Username, s.Password, s.Host)); err != nil {
			return fmt.Errorf("autenticação SMTP: %w", err)
		}
	}
	if err := cl.Mail(s.From); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := cl.Rcpt(rcpt); err != nil {
			return fmt.Errorf("destinatário %s: %w", rcpt, err)
		}
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}

func (m *Manager) buildMail(from string, to []string, e Event, suppressed int) ([]byte, error) {
	var text strings.Builder
	text.WriteString(e.Title + "\n\n")
	if e.Text != "" {
		text.WriteString(e.Text + "\n\n")
	}
	if e.Type != EventReport && e.Type != EventTest {
		fmt.Fprintf(&text, "Gravidade: %s\n", SevLabel(e.Severity))
	}
	for _, f := range e.Fields {
		fmt.Fprintf(&text, "%s: %s\n", f[0], f[1])
	}
	if n := suppressedNote(suppressed); n != "" {
		text.WriteString("\n" + n + "\n")
	}
	if e.Link != "" {
		text.WriteString("\nPainel: " + e.Link + "\n")
	}
	text.WriteString("\n-- \nHeimdallDNS · " + m.footer(e) + "\n")

	var buf bytes.Buffer
	subject := "[HeimdallDNS] " + e.Title
	if e.Type != EventReport && e.Type != EventTest {
		subject = "[HeimdallDNS] [" + SevLabel(e.Severity) + "] " + e.Title
	}
	id := make([]byte, 12)
	rand.Read(id)
	domain := from[strings.LastIndexByte(from, '@')+1:]
	hdr := []string{
		"From: " + from,
		"To: " + strings.Join(to, ", "),
		"Subject: " + mime.QEncoding.Encode("utf-8", subject),
		"Date: " + e.Time.Format(time.RFC1123Z),
		"Message-ID: <" + hex.EncodeToString(id) + "@" + domain + ">",
		"MIME-Version: 1.0",
		"Auto-Submitted: auto-generated",
	}
	if e.Attachment == nil {
		hdr = append(hdr, "Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: quoted-printable")
		buf.WriteString(strings.Join(hdr, "\r\n") + "\r\n\r\n")
		qp := quotedprintable.NewWriter(&buf)
		qp.Write([]byte(strings.ReplaceAll(text.String(), "\n", "\r\n")))
		qp.Close()
		return buf.Bytes(), nil
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	hdr = append(hdr, "Content-Type: multipart/mixed; boundary="+mw.Boundary())
	buf.WriteString(strings.Join(hdr, "\r\n") + "\r\n\r\n")
	pw, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type": {"text/plain; charset=utf-8"}, "Content-Transfer-Encoding": {"quoted-printable"},
	})
	if err != nil {
		return nil, err
	}
	qp := quotedprintable.NewWriter(pw)
	qp.Write([]byte(strings.ReplaceAll(text.String(), "\n", "\r\n")))
	qp.Close()
	a := e.Attachment
	aw, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {a.Type + "; name=\"" + a.Name + "\""},
		"Content-Disposition":       {"attachment; filename=\"" + a.Name + "\""},
		"Content-Transfer-Encoding": {"base64"},
	})
	if err != nil {
		return nil, err
	}
	enc := base64.StdEncoding.EncodeToString(a.Data)
	for len(enc) > 76 {
		aw.Write([]byte(enc[:76] + "\r\n"))
		enc = enc[76:]
	}
	aw.Write([]byte(enc + "\r\n"))
	mw.Close()
	buf.Write(body.Bytes())
	return buf.Bytes(), nil
}
