// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package certs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/acme"
)

func (m *Manager) issue(ctx context.Context, s Settings) error {
	dir := m.opts.DirectoryURL
	if dir == "" {
		dir = LetsEncrypt
		if s.Staging {
			dir = LetsEncryptStaging
		}
	}
	key, err := m.accountKey()
	if err != nil {
		return fmt.Errorf("chave da conta ACME: %w", err)
	}
	cl := &acme.Client{Key: key, DirectoryURL: dir, HTTPClient: m.opts.HTTPClient, UserAgent: "HeimdallDNS"}
	m.step("conectando a %s", dir)
	acct := &acme.Account{}
	if s.Email != "" {
		acct.Contact = []string{"mailto:" + s.Email}
	}
	if _, err := cl.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return fmt.Errorf("conta no Let's Encrypt: %w", err)
	}
	m.step("pedido para %s", strings.Join(s.Domains, ", "))
	order, err := cl.AuthorizeOrder(ctx, acme.DomainIDs(s.Domains...))
	if err != nil {
		return fmt.Errorf("pedido: %w", err)
	}

	var cleanup []func()
	defer func() {
		for _, f := range cleanup {
			f()
		}
	}()
	var httpSrv *challengeServer
	for _, u := range order.AuthzURLs {
		authz, err := cl.GetAuthorization(ctx, u)
		if err != nil {
			return err
		}
		if authz.Status == acme.StatusValid {
			m.step("%s já validado", authz.Identifier.Value)
			continue
		}
		want := "http-01"
		if s.Challenge == ChallengeCloudflare {
			want = "dns-01"
		}
		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == want {
				chal = c
			}
		}
		if chal == nil {
			return fmt.Errorf("%s: o Let's Encrypt não ofereceu a validação %s", authz.Identifier.Value, want)
		}
		name := authz.Identifier.Value
		switch want {
		case "http-01":
			if httpSrv == nil {
				httpSrv, err = startChallengeServer(m.opts.HTTPAddr)
				if err != nil {
					return fmt.Errorf("a validação HTTP precisa da porta 80 livre neste servidor: %w", err)
				}
				cleanup = append(cleanup, httpSrv.close)
				m.step("porta 80 aberta para a validação (só durante a emissão)")
			}
			resp, err := cl.HTTP01ChallengeResponse(chal.Token)
			if err != nil {
				return err
			}
			httpSrv.set(cl.HTTP01ChallengePath(chal.Token), resp)
		case "dns-01":
			val, err := cl.DNS01ChallengeRecord(chal.Token)
			if err != nil {
				return err
			}
			cf := &cloudflare{token: s.CloudflareToken, api: m.opts.CloudflareAPI, http: m.opts.HTTPClient}
			rec := "_acme-challenge." + strings.TrimPrefix(name, "*.")
			id, zone, err := cf.addTXT(ctx, rec, val)
			if err != nil {
				return fmt.Errorf("Cloudflare: %w", err)
			}
			m.step("registro TXT %s criado na Cloudflare", rec)
			cleanup = append(cleanup, func() {
				dctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := cf.delete(dctx, zone, id); err != nil {
					m.log.Warn("não apaguei o TXT do desafio na Cloudflare", "registro", rec, "erro", err)
				}
			})
			if !m.opts.SkipTXTCheck {
				m.step("esperando o TXT aparecer no DNS público")
				if err := waitTXT(ctx, rec, val); err != nil {
					return err
				}
			}
		}
		if _, err := cl.Accept(ctx, chal); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		m.step("validando %s", name)
		if _, err := cl.WaitAuthorization(ctx, authz.URI); err != nil {
			return fmt.Errorf("%s não foi validado: %s", name, explain(err, want))
		}
		m.step("%s validado", name)
	}
	finalize := order.FinalizeURL
	if _, err = cl.WaitOrder(ctx, order.URI); err != nil {
		return fmt.Errorf("pedido: %w", err)
	}
	csr, certKey, err := newCSR(s.Domains)
	if err != nil {
		return err
	}
	chain, _, err := cl.CreateOrderCert(ctx, finalize, csr, true)
	if err != nil {
		// O RFC 8555 não obriga o cabeçalho Location na resposta da
		// finalização, e sem ele a biblioteca não sabe onde esperar. O
		// pedido já foi finalizado: espera pelo endereço que já temos.
		o, werr := cl.WaitOrder(ctx, order.URI)
		if werr != nil || o.Status != acme.StatusValid || o.CertURL == "" {
			return fmt.Errorf("emissão: %w", err)
		}
		if chain, err = cl.FetchCert(ctx, o.CertURL, true); err != nil {
			return fmt.Errorf("baixar o certificado: %w", err)
		}
	}
	if err := m.save(chain, certKey); err != nil {
		return fmt.Errorf("gravar o certificado: %w", err)
	}
	m.step("certificado instalado em %s (vale até %s)", m.opts.Dir, m.leaf.Load().NotAfter.Format("02/01/2006"))
	return nil
}

// explain traduz as falhas comuns da validação.
func explain(err error, typ string) string {
	msg := err.Error()
	var ae *acme.AuthorizationError
	if errors.As(err, &ae) && len(ae.Errors) > 0 {
		msg = ae.Errors[0].Error()
	}
	switch {
	case typ == "http-01" && (strings.Contains(msg, "Timeout") || strings.Contains(msg, "connection")):
		return msg + " — o Let's Encrypt não alcançou a porta 80 deste servidor: confira o DNS público do domínio, o firewall e o redirecionamento de porta no roteador"
	case strings.Contains(msg, "NXDOMAIN") || strings.Contains(msg, "no valid A records"):
		return msg + " — o domínio não aponta para este servidor no DNS público"
	}
	return msg
}

// --- HTTP-01 ----------------------------------------------------------------

type challengeServer struct {
	srv  *http.Server
	mu   sync.Mutex
	resp map[string]string
}

func startChallengeServer(addr string) (*challengeServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	c := &challengeServer{resp: map[string]string{}}
	c.srv = &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		v, ok := c.resp[r.URL.Path]
		c.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, v)
	})}
	go c.srv.Serve(ln)
	return c, nil
}

func (c *challengeServer) set(path, value string) {
	c.mu.Lock()
	c.resp[path] = value
	c.mu.Unlock()
}

func (c *challengeServer) close() { c.srv.Close() }

// --- DNS-01 pela Cloudflare ------------------------------------------------------

type cloudflare struct {
	token string
	api   string
	http  *http.Client
}

func (c *cloudflare) do(ctx context.Context, method, path string, body any, out any) error {
	api := c.api
	if api == "" {
		api = "https://api.cloudflare.com/client/v4"
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, api+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	hc := c.http
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var env struct {
		Success bool                       `json:"success"`
		Errors  []struct{ Message string } `json:"errors"`
		Result  json.RawMessage            `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&env); err != nil {
		return fmt.Errorf("resposta HTTP %d ilegível", resp.StatusCode)
	}
	if !env.Success {
		msgs := []string{}
		for _, e := range env.Errors {
			msgs = append(msgs, e.Message)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.Join(msgs, "; "))
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// zoneFor acha a zona do nome subindo pelos rótulos (sub.empresa.com.br → empresa.com.br).
func (c *cloudflare) zoneFor(ctx context.Context, name string) (string, error) {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i := range len(labels) - 1 {
		cand := strings.Join(labels[i:], ".")
		var zones []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := c.do(ctx, http.MethodGet, "/zones?name="+cand, nil, &zones); err != nil {
			return "", err
		}
		if len(zones) > 0 {
			return zones[0].ID, nil
		}
	}
	return "", fmt.Errorf("nenhuma zona da conta cobre %s (o token tem acesso à zona?)", name)
}

func (c *cloudflare) addTXT(ctx context.Context, name, value string) (id, zone string, err error) {
	if zone, err = c.zoneFor(ctx, name); err != nil {
		return "", "", err
	}
	var rec struct {
		ID string `json:"id"`
	}
	err = c.do(ctx, http.MethodPost, "/zones/"+zone+"/dns_records", map[string]any{
		"type": "TXT", "name": name, "content": value, "ttl": 60, "comment": "desafio ACME do HeimdallDNS (apagado em seguida)",
	}, &rec)
	return rec.ID, zone, err
}

func (c *cloudflare) delete(ctx context.Context, zone, id string) error {
	return c.do(ctx, http.MethodDelete, "/zones/"+zone+"/dns_records/"+id, nil, nil)
}

// waitTXT espera o valor aparecer nos resolvedores públicos (até 3 minutos).
func waitTXT(ctx context.Context, name, value string) error {
	deadline := time.Now().Add(3 * time.Minute)
	cl := &dns.Client{Timeout: 5 * time.Second}
	for time.Now().Before(deadline) {
		for _, srv := range []string{"1.1.1.1:53", "8.8.8.8:53"} {
			q := new(dns.Msg)
			q.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
			r, _, err := cl.ExchangeContext(ctx, q, srv)
			if err != nil {
				continue
			}
			for _, rr := range r.Answer {
				if t, ok := rr.(*dns.TXT); ok && strings.Join(t.Txt, "") == value {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
		}
	}
	return fmt.Errorf("o TXT %s não apareceu no DNS público em 3 minutos", name)
}
