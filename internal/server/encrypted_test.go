// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ugoneiva/HeimdallDNS/internal/cache"
	"github.com/ugoneiva/HeimdallDNS/internal/clients"
	"github.com/ugoneiva/HeimdallDNS/internal/config"
	"github.com/ugoneiva/HeimdallDNS/internal/filter"
	"github.com/ugoneiva/HeimdallDNS/internal/upstream"
)

// selfSigned gera um certificado para dns.teste e *.dns.teste.
func selfSigned(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dns.teste"},
		DNSNames:  []string{"dns.teste", "*.dns.teste"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}}, pool
}

func startEncrypted(t *testing.T) (*Server, *clients.Registry, *x509.CertPool) {
	t.Helper()
	addr, _ := fakeUpstream(t)
	ups, _ := upstream.New(upstream.Options{Servers: []string{addr}, Mode: upstream.ModeFastest, Timeout: 2 * time.Second})
	t.Cleanup(func() { ups.Close() })
	reg, _ := clients.NewRegistry(clients.Options{})
	cfg, pool := selfSigned(t)
	b := filter.NewBuilder()
	b.AddLine("||bloqueado.test^", false)
	mt := b.Build()
	srv := New(Options{
		Listen: []string{"127.0.0.1:0"},
		// O loopback NÃO está nas redes permitidas: só entra quem tiver token.
		Allowed:   []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		BlockMode: config.BlockNull, BlockTTL: 10, Cache: cache.New(cache.Options{Size: 100}),
		Filter: func() *filter.Matcher { return mt }, Upstream: ups, Clients: reg,
		TLS: cfg, PublicHost: "dns.teste", DoTListen: []string{"127.0.0.1:0"}, DoHListen: "127.0.0.1:0",
	})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Shutdown(t.Context()) })
	return srv, reg, pool
}

func dotQuery(t *testing.T, srv *Server, pool *x509.CertPool, sni, name string) *dns.Msg {
	t.Helper()
	c := &dns.Client{Net: "tcp-tls", Timeout: 2 * time.Second,
		TLSConfig: &tls.Config{ServerName: sni, RootCAs: pool, NextProtos: []string{"dot"}}}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	r, _, err := c.Exchange(m, srv.DoTAddrs()[0].String())
	if err != nil {
		t.Fatalf("DoT %s: %v", sni, err)
	}
	return r
}

func dohClient(pool *x509.CertPool) *http.Client {
	return &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{ServerName: "dns.teste", RootCAs: pool}, ForceAttemptHTTP2: true}}
}

func TestDoTWithDeviceToken(t *testing.T) {
	srv, reg, pool := startEncrypted(t)
	dev := reg.Observe(netip.MustParseAddr("10.0.0.50"), time.Now()) // aparelho conhecido da rede
	tok, err := reg.SetToken(dev, false)
	if err != nil || len(tok) != 16 {
		t.Fatalf("token = %q %v", tok, err)
	}

	if r := dotQuery(t, srv, pool, "dns.teste", "exemplo.com"); r.Rcode != dns.RcodeRefused {
		t.Errorf("DoT sem token, de fora das redes permitidas: %s", dns.RcodeToString[r.Rcode])
	}
	r := dotQuery(t, srv, pool, tok+".dns.teste", "exemplo.com")
	if firstA(t, r) != "1.2.3.4" {
		t.Errorf("DoT com token: %v", r)
	}
	v := dev.View()
	if v.Queries != 2 || len(v.IPs) != 1 {
		t.Errorf("a consulta conta para o aparelho, sem trazer o IP de fora: %+v", v)
	}
	// A política do aparelho vale fora da rede.
	reg.Isolate(dev, clients.ModeRefused, "teste", nil)
	if r := dotQuery(t, srv, pool, tok+".dns.teste", "exemplo.com"); r.Rcode != dns.RcodeRefused {
		t.Errorf("isolado também fora da rede: %s", dns.RcodeToString[r.Rcode])
	}
	// Token revogado deixa de valer.
	reg.Release(dev)
	reg.SetToken(dev, true)
	if r := dotQuery(t, srv, pool, tok+".dns.teste", "exemplo.com"); r.Rcode != dns.RcodeRefused {
		t.Errorf("token revogado: %s", dns.RcodeToString[r.Rcode])
	}
}

func TestDoH(t *testing.T) {
	srv, reg, pool := startEncrypted(t)
	dev := reg.Observe(netip.MustParseAddr("10.0.0.60"), time.Now())
	tok, _ := reg.SetToken(dev, false)
	base := "https://" + srv.DoHAddr().String() + "/dns-query"
	hc := dohClient(pool)

	msg := func(name string) []byte {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), dns.TypeA)
		m.Id = 0 // RFC 8484 recomenda ID 0 (melhor para cache HTTP)
		b, _ := m.Pack()
		return b
	}
	parse := func(resp *http.Response, err error) *dns.Msg {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/dns-message" {
			t.Fatalf("HTTP %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		b, _ := io.ReadAll(resp.Body)
		m := new(dns.Msg)
		if err := m.Unpack(b); err != nil {
			t.Fatal(err)
		}
		return m
	}

	// GET com token.
	r := parse(hc.Get(base + "/" + tok + "?dns=" + base64.RawURLEncoding.EncodeToString(msg("exemplo.com"))))
	if firstA(t, r) != "1.2.3.4" {
		t.Errorf("GET: %v", r)
	}
	// POST com token, domínio bloqueado.
	r = parse(hc.Post(base+"/"+tok, "application/dns-message", bytes.NewReader(msg("ads.bloqueado.test"))))
	if firstA(t, r) != "0.0.0.0" {
		t.Errorf("POST bloqueado: %v", r)
	}
	// Sem token, de fora das redes permitidas: recusa.
	r = parse(hc.Post(base, "application/dns-message", bytes.NewReader(msg("exemplo.com"))))
	if r.Rcode != dns.RcodeRefused {
		t.Errorf("sem token: %s", dns.RcodeToString[r.Rcode])
	}
	if dev.View().Queries != 3 {
		t.Errorf("consultas do aparelho = %d", dev.View().Queries)
	}

	for _, bad := range []struct {
		method, url, ct string
		body            []byte
		code            int
	}{
		{"GET", base + "?dns=@@@", "", nil, 400},
		{"POST", base, "text/plain", msg("x.com"), 415},
		{"POST", base, "application/dns-message", []byte{1, 2, 3}, 400},
		{"PUT", base, "application/dns-message", nil, 405},
		{"GET", "https://" + srv.DoHAddr().String() + "/outra", "", nil, 404},
		{"GET", base + "/a/b?dns=AAAA", "", nil, 404},
	} {
		req, _ := http.NewRequest(bad.method, bad.url, bytes.NewReader(bad.body))
		if bad.ct != "" {
			req.Header.Set("Content-Type", bad.ct)
		}
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != bad.code {
			t.Errorf("%s %s: %d, quero %d", bad.method, bad.url, resp.StatusCode, bad.code)
		}
	}
}

func TestTokenFromSNI(t *testing.T) {
	s := New(Options{PublicHost: "dns.empresa.com.br."})
	cases := map[string]string{
		"abc123.dns.empresa.com.br": "abc123",
		"ABC123.DNS.EMPRESA.COM.BR": "abc123",
		"dns.empresa.com.br":        "",
		"a.b.dns.empresa.com.br":    "",
		"abc123.outro.com":          "",
	}
	for sni, want := range cases {
		if got := s.tokenFromSNI(sni); got != want {
			t.Errorf("tokenFromSNI(%q) = %q, quero %q", sni, got, want)
		}
	}
}
