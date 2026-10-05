// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package certs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestValidate(t *testing.T) {
	for _, bad := range []Settings{
		{},
		{Domains: []string{"heimdall.empresa.local"}},
		{Domains: []string{"*.empresa.com.br"}},
		{Domains: []string{"dns.empresa.com.br"}, Challenge: ChallengeCloudflare},
		{Domains: []string{"dns.empresa.com.br"}, Email: "não"},
		{Domains: []string{"semponto"}},
	} {
		if bad.Validate() == nil {
			t.Errorf("deveria recusar %+v", bad)
		}
	}
	s := Settings{Domains: []string{" DNS.Empresa.com.br. ", "dns.empresa.com.br", "painel.empresa.com.br"}}
	if err := s.Validate(); err != nil || len(s.Domains) != 2 || s.Domains[0] != "dns.empresa.com.br" || s.Challenge != ChallengeHTTP {
		t.Errorf("normalizar = %+v %v", s, err)
	}
	w := Settings{Domains: []string{"*.empresa.com.br"}, Challenge: ChallengeCloudflare, CloudflareToken: "x"}
	if err := w.Validate(); err != nil {
		t.Errorf("curinga pela Cloudflare: %v", err)
	}
}

// fakeDNS responde A 127.0.0.1 para tudo e os TXT guardados (desafio dns-01).
type fakeDNS struct {
	mu  sync.Mutex
	txt map[string][]string
}

func (f *fakeDNS) start(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 1}
		switch q.Qtype {
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.IPv4(127, 0, 0, 1)})
		case dns.TypeTXT:
			f.mu.Lock()
			for _, v := range f.txt[strings.ToLower(q.Name)] {
				m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr, Txt: []string{v}})
			}
			f.mu.Unlock()
		}
		w.WriteMsg(m)
	})
	udp, tcp := &dns.Server{PacketConn: pc, Handler: h}, &dns.Server{Listener: ln, Handler: h}
	go udp.ActivateAndServe()
	go tcp.ActivateAndServe()
	t.Cleanup(func() { udp.Shutdown(); tcp.Shutdown() })
	return pc.LocalAddr().String()
}

// fakeCloudflare imita a API v4: zonas, criar e apagar TXT.
func fakeCloudflare(t *testing.T, d *fakeDNS, created, deleted *int) *httptest.Server {
	var mu sync.Mutex
	recs := map[string][2]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token-cf" {
			w.WriteHeader(403)
			fmt.Fprint(w, `{"success":false,"errors":[{"message":"Invalid API Token"}]}`)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == "GET" && r.URL.Path == "/zones":
			if r.URL.Query().Get("name") == "exemplo.com.br" {
				fmt.Fprint(w, `{"success":true,"result":[{"id":"z1","name":"exemplo.com.br"}]}`)
			} else {
				fmt.Fprint(w, `{"success":true,"result":[]}`)
			}
		case r.Method == "POST" && r.URL.Path == "/zones/z1/dns_records":
			var body struct{ Name, Content string }
			json.NewDecoder(r.Body).Decode(&body)
			id := fmt.Sprintf("r%d", len(recs)+1)
			recs[id] = [2]string{body.Name, body.Content}
			d.mu.Lock()
			d.txt[dns.Fqdn(body.Name)] = append(d.txt[dns.Fqdn(body.Name)], body.Content)
			d.mu.Unlock()
			*created++
			fmt.Fprintf(w, `{"success":true,"result":{"id":%q}}`, id)
		case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/zones/z1/dns_records/"):
			delete(recs, strings.TrimPrefix(r.URL.Path, "/zones/z1/dns_records/"))
			*deleted++
			fmt.Fprint(w, `{"success":true,"result":{}}`)
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, `{"success":false,"errors":[{"message":"não existe"}]}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// lockedBuf guarda a saída do Pebble (escrita pelo processo, lida pelo teste).
type lockedBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// TestPebble emite de verdade num servidor ACME de teste (Pebble), com a
// validação HTTP-01 e a DNS-01 pela "Cloudflare". Roda só com
// HEIMDALL_PEBBLE_BIN (binário do pebble) e HEIMDALL_PEBBLE_ROOT (pasta do
// módulo, onde ficam os test/certs); o CI define as duas.
func TestPebble(t *testing.T) {
	bin, root := os.Getenv("HEIMDALL_PEBBLE_BIN"), os.Getenv("HEIMDALL_PEBBLE_ROOT")
	if bin == "" || root == "" {
		t.Skip("defina HEIMDALL_PEBBLE_BIN e HEIMDALL_PEBBLE_ROOT para o teste com o Pebble")
	}
	fd := &fakeDNS{txt: map[string][]string{}}
	dnsAddr := fd.start(t)
	httpPort, acmePort, mgmtPort := freePort(t), freePort(t), freePort(t)
	cfg := fmt.Sprintf(`{"pebble":{"listenAddress":"127.0.0.1:%d","managementListenAddress":"127.0.0.1:%d",
		"certificate":"%s/test/certs/localhost/cert.pem","privateKey":"%s/test/certs/localhost/key.pem",
		"httpPort":%d,"tlsPort":5001,"ocspResponderURL":"","externalAccountBindingRequired":false,
		"profiles":{"default":{"description":"x","validityPeriod":7776000}}}}`, acmePort, mgmtPort, root, root, httpPort)
	cfgFile := filepath.Join(t.TempDir(), "pebble.json")
	os.WriteFile(cfgFile, []byte(cfg), 0o644)
	cmd := exec.Command(bin, "-config", cfgFile, "-dnsserver", dnsAddr)
	cmd.Env = append(os.Environ(), "PEBBLE_VA_NOSLEEP=1", "PEBBLE_WFE_NONCEREJECT=0", "PEBBLE_AUTHZREUSE=0")
	out := &lockedBuf{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })

	ca, _ := os.ReadFile(filepath.Join(root, "test/certs/pebble.minica.pem"))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	dir := fmt.Sprintf("https://127.0.0.1:%d/dir", acmePort)
	for i := 0; ; i++ {
		if r, err := hc.Get(dir); err == nil {
			r.Body.Close()
			break
		}
		if i > 50 {
			t.Fatalf("pebble não subiu: %s", out.String())
		}
		time.Sleep(100 * time.Millisecond)
	}

	var events []string
	var created, deleted int
	cf := fakeCloudflare(t, fd, &created, &deleted)
	m := New(Options{Dir: t.TempDir(), DirectoryURL: dir, HTTPClient: hc, HTTPAddr: fmt.Sprintf("127.0.0.1:%d", httpPort),
		CloudflareAPI: cf.URL, SkipTXTCheck: true,
		OnEvent: func(ok bool, title, _ string) { events = append(events, fmt.Sprint(ok, " ", title)) }})

	// HTTP-01.
	if err := m.SetSettings(Settings{Enabled: true, Domains: []string{"heimdall.exemplo.com.br"}, Email: "ti@exemplo.com.br", AutoRenew: true, UsePanel: true}); err != nil {
		t.Fatal(err)
	}
	if err := m.Issue(t.Context()); err != nil {
		t.Fatalf("HTTP-01: %v\n%s\npebble: %s", err, strings.Join(m.Status().Log, "\n"), out.String())
	}
	st := m.Status()
	if st.State != "active" || st.Domains[0] != "heimdall.exemplo.com.br" || st.NotAfter.Before(time.Now().Add(80*24*time.Hour)) {
		t.Fatalf("status = %+v", st)
	}
	if fi, _ := os.Stat(m.KeyFile()); fi.Mode().Perm() != 0o600 {
		t.Errorf("chave com permissão %v", fi.Mode().Perm())
	}
	if !m.ForPanel() || m.ForDNS() {
		t.Error("uso no painel/DNS")
	}
	// A configuração TLS embrulhada entrega o certificado novo pelo nome.
	wrapped := m.Wrap(nil, m.ForPanel)
	c, err := wrapped.GetCertificate(&tls.ClientHelloInfo{ServerName: "heimdall.exemplo.com.br"})
	if err != nil || c.Leaf.DNSNames[0] != "heimdall.exemplo.com.br" {
		t.Errorf("Wrap = %v", err)
	}

	// DNS-01 pela Cloudflare, com curinga; o TXT é apagado no fim.
	if err := m.SetSettings(Settings{Enabled: true, Domains: []string{"exemplo.com.br", "*.exemplo.com.br"}, Challenge: ChallengeCloudflare, CloudflareToken: "token-cf", AutoRenew: true, UseDNS: true}); err != nil {
		t.Fatal(err)
	}
	if err := m.Issue(t.Context()); err != nil {
		t.Fatalf("DNS-01: %v\n%s\npebble: %s", err, strings.Join(m.Status().Log, "\n"), out.String())
	}
	if created != 2 || deleted != 2 {
		t.Errorf("TXT criados %d, apagados %d", created, deleted)
	}
	if st := m.Status(); len(st.Domains) != 2 || !m.ForDNS() {
		t.Errorf("curinga = %+v", st.Domains)
	}
	// Token errado: falha clara, e o certificado anterior continua.
	m.SetSettings(Settings{Enabled: true, Domains: []string{"exemplo.com.br"}, Challenge: ChallengeCloudflare, CloudflareToken: "errado", AutoRenew: true})
	if err := m.Issue(t.Context()); err == nil || !strings.Contains(err.Error(), "Invalid API Token") {
		t.Errorf("token errado: %v", err)
	}
	if m.Certificate() == nil || m.Status().State != "error" {
		t.Error("o certificado anterior tem que continuar valendo")
	}

	// Um novo gerenciador na mesma pasta pega o certificado do disco (partida).
	m2 := New(Options{Dir: m.opts.Dir})
	if m2.Certificate() == nil {
		t.Error("não carregou do disco")
	}
	if len(events) != 3 || !strings.HasPrefix(events[0], "true") || !strings.HasPrefix(events[2], "false") {
		t.Errorf("eventos = %v", events)
	}
	_ = io.Discard
}

func TestRenewalCheck(t *testing.T) {
	// Sem ACME: confere só a decisão (renovar desligado → aviso, uma vez por dia).
	var events []string
	m := New(Options{Dir: t.TempDir(), OnEvent: func(ok bool, title, _ string) { events = append(events, title) }})
	m.SetSettings(Settings{Enabled: true, Domains: []string{"dns.exemplo.com.br"}, AutoRenew: false})
	leaf := &x509.Certificate{DNSNames: []string{"dns.exemplo.com.br"}, NotBefore: time.Now().Add(-80 * 24 * time.Hour), NotAfter: time.Now().Add(10 * 24 * time.Hour)}
	m.leaf.Store(leaf)
	m.cert.Store(&tls.Certificate{Leaf: leaf})
	m.check(context.Background(), time.Now())
	m.check(context.Background(), time.Now().Add(time.Hour))
	if len(events) != 1 || !strings.Contains(events[0], "perto de vencer") {
		t.Errorf("avisos = %v", events)
	}
	m.check(context.Background(), time.Now().Add(25*time.Hour))
	if len(events) != 2 {
		t.Errorf("aviso do dia seguinte: %v", events)
	}
	// Longe do vencimento: nada.
	leaf.NotAfter = time.Now().Add(60 * 24 * time.Hour)
	m.check(context.Background(), time.Now().Add(50*time.Hour))
	if len(events) != 2 {
		t.Error("não deveria avisar com 60 dias")
	}
	if st := m.Status(); !st.NextRenewal.IsZero() {
		t.Error("sem renovação automática não há próxima renovação")
	}
	// Renovação em um terço da validade: 30 dias antes nos de 90, 2 dias nos de 6.
	now := time.Now()
	for _, tc := range []struct{ life, want time.Duration }{{90 * 24 * time.Hour, 30 * 24 * time.Hour}, {6 * 24 * time.Hour, 48 * time.Hour}} {
		c := &x509.Certificate{NotBefore: now, NotAfter: now.Add(tc.life)}
		if got := c.NotAfter.Sub(renewAt(c)); got != tc.want {
			t.Errorf("validade %v: renova %v antes, quero %v", tc.life, got, tc.want)
		}
	}
}
