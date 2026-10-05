// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

// Package certs emite e renova o certificado HTTPS do HeimdallDNS pelo
// Let's Encrypt (ACME, RFC 8555), sem programa externo. O certificado fica em
// <data_dir>/certs e passa a valer no painel e no DNS criptografado (DoT/DoH)
// sem reiniciar o serviço.
package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Endereços do Let's Encrypt.
const (
	LetsEncrypt        = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Formas de provar que o domínio é seu.
const (
	ChallengeHTTP       = "http-01"           // porta 80 aberta para a internet
	ChallengeCloudflare = "dns-01-cloudflare" // registro TXT criado pela API da Cloudflare
)

// RenewBefore é o máximo de antecedência da renovação automática. Ela age
// quando falta um terço da validade: 30 dias nos certificados de 90 dias,
// 2 dias nos de 6 (o Let's Encrypt também emite certificados curtos).
const RenewBefore = 30 * 24 * time.Hour

// renewAt é quando o certificado deve ser renovado.
func renewAt(leaf *x509.Certificate) time.Time {
	return leaf.NotAfter.Add(-min(RenewBefore, leaf.NotAfter.Sub(leaf.NotBefore)/3))
}

// Settings é o que o administrador preenche no painel.
type Settings struct {
	Enabled   bool     `json:"enabled"` // usar o certificado emitido aqui
	Domains   []string `json:"domains"` // o primeiro é o principal
	Email     string   `json:"email"`   // avisos do Let's Encrypt (opcional)
	Challenge string   `json:"challenge"`
	// Token da API da Cloudflare com permissão Zone:DNS:Edit (só no dns-01).
	CloudflareToken string `json:"cloudflare_token,omitempty"`
	AutoRenew       bool   `json:"auto_renew"`
	Staging         bool   `json:"staging"`   // ambiente de teste (certificado não confiável)
	UsePanel        bool   `json:"use_panel"` // painel e API
	UseDNS          bool   `json:"use_dns"`   // DoT/DoH
}

// Validate normaliza e confere.
func (s *Settings) Validate() error {
	var ds []string
	for _, d := range s.Domains {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if d == "" || slices.Contains(ds, d) {
			continue
		}
		if _, ok := dns.IsDomainName(d); !ok || !strings.Contains(d, ".") || strings.ContainsAny(d, " /:") {
			return fmt.Errorf("domínio %q inválido", d)
		}
		if strings.HasPrefix(d, "*.") && s.Challenge != ChallengeCloudflare {
			return errors.New("certificado curinga (*.) só pela validação DNS (Cloudflare)")
		}
		if strings.HasSuffix(d, ".local") || strings.HasSuffix(d, ".lan") || strings.HasSuffix(d, ".internal") || strings.HasSuffix(d, ".home.arpa") {
			return fmt.Errorf("%s não é um domínio público: o Let's Encrypt só emite para domínios registrados", d)
		}
		ds = append(ds, d)
	}
	if len(ds) == 0 {
		return errors.New("informe o domínio (ex.: dns.empresa.com.br)")
	}
	if len(ds) > 20 {
		return errors.New("no máximo 20 nomes por certificado")
	}
	s.Domains = ds
	s.Email = strings.TrimSpace(s.Email)
	if s.Email != "" && (!strings.Contains(s.Email, "@") || strings.ContainsAny(s.Email, " <>,;")) {
		return fmt.Errorf("e-mail %q inválido", s.Email)
	}
	switch s.Challenge {
	case "":
		s.Challenge = ChallengeHTTP
	case ChallengeHTTP:
	case ChallengeCloudflare:
		if strings.TrimSpace(s.CloudflareToken) == "" {
			return errors.New("informe o token da API da Cloudflare")
		}
	default:
		return fmt.Errorf("validação %q (use http-01 ou dns-01-cloudflare)", s.Challenge)
	}
	return nil
}

// Status é o estado do certificado, para o painel.
type Status struct {
	State       string    `json:"state"` // none, issuing, active, error
	Domains     []string  `json:"domains,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
	NotBefore   time.Time `json:"not_before,omitzero"`
	NotAfter    time.Time `json:"not_after,omitzero"`
	Staging     bool      `json:"staging,omitempty"`
	LastAttempt time.Time `json:"last_attempt,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	NextRenewal time.Time `json:"next_renewal,omitzero"`
	Log         []string  `json:"log"` // passos da última emissão
	CertFile    string    `json:"cert_file,omitempty"`
	KeyFile     string    `json:"key_file,omitempty"`
}

// Options do gerenciador.
type Options struct {
	Dir    string // <data_dir>/certs
	Logger *slog.Logger
	// OnEvent avisa emissões, renovações e falhas (notificações).
	OnEvent func(ok bool, title, detail string)
	// Para os testes: diretório ACME, cliente HTTP, porta do HTTP-01, API da
	// Cloudflare e conferência do TXT.
	DirectoryURL  string
	HTTPClient    *http.Client
	HTTPAddr      string // padrão ":80"
	CloudflareAPI string
	SkipTXTCheck  bool
}

// Manager guarda o certificado em uso e cuida da renovação.
type Manager struct {
	opts     Options
	log      *slog.Logger
	settings atomic.Pointer[Settings]
	cert     atomic.Pointer[tls.Certificate]
	leaf     atomic.Pointer[x509.Certificate]

	mu      sync.Mutex // uma emissão de cada vez
	stMu    sync.Mutex
	status  Status
	warned  time.Time
	running atomic.Bool
}

func New(opts Options) *Manager {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.HTTPAddr == "" {
		opts.HTTPAddr = ":80"
	}
	m := &Manager{opts: opts, log: opts.Logger}
	m.settings.Store(&Settings{AutoRenew: true, UsePanel: true, UseDNS: true, Challenge: ChallengeHTTP})
	m.status = Status{State: "none", Log: []string{}}
	m.loadFromDisk()
	return m
}

func (m *Manager) Settings() Settings { return *m.settings.Load() }

// SetSettings aplica (o certificado atual continua até a próxima emissão).
func (m *Manager) SetSettings(s Settings) error {
	if s.Enabled || len(s.Domains) > 0 {
		if err := s.Validate(); err != nil {
			return err
		}
	}
	m.settings.Store(&s)
	return nil
}

func (m *Manager) CertFile() string { return filepath.Join(m.opts.Dir, "fullchain.pem") }
func (m *Manager) KeyFile() string  { return filepath.Join(m.opts.Dir, "privkey.pem") }

// Active diz se há certificado emitido e ligado.
func (m *Manager) Active() bool {
	return m.settings.Load().Enabled && m.cert.Load() != nil
}

// ForPanel e ForDNS dizem se o certificado vale para cada serviço.
func (m *Manager) ForPanel() bool { return m.Active() && m.settings.Load().UsePanel }
func (m *Manager) ForDNS() bool   { return m.Active() && m.settings.Load().UseDNS }

// Certificate devolve o certificado em uso (nil = nenhum).
func (m *Manager) Certificate() *tls.Certificate { return m.cert.Load() }

// Status devolve o estado atual.
func (m *Manager) Status() Status {
	m.stMu.Lock()
	defer m.stMu.Unlock()
	st := m.status
	st.Log = slices.Clone(st.Log)
	if leaf := m.leaf.Load(); leaf != nil {
		st.Domains = leaf.DNSNames
		st.Issuer = leaf.Issuer.CommonName
		if len(leaf.Issuer.Organization) > 0 {
			st.Issuer = leaf.Issuer.Organization[0] + " " + leaf.Issuer.CommonName
		}
		st.NotBefore, st.NotAfter = leaf.NotBefore, leaf.NotAfter
		st.Staging = strings.Contains(strings.ToUpper(st.Issuer), "STAGING") || strings.Contains(strings.ToLower(st.Issuer), "fake")
		st.CertFile, st.KeyFile = m.CertFile(), m.KeyFile()
		if m.settings.Load().AutoRenew {
			st.NextRenewal = renewAt(leaf)
		}
		if st.State == "none" {
			st.State = "active"
		}
	}
	return st
}

func (m *Manager) step(format string, args ...any) {
	line := time.Now().Format("15:04:05") + "  " + fmt.Sprintf(format, args...)
	m.stMu.Lock()
	m.status.Log = append(m.status.Log, line)
	m.stMu.Unlock()
	m.log.Info("certificado: " + fmt.Sprintf(format, args...))
}

// loadFromDisk pega o certificado emitido antes (partida do serviço).
func (m *Manager) loadFromDisk() {
	c, err := tls.LoadX509KeyPair(m.CertFile(), m.KeyFile())
	if err != nil {
		return
	}
	m.install(&c)
}

func (m *Manager) install(c *tls.Certificate) {
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return
	}
	c.Leaf = leaf
	m.cert.Store(c)
	m.leaf.Store(leaf)
}

// Wrap devolve uma configuração TLS que usa o certificado daqui quando ele
// está ligado para o serviço, e o de base (arquivo, autoassinado) no resto.
// O certificado novo vale na próxima conexão, sem reiniciar.
func (m *Manager) Wrap(base *tls.Config, use func() bool) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if base != nil {
		cfg = base.Clone()
	}
	baseGet := cfg.GetCertificate
	baseCerts := cfg.Certificates
	cfg.Certificates = nil
	cfg.GetCertificate = func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if use() {
			if c := m.cert.Load(); c != nil && (h.ServerName == "" || c.Leaf == nil || c.Leaf.VerifyHostname(h.ServerName) == nil) {
				return c, nil
			}
		}
		if baseGet != nil {
			return baseGet(h)
		}
		if len(baseCerts) > 0 {
			return &baseCerts[0], nil
		}
		if c := m.cert.Load(); c != nil {
			return c, nil
		}
		return nil, errors.New("sem certificado")
	}
	return cfg
}

// Issue emite (ou renova) agora. Bloqueia até terminar.
func (m *Manager) Issue(ctx context.Context) error {
	if !m.mu.TryLock() {
		return errors.New("já há uma emissão em andamento")
	}
	defer m.mu.Unlock()
	s := *m.settings.Load()
	if err := s.Validate(); err != nil {
		return err
	}
	m.stMu.Lock()
	m.status.State, m.status.LastAttempt, m.status.LastError, m.status.Log = "issuing", time.Now(), "", []string{}
	m.stMu.Unlock()
	m.running.Store(true)
	defer m.running.Store(false)

	err := m.issue(ctx, s)
	m.stMu.Lock()
	if err != nil {
		m.status.State, m.status.LastError = "error", err.Error()
	} else {
		m.status.State = "active"
	}
	m.stMu.Unlock()
	if err != nil {
		m.step("falhou: %v", err)
		if m.opts.OnEvent != nil {
			m.opts.OnEvent(false, "Certificado HTTPS não foi emitido", strings.Join(s.Domains, ", ")+": "+err.Error())
		}
		return err
	}
	if m.opts.OnEvent != nil {
		leaf := m.leaf.Load()
		m.opts.OnEvent(true, "Certificado HTTPS emitido", fmt.Sprintf("%s, válido até %s", strings.Join(s.Domains, ", "), leaf.NotAfter.Format("02/01/2006")))
	}
	return nil
}

// Running diz se há emissão em andamento.
func (m *Manager) Running() bool { return m.running.Load() }

// IssueAsync dispara a emissão em segundo plano (o painel acompanha pelo status).
func (m *Manager) IssueAsync() error {
	if m.Running() {
		return errors.New("já há uma emissão em andamento")
	}
	s := *m.settings.Load()
	if err := s.Validate(); err != nil {
		return err
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		_ = m.Issue(ctx)
	}()
	return nil
}

// Run confere a validade a cada hora e renova quando faltar um terço dela
// (se a renovação automática estiver ligada). Desligada, só avisa.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		m.check(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (m *Manager) check(ctx context.Context, now time.Time) {
	s := m.settings.Load()
	leaf := m.leaf.Load()
	if !s.Enabled || leaf == nil {
		return
	}
	left := leaf.NotAfter.Sub(now)
	if now.Before(renewAt(leaf)) {
		return
	}
	if s.AutoRenew {
		// Depois de uma falha, espera 6 horas para tentar de novo (o Let's
		// Encrypt limita as falhas por hora).
		if st := m.Status(); st.State == "error" && now.Sub(st.LastAttempt) < 6*time.Hour {
			return
		}
		ictx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		if err := m.Issue(ictx); err == nil {
			m.log.Info("certificado renovado", "dominios", s.Domains)
		}
		return
	}
	if now.Sub(m.warned) > 24*time.Hour && m.opts.OnEvent != nil {
		m.warned = now
		m.opts.OnEvent(false, "Certificado HTTPS perto de vencer",
			fmt.Sprintf("%s vence em %d dias e a renovação automática está desligada. Renove pelo painel (Certificado HTTPS).",
				strings.Join(leaf.DNSNames, ", "), int(left.Hours()/24)))
	}
}

// Disable deixa de usar o certificado emitido (os arquivos ficam).
func (m *Manager) Disable() {
	s := *m.settings.Load()
	s.Enabled = false
	m.settings.Store(&s)
}

// --- arquivos ---------------------------------------------------------------

func (m *Manager) accountKey() (crypto.Signer, error) {
	p := filepath.Join(m.opts.Dir, "account.key")
	if b, err := os.ReadFile(p); err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, errors.New("account.key ilegível")
		}
		return x509.ParseECPrivateKey(blk.Bytes)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, _ := x509.MarshalECPrivateKey(k)
	if err := os.MkdirAll(m.opts.Dir, 0o700); err != nil {
		return nil, err
	}
	return k, writeFile(p, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
}

// save grava a cadeia e a chave (troca atômica: nunca um par pela metade).
func (m *Manager) save(chain [][]byte, key *ecdsa.PrivateKey) error {
	var certPEM []byte
	for _, c := range chain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})...)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(m.opts.Dir, 0o700); err != nil {
		return err
	}
	if err := writeFile(m.KeyFile(), keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeFile(m.CertFile(), certPEM, 0o644); err != nil {
		return err
	}
	m.install(&c)
	return nil
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func newCSR(domains []string) ([]byte, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: domains[0]}, DNSNames: domains,
	}, key)
	return csr, key, err
}
