// Package tlsconf monta a configuração TLS do DNS criptografado (DoT/DoH):
// certificado em arquivo (recarregado quando o certbot renova) ou emitido
// automaticamente pelo Let's Encrypt (ACME, desafio TLS-ALPN-01 na porta 443).
package tlsconf

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

type Options struct {
	CertFile, KeyFile string

	ACME     bool
	Email    string
	CacheDir string
	// Host é o nome público (ex.: dns.empresa.com.br). No ACME, recebe
	// certificado ele e "<token>.<Host>" para tokens válidos (DoT por SNI).
	Host       string
	ValidToken func(string) bool
}

// New devolve nil, nil quando não há certificado configurado.
func New(o Options) (*tls.Config, error) {
	switch {
	case o.ACME:
		if o.Host == "" {
			return nil, errors.New("dns.acme precisa de dns.public_host")
		}
		host := strings.ToLower(strings.TrimSuffix(o.Host, "."))
		m := &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache(o.CacheDir),
			Email:  o.Email,
			HostPolicy: func(_ context.Context, name string) error {
				name = strings.ToLower(name)
				if name == host {
					return nil
				}
				label, ok := strings.CutSuffix(name, "."+host)
				if ok && !strings.Contains(label, ".") && o.ValidToken != nil && o.ValidToken(label) {
					return nil
				}
				return fmt.Errorf("nome %q não é atendido por este servidor", name)
			},
		}
		cfg := m.TLSConfig() // inclui o protocolo do desafio acme-tls/1
		cfg.MinVersion = tls.VersionTLS12
		return cfg, nil
	case o.CertFile != "" || o.KeyFile != "":
		r := &reloader{cert: o.CertFile, key: o.KeyFile}
		if _, err := r.load(); err != nil {
			return nil, err
		}
		return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: r.get}, nil
	}
	return nil, nil
}

// reloader relê o certificado quando o arquivo muda (renovação do certbot),
// conferindo no máximo uma vez por minuto.
type reloader struct {
	cert, key string
	mu        sync.Mutex
	current   *tls.Certificate
	modTime   time.Time
	checked   time.Time
}

func (r *reloader) load() (*tls.Certificate, error) {
	c, err := tls.LoadX509KeyPair(r.cert, r.key)
	if err != nil {
		return nil, fmt.Errorf("certificado DoT/DoH: %w", err)
	}
	fi, err := os.Stat(r.cert)
	if err != nil {
		return nil, err
	}
	r.current, r.modTime, r.checked = &c, fi.ModTime(), time.Now()
	return &c, nil
}

func (r *reloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.checked) > time.Minute {
		r.checked = time.Now()
		if fi, err := os.Stat(r.cert); err == nil && fi.ModTime().After(r.modTime) {
			if c, err := r.load(); err == nil {
				return c, nil
			}
			// falhou (renovação pela metade?): segue com o anterior
		}
	}
	return r.current, nil
}
