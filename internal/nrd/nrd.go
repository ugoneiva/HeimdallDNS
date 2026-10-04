// Package nrd descobre a data de registro dos domínios consultados (via RDAP,
// direto no registro de cada TLD) e avisa ou bloqueia os registrados há poucos
// dias, uma marca comum de phishing e de infraestrutura de malware.
package nrd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/dnsname"
	"github.com/ugoneiva/HeimdallDNS/internal/security"
	"github.com/ugoneiva/HeimdallDNS/internal/server"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

// BootstrapURL é o mapa oficial da IANA: qual servidor RDAP atende cada TLD.
const BootstrapURL = "https://data.iana.org/rdap/dns.json"

const (
	bootstrapMaxAge = 7 * 24 * time.Hour
	recheckKnown    = 90 * 24 * time.Hour // data conhecida: só reconsulta depois disso
	recheckUnknown  = 7 * 24 * time.Hour  // sem RDAP ou erro: tenta de novo em 7 dias
	queueSize       = 2000
	perSecond       = 2 // consultas RDAP por segundo, no máximo
	maxBody         = 1 << 20
)

type entry struct {
	registered time.Time // zero = desconhecida
	checked    time.Time
}

type request struct {
	domain string
	ev     server.Event
}

type Options struct {
	Store    *store.Store
	DataDir  string
	Settings func() security.Settings
	Raise    func(security.Alert)
	Name     func(id, ip string) string
	Client   *http.Client
	Logger   *slog.Logger
	Now      func() time.Time
}

type Checker struct {
	opts Options
	log  *slog.Logger

	mu      sync.RWMutex
	known   map[string]entry
	pending map[string]bool
	boot    map[string]string // TLD → URL base do RDAP
	queue   chan request
}

func New(opts Options) (*Checker, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: 10 * time.Second}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Name == nil {
		opts.Name = func(_, ip string) string { return ip }
	}
	c := &Checker{opts: opts, log: opts.Logger, known: map[string]entry{}, pending: map[string]bool{},
		queue: make(chan request, queueSize)}
	if opts.Store != nil {
		rows, err := opts.Store.DomainAges()
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			c.known[r.Domain] = entry{registered: r.Registered, checked: r.Checked}
		}
	}
	return c, nil
}

func (c *Checker) maxAge() time.Duration {
	return time.Duration(c.opts.Settings().NRDMaxDays) * 24 * time.Hour
}

// Age devolve a idade conhecida do domínio registrável do nome.
func (c *Checker) Age(name string) (age time.Duration, known bool) {
	d, ok := dnsname.Registrable(name)
	if !ok {
		return 0, false
	}
	c.mu.RLock()
	e, ok := c.known[d]
	c.mu.RUnlock()
	if !ok || e.registered.IsZero() {
		return 0, false
	}
	return c.opts.Now().Sub(e.registered), true
}

// Block implementa server.NRDBlocker: só bloqueia no modo "block".
func (c *Checker) Block(name string) (string, bool) {
	s := c.opts.Settings()
	if !s.NRD || s.NRDAction != "block" {
		return "", false
	}
	age, ok := c.Age(name)
	if !ok || age >= c.maxAge() {
		return "", false
	}
	return fmt.Sprintf("domínio registrado há %s", days(age)), true
}

func days(d time.Duration) string {
	n := int(d.Hours() / 24)
	if n <= 1 {
		return "menos de 2 dias"
	}
	return fmt.Sprintf("%d dias", n)
}

// Observe recebe uma consulta que resolveu. Se o domínio é novo para nós,
// entra na fila de consulta RDAP; se já sabemos que é jovem, alerta.
func (c *Checker) Observe(e server.Event) {
	d, ok := dnsname.Registrable(e.Name)
	if !ok {
		return
	}
	now := c.opts.Now()
	c.mu.Lock()
	ent, known := c.known[d]
	stale := !known || (ent.registered.IsZero() && now.Sub(ent.checked) > recheckUnknown) ||
		(!ent.registered.IsZero() && now.Sub(ent.checked) > recheckKnown)
	enqueue := stale && !c.pending[d]
	if enqueue {
		c.pending[d] = true
	}
	c.mu.Unlock()

	if known && !ent.registered.IsZero() {
		c.alertIfYoung(d, ent.registered, e)
	}
	if enqueue {
		select {
		case c.queue <- request{domain: d, ev: e}:
		default: // fila cheia: tenta numa próxima consulta
			c.mu.Lock()
			delete(c.pending, d)
			c.mu.Unlock()
		}
	}
}

func (c *Checker) alertIfYoung(domain string, registered time.Time, e server.Event) {
	age := c.opts.Now().Sub(registered)
	if age >= c.maxAge() {
		return
	}
	name := e.Display
	if name == "" {
		name = c.opts.Name(e.ClientID, e.Client.String())
	}
	sev := security.SevMedium
	if age < 7*24*time.Hour {
		sev = security.SevHigh
	}
	action := "liberado (modo alerta)"
	if e.Status == server.StatusBlocked {
		action = "bloqueado"
	}
	c.opts.Raise(security.Alert{
		Time: e.Time, Kind: security.KindNRD, Severity: sev, ClientID: e.ClientID, ClientIP: e.Client.String(),
		Domain:  domain,
		Summary: fmt.Sprintf("%s acessou %s, registrado há %s (%s)", name, domain, days(age), action),
		Details: map[string]any{"name": strings.TrimSuffix(e.Name, "."), "registered": registered.Format(time.DateOnly),
			"age_days": int(age.Hours() / 24)},
	})
}

// Run consulta o RDAP no ritmo permitido até ctx terminar.
func (c *Checker) Run(ctx context.Context) {
	if err := c.loadBootstrap(ctx); err != nil {
		c.log.Warn("mapa RDAP da IANA indisponível; checagem de idade desligada até a próxima tentativa", "erro", err)
	}
	tick := time.NewTicker(time.Second / perSecond)
	defer tick.Stop()
	reboot := time.NewTicker(24 * time.Hour)
	defer reboot.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-reboot.C:
			if err := c.loadBootstrap(ctx); err != nil {
				c.log.Warn("falha ao renovar o mapa RDAP", "erro", err)
			}
		case req := <-c.queue:
			c.lookup(ctx, req)
			select { // respeita o limite de consultas por segundo
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}
}

func (c *Checker) lookup(ctx context.Context, req request) {
	defer func() {
		c.mu.Lock()
		delete(c.pending, req.domain)
		c.mu.Unlock()
	}()
	if !c.opts.Settings().NRD {
		return
	}
	reg, source, err := c.query(ctx, req.domain)
	if err != nil && ctx.Err() != nil {
		return
	}
	if err != nil {
		c.log.Debug("RDAP sem resposta", "dominio", req.domain, "erro", err)
	}
	now := c.opts.Now()
	c.mu.Lock()
	c.known[req.domain] = entry{registered: reg, checked: now}
	c.mu.Unlock()
	if c.opts.Store != nil {
		if err := c.opts.Store.SaveDomainAge(store.DomainAge{Domain: req.domain, Registered: reg, Checked: now, Source: source}); err != nil {
			c.log.Error("falha ao gravar idade do domínio", "erro", err)
		}
	}
	if !reg.IsZero() {
		c.alertIfYoung(req.domain, reg, req.ev)
	}
}

// query pergunta ao servidor RDAP do TLD a data do evento "registration".
func (c *Checker) query(ctx context.Context, domain string) (time.Time, string, error) {
	tld := domain[strings.LastIndexByte(domain, '.')+1:]
	c.mu.RLock()
	base := c.boot[tld]
	c.mu.RUnlock()
	if base == "" {
		return time.Time{}, "", fmt.Errorf("TLD .%s sem servidor RDAP", tld)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"domain/"+domain, nil)
	if err != nil {
		return time.Time{}, "", err
	}
	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", "HeimdallDNS")
	resp, err := c.opts.Client.Do(req)
	if err != nil {
		return time.Time{}, base, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, base, fmt.Errorf("RDAP %s", resp.Status)
	}
	var body struct {
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&body); err != nil {
		return time.Time{}, base, err
	}
	for _, ev := range body.Events {
		if ev.Action == "registration" {
			t, err := time.Parse(time.RFC3339, ev.Date)
			if err != nil {
				return time.Time{}, base, fmt.Errorf("data de registro %q: %w", ev.Date, err)
			}
			return t, base, nil
		}
	}
	return time.Time{}, base, errors.New("resposta RDAP sem data de registro")
}

// loadBootstrap lê o mapa da IANA do disco ou baixa de novo se tiver mais de 7 dias.
func (c *Checker) loadBootstrap(ctx context.Context) error {
	path := filepath.Join(c.opts.DataDir, "rdap-dns.json")
	raw, err := os.ReadFile(path)
	fi, statErr := os.Stat(path)
	if err != nil || statErr != nil || time.Since(fi.ModTime()) > bootstrapMaxAge {
		fresh, derr := c.download(ctx)
		if derr == nil {
			raw = fresh
			_ = os.WriteFile(path, fresh, 0o644)
		} else if err != nil {
			return derr
		}
	}
	m, err := parseBootstrap(raw)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.boot = m
	c.mu.Unlock()
	c.log.Info("mapa RDAP carregado", "tlds", len(m))
	return nil
}

func (c *Checker) download(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, BootstrapURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.opts.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IANA: %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

// parseBootstrap lê o formato da RFC 9224: services = [[[tlds…], [urls…]], …].
func parseBootstrap(raw []byte) (map[string]string, error) {
	var doc struct {
		Services [][][]string `json:"services"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("mapa RDAP: %w", err)
	}
	m := map[string]string{}
	for _, svc := range doc.Services {
		if len(svc) < 2 || len(svc[1]) == 0 {
			continue
		}
		url := svc[1][0]
		for _, u := range svc[1] { // prefere HTTPS
			if strings.HasPrefix(u, "https://") {
				url = u
				break
			}
		}
		if !strings.HasSuffix(url, "/") {
			url += "/"
		}
		for _, tld := range svc[0] {
			m[strings.ToLower(tld)] = url
		}
	}
	if len(m) == 0 {
		return nil, errors.New("mapa RDAP vazio")
	}
	return m, nil
}
