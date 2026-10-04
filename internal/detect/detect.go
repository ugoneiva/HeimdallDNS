// Package detect procura sinais de comprometimento no tráfego DNS: DGA
// (malware procurando o servidor de comando), túnel DNS (exfiltração) e
// acessos bloqueados por listas de ameaças.
package detect

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/ugoneiva/HeimdallDNS/internal/dnsname"
	"github.com/ugoneiva/HeimdallDNS/internal/filter"
	"github.com/ugoneiva/HeimdallDNS/internal/security"
	"github.com/ugoneiva/HeimdallDNS/internal/server"
)

const (
	dgaWindow    = 10 * time.Minute
	dgaMinNames  = 10 // nomes suspeitos inexistentes, distintos, na janela
	tunWindow    = 5 * time.Minute
	tunMinUnique = 50 // subdomínios distintos sob o mesmo domínio, na janela
	tunMinAvgLen = 20 // tamanho médio desses subdomínios
	tunMinTXT    = 40 // ou: consultas TXT/NULL ao mesmo domínio na janela
	maxTracked   = 300
	examples     = 5
	inBuffer     = 50_000
)

// TunnelIgnore são domínios que legitimamente consultam muitos subdomínios
// únicos e longos: CDNs, nuvens e serviços de reputação por DNS (antivírus,
// listas de spam). Somam-se aos ignorados das configurações.
var TunnelIgnore = []string{
	"cloudfront.net", "amazonaws.com", "akamaiedge.net", "akamaized.net", "akamai.net", "edgekey.net",
	"googlevideo.com", "gvt1.com", "fbcdn.net", "azureedge.net", "windows.net", "trafficmanager.net",
	"cloudflare.net", "fastly.net", "apple-dns.net", "aaplimg.com",
	"spamhaus.org", "spamcop.net", "sorbs.net", "barracudacentral.org", "surbl.org", "uribl.com",
	"sophosxl.net", "e5.sk", "mcafee.com", "trendmicro.com", "kaspersky-labs.com", "bitdefender.net",
}

// NRDChecker recebe os domínios que resolveram, para checar a idade.
type NRDChecker interface {
	Observe(e server.Event)
}

type Options struct {
	Settings func() security.Settings
	Raise    func(security.Alert)
	Name     func(id, ip string) string // nome do dispositivo para o resumo
	NRD      NRDChecker                 // nil = sem checagem de idade
	Logger   *slog.Logger
}

type dgaState struct {
	start time.Time
	names map[string]bool
	ip    string
	fired bool
}

type tunState struct {
	start   time.Time
	subs    map[string]bool
	sumLen  int
	txt     int
	queries int
	ip      string
	fired   bool
	samples []string
}

type Detector struct {
	opts    Options
	in      chan server.Event
	dropped atomic.Uint64
	dga     map[string]*dgaState // por dispositivo
	tun     map[string]*tunState // por dispositivo + domínio registrável
}

func New(opts Options) *Detector {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Name == nil {
		opts.Name = func(_, ip string) string { return ip }
	}
	return &Detector{
		opts: opts, in: make(chan server.Event, inBuffer),
		dga: map[string]*dgaState{}, tun: map[string]*tunState{},
	}
}

// Observe recebe a consulta (OnQuery do servidor). Nunca bloqueia.
func (d *Detector) Observe(e server.Event) {
	select {
	case d.in <- e:
	default:
		d.dropped.Add(1)
	}
}

func (d *Detector) Run(ctx context.Context) {
	gc := time.NewTicker(time.Minute)
	defer gc.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-d.in:
			d.process(e)
		case now := <-gc.C:
			d.expire(now)
		}
	}
}

func clientKey(e *server.Event) string {
	if e.ClientID != "" {
		return e.ClientID
	}
	return e.Client.String()
}

func (d *Detector) process(e server.Event) {
	switch e.Status {
	case server.StatusRefused, server.StatusInvalid, server.StatusLocal, server.StatusIsolated:
		return
	}
	s := d.opts.Settings()
	name := strings.TrimSuffix(e.Name, ".")
	if s.Ignored(name) {
		return
	}
	domain, label, sub, ok := dnsname.Split(name)

	if e.Status == server.StatusBlocked && e.Category == filter.CategoryThreat {
		if !ok { // TLD fora da Public Suffix List: o alerta usa o nome inteiro
			domain = name
		}
		d.raise(e, security.Alert{
			Kind: security.KindThreat, Severity: security.SevHigh, Domain: domain,
			Summary: fmt.Sprintf("%s tentou acessar %s, bloqueado por lista de ameaças", d.name(e), name),
			Details: map[string]any{"name": name, "rule": e.Rule, "qtype": e.Type},
		})
		return
	}
	if !ok {
		return
	}

	if s.DGA && e.Rcode == "NXDOMAIN" && LooksGenerated(label) {
		d.trackDGA(e, domain, label)
	}
	if s.Tunnel && sub != "" && !ignoredTunnel(domain) {
		d.trackTunnel(e, domain, sub)
	}
	if s.NRD && d.opts.NRD != nil && e.Rcode == "NOERROR" &&
		(e.Status == server.StatusForwarded || e.Status == server.StatusCached) {
		d.opts.NRD.Observe(e)
	}
}

func ignoredTunnel(domain string) bool { return slices.Contains(TunnelIgnore, domain) }

func (d *Detector) name(e server.Event) string {
	if e.Display != "" {
		return e.Display
	}
	return d.opts.Name(e.ClientID, e.Client.String())
}

func (d *Detector) raise(e server.Event, a security.Alert) {
	a.Time, a.ClientID, a.ClientIP = e.Time, e.ClientID, e.Client.String()
	d.opts.Raise(a)
}

func (d *Detector) trackDGA(e server.Event, domain, label string) {
	k := clientKey(&e)
	st := d.dga[k]
	if st == nil || e.Time.Sub(st.start) > dgaWindow {
		st = &dgaState{start: e.Time, names: map[string]bool{}, ip: e.Client.String()}
		d.dga[k] = st
	}
	if len(st.names) < maxTracked {
		st.names[domain] = true
	}
	if st.fired || len(st.names) < dgaMinNames {
		return
	}
	st.fired = true // um alerta por janela
	sample := make([]string, 0, examples)
	for n := range st.names {
		if len(sample) == examples {
			break
		}
		sample = append(sample, n)
	}
	slices.Sort(sample)
	d.raise(e, security.Alert{
		Kind: security.KindDGA, Severity: security.SevHigh,
		Summary: fmt.Sprintf("%s consultou %d domínios com cara de gerados por algoritmo que não existem, em %s: comportamento de malware procurando o servidor de comando",
			d.name(e), len(st.names), dgaWindow),
		Details: map[string]any{"distinct": len(st.names), "examples": sample, "window": dgaWindow.String(), "last_score": DGAScore(label)},
	})
}

func (d *Detector) trackTunnel(e server.Event, domain, sub string) {
	k := clientKey(&e) + "|" + domain
	st := d.tun[k]
	if st == nil || e.Time.Sub(st.start) > tunWindow {
		if len(d.tun) > 20_000 { // muita coisa distinta: recomeça em vez de crescer
			clear(d.tun)
		}
		st = &tunState{start: e.Time, subs: map[string]bool{}, ip: e.Client.String()}
		d.tun[k] = st
	}
	st.queries++
	if e.Type == "TXT" || e.Type == "NULL" || e.Type == dns.TypeToString[dns.TypeANY] {
		st.txt++
	}
	if !st.subs[sub] && len(st.subs) < maxTracked {
		st.subs[sub] = true
		st.sumLen += len(sub)
		if len(st.samples) < examples {
			st.samples = append(st.samples, sub+"."+domain)
		}
	}
	if st.fired {
		return
	}
	unique := len(st.subs)
	avg := 0
	if unique > 0 {
		avg = st.sumLen / unique
	}
	byNames := unique >= tunMinUnique && avg >= tunMinAvgLen
	byTXT := st.txt >= tunMinTXT && unique >= tunMinUnique/2
	if !byNames && !byTXT {
		return
	}
	st.fired = true
	sev := security.SevHigh
	if byNames && byTXT {
		sev = security.SevCritical
	}
	d.raise(e, security.Alert{
		Kind: security.KindTunnel, Severity: sev, Domain: domain,
		Summary: fmt.Sprintf("%s fez %d consultas a %d subdomínios únicos de %s (média de %d caracteres, %d TXT) em %s: possível túnel ou exfiltração por DNS",
			d.name(e), st.queries, unique, domain, avg, st.txt, tunWindow),
		Details: map[string]any{"unique_subdomains": unique, "avg_length": avg, "txt_queries": st.txt,
			"queries": st.queries, "examples": st.samples, "window": tunWindow.String()},
	})
}

// expire descarta janelas vencidas, para a memória não crescer.
func (d *Detector) expire(now time.Time) {
	for k, st := range d.dga {
		if now.Sub(st.start) > dgaWindow {
			delete(d.dga, k)
		}
	}
	for k, st := range d.tun {
		if now.Sub(st.start) > tunWindow {
			delete(d.tun, k)
		}
	}
}

// Dropped conta consultas que o detector não conseguiu analisar (fila cheia).
func (d *Detector) Dropped() uint64 { return d.dropped.Load() }
