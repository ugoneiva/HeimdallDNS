// Package security recebe os alertas das detecções, grava com deduplicação,
// isola dispositivos automaticamente (se configurado) e manda para exportação.
package security

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/clients"
	"github.com/ugoneiva/HeimdallDNS/internal/dnsname"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

// Tipos de alerta.
const (
	KindThreat    = "threat_blocked" // bloqueado por lista de ameaças (malware, phishing, C2)
	KindDGA       = "dga"            // vários nomes aleatórios inexistentes: malware procurando o C2
	KindTunnel    = "dns_tunnel"     // muitos subdomínios longos e únicos: exfiltração/túnel por DNS
	KindNRD       = "nrd"            // domínio registrado há poucos dias
	KindNewDevice = "new_device"     // dispositivo novo na rede
)

// Gravidades (do status palette do painel; nunca só cor).
const (
	SevLow      = "low"
	SevMedium   = "medium"
	SevHigh     = "high"
	SevCritical = "critical"
)

// Kinds lista os tipos na ordem de exibição.
var Kinds = []string{KindThreat, KindDGA, KindTunnel, KindNRD, KindNewDevice}

// Alert é o que uma detecção levanta.
type Alert struct {
	Time     time.Time
	Kind     string
	Severity string
	ClientID string
	ClientIP string
	Domain   string // domínio registrável envolvido (vazio para dispositivo novo)
	Summary  string
	Details  map[string]any
}

// Settings são as opções de segurança, editáveis pelo painel.
type Settings struct {
	DGA         bool     `json:"dga"`
	Tunnel      bool     `json:"tunnel"`
	NRD         bool     `json:"nrd"`
	NRDAction   string   `json:"nrd_action"` // alert ou block
	NRDMaxDays  int      `json:"nrd_max_days"`
	NewDevice   bool     `json:"new_device"`
	AutoIsolate []string `json:"auto_isolate"`   // tipos que isolam o dispositivo na hora
	Ignore      []string `json:"ignore_domains"` // domínios registráveis que as detecções ignoram
}

func (s *Settings) Validate() error {
	var errs []error
	if s.NRDAction != "alert" && s.NRDAction != "block" {
		errs = append(errs, errors.New(`nrd_action: use "alert" ou "block"`))
	}
	if s.NRDMaxDays < 1 || s.NRDMaxDays > 365 {
		errs = append(errs, errors.New("nrd_max_days: entre 1 e 365"))
	}
	for _, k := range s.AutoIsolate {
		if !slices.Contains(Kinds, k) || k == KindNewDevice {
			errs = append(errs, fmt.Errorf("auto_isolate: tipo %q inválido", k))
		}
	}
	for i, d := range s.Ignore {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if d == "" || !strings.Contains(d, ".") {
			errs = append(errs, fmt.Errorf("ignore_domains: %q inválido", s.Ignore[i]))
		}
		s.Ignore[i] = d
	}
	return errors.Join(errs...)
}

// Ignored diz se o nome (ou o domínio registrável dele) está na lista de ignorados.
func (s *Settings) Ignored(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	reg, _ := dnsname.Registrable(name)
	for _, d := range s.Ignore {
		if name == d || reg == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

const (
	settingsKey = "security"
	dedupWindow = time.Hour        // repetições dentro dela somam no mesmo alerta
	reexportGap = 10 * time.Minute // repetições somadas são reexportadas no máximo a cada 10 min
	retention   = 90 * 24 * time.Hour
)

// Exporter recebe cada alerta novo (ou repetido, espaçado) para o SIEM.
type Exporter interface {
	Security(ev store.SecurityEvent, clientName, response string)
}

type Options struct {
	Store    *store.Store
	Clients  *clients.Registry
	Exporter Exporter // nil = sem exportação
	Defaults Settings // usados enquanto o painel não salvar outras
	Logger   *slog.Logger
}

type Manager struct {
	opts     Options
	log      *slog.Logger
	settings atomic.Pointer[Settings]

	mu         sync.Mutex
	lastExport map[int64]time.Time
}

func New(opts Options) (*Manager, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	m := &Manager{opts: opts, log: opts.Logger, lastExport: map[int64]time.Time{}}
	s := opts.Defaults
	if opts.Store != nil {
		if _, err := opts.Store.GetJSON(settingsKey, &s); err != nil {
			return nil, err
		}
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("configurações de segurança: %w", err)
	}
	m.settings.Store(&s)
	return m, nil
}

// Settings devolve as opções em vigor (cópia).
func (m *Manager) Settings() Settings {
	s := *m.settings.Load()
	s.AutoIsolate, s.Ignore = slices.Clone(s.AutoIsolate), slices.Clone(s.Ignore)
	return s
}

// SetSettings valida, grava e aplica.
func (m *Manager) SetSettings(s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if m.opts.Store != nil {
		if err := m.opts.Store.SetJSON(settingsKey, s); err != nil {
			return err
		}
	}
	m.settings.Store(&s)
	return nil
}

// Raise registra o alerta. Repetições (mesmo tipo, dispositivo e domínio em
// 1 hora) somam no alerta existente.
func (m *Manager) Raise(a Alert) {
	s := m.settings.Load()
	if a.Domain != "" && s.Ignored(a.Domain) {
		return
	}
	if a.Time.IsZero() {
		a.Time = time.Now()
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	ev := store.SecurityEvent{
		FirstSeen: a.Time, LastSeen: a.Time, Count: 1, Kind: a.Kind, Severity: a.Severity,
		ClientID: a.ClientID, ClientIP: a.ClientIP, Domain: a.Domain, Summary: a.Summary, Details: a.Details,
	}
	isNew := true
	id, err := m.opts.Store.FindRecentEvent(a.Kind, a.ClientID, a.Domain, a.Time.Add(-dedupWindow))
	if err == nil && id > 0 {
		isNew = false
		ev.ID = id
		err = m.opts.Store.BumpEvent(id, a.Time, a.Details)
	} else if err == nil {
		err = m.opts.Store.InsertEvent(&ev)
	}
	if err != nil {
		m.log.Error("falha ao gravar alerta", "tipo", a.Kind, "erro", err)
		return
	}

	response := "alert"
	if slices.Contains(s.AutoIsolate, a.Kind) && a.ClientID != "" {
		if c, err := m.opts.Clients.Find(a.ClientID); err == nil && !c.Policy().Isolated {
			reason := "Automático: " + a.Summary
			if err := m.opts.Clients.Isolate(c, "", reason, nil); err != nil {
				m.log.Error("isolamento automático falhou", "cliente", a.ClientID, "erro", err)
			} else {
				response = "isolated"
				isNew = true // o isolamento sempre vai para o SIEM
			}
		}
	}
	if isNew {
		m.log.Warn("alerta de segurança", "tipo", a.Kind, "gravidade", a.Severity, "cliente", a.ClientIP,
			"dominio", a.Domain, "resumo", a.Summary, "resposta", response)
	}

	if m.opts.Exporter == nil {
		return
	}
	if !isNew && time.Since(m.lastExport[ev.ID]) < reexportGap {
		return
	}
	m.lastExport[ev.ID] = time.Now()
	if len(m.lastExport) > 10_000 { // não cresce sem limite
		clear(m.lastExport)
	}
	m.opts.Exporter.Security(ev, m.clientName(a.ClientID), response)
}

func (m *Manager) clientName(id string) string {
	if id == "" || m.opts.Clients == nil {
		return ""
	}
	if c, err := m.opts.Clients.Find(id); err == nil {
		return c.Policy().Display
	}
	return ""
}

// ClientName devolve o nome mostrado do dispositivo (para resumos de alerta).
func (m *Manager) ClientName(id, ip string) string {
	if n := m.clientName(id); n != "" {
		return n
	}
	return ip
}

// Purge apaga alertas com mais de 90 dias.
func (m *Manager) Purge() {
	if err := m.opts.Store.PurgeEvents(time.Now().Add(-retention)); err != nil {
		m.log.Error("falha ao limpar alertas antigos", "erro", err)
	}
}
