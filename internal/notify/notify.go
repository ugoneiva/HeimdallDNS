// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

// Package notify avisa as pessoas fora do painel: Telegram, Microsoft Teams,
// e-mail e webhook. Cada canal escolhe os tipos de evento e a gravidade
// mínima; repetições do mesmo evento em pouco tempo viram um aviso só.
package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Tipos de evento (o canal escolhe quais quer).
const (
	EventSecurity  = "security"  // alertas de segurança (ameaça, DGA, túnel, recém-registrado…)
	EventIsolation = "isolation" // dispositivo isolado ou liberado
	EventUpstream  = "upstream"  // upstreams fora do ar e de volta
	EventSystem    = "system"    // backup, listas e outras falhas do serviço
	EventReport    = "report"    // relatório periódico
	EventTest      = "test"      // botão "testar" do painel
)

// Events lista os tipos na ordem do painel (teste fica de fora).
var Events = []string{EventSecurity, EventIsolation, EventUpstream, EventSystem, EventReport}

// Gravidades, as mesmas dos alertas de segurança.
const (
	SevLow      = "low"
	SevMedium   = "medium"
	SevHigh     = "high"
	SevCritical = "critical"
)

var sevRank = map[string]int{SevLow: 0, SevMedium: 1, SevHigh: 2, SevCritical: 3}

// Event é um aviso.
type Event struct {
	Type     string
	Severity string
	Title    string
	Text     string
	Fields   [][2]string // pares nome/valor, na ordem
	Link     string      // endereço do painel, se conhecido
	Time     time.Time
	// Key agrupa as repetições (ex.: tipo|aparelho|domínio). Vazio = Title.
	Key string
	// Attachment vai junto no e-mail (relatório em PDF); os outros canais
	// recebem só o texto.
	Attachment *Attachment
}

// Attachment é um arquivo anexado ao e-mail.
type Attachment struct {
	Name string
	Type string
	Data []byte
}

// Tipos de canal.
const (
	TypeTelegram = "telegram"
	TypeTeams    = "teams"
	TypeEmail    = "email"
	TypeWebhook  = "webhook"
)

// Channel é um destino. Os segredos (token do bot, segredo do webhook) ficam
// no banco e nunca voltam inteiros para o painel.
type Channel struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Enabled     bool     `json:"enabled"`
	Events      []string `json:"events"`       // vazio = todos
	MinSeverity string   `json:"min_severity"` // filtra os alertas de segurança

	// Telegram
	BotToken string `json:"bot_token,omitempty"`
	ChatID   string `json:"chat_id,omitempty"`
	// Teams (fluxo "Post to a channel when a webhook request is received") e webhook genérico
	URL string `json:"url,omitempty"`
	// Webhook: segredo do HMAC-SHA256 (cabeçalho X-Heimdall-Signature)
	Secret string `json:"secret,omitempty"`
	// E-mail
	To []string `json:"to,omitempty"`
}

// SMTP é o servidor de e-mail (um para todos os canais de e-mail).
type SMTP struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`               // 587 (STARTTLS), 465 (TLS) ou 25
	Security string `json:"security"`           // starttls, tls ou none
	Username string `json:"username,omitempty"` // vazio = sem autenticação
	Password string `json:"password,omitempty"`
	From     string `json:"from"`
}

// Settings é tudo o que o painel edita.
type Settings struct {
	Channels []Channel `json:"channels"`
	SMTP     SMTP      `json:"smtp"`
	// PanelURL vai nos avisos como link (ex.: https://heimdall.empresa.local:8080).
	PanelURL string `json:"panel_url,omitempty"`
}

// Delivery é o resultado de um envio (os últimos aparecem no painel).
type Delivery struct {
	Time    time.Time `json:"time"`
	Channel string    `json:"channel"`
	Name    string    `json:"name"`
	Type    string    `json:"type"`
	Title   string    `json:"title"`
	OK      bool      `json:"ok"`
	Error   string    `json:"error,omitempty"`
	// Suppressed conta as repetições juntadas neste aviso.
	Suppressed int `json:"suppressed,omitempty"`
}

// Options do gerenciador.
type Options struct {
	Node   string // nome deste servidor, no rodapé dos avisos
	Logger *slog.Logger
	// Dedup é a janela em que o mesmo evento vira um aviso só (padrão 10 min).
	Dedup time.Duration
	// HTTP e TelegramAPI existem para os testes.
	HTTP        *http.Client
	TelegramAPI string
}

// Manager guarda os canais e envia em segundo plano.
type Manager struct {
	opts     Options
	log      *slog.Logger
	settings atomic.Pointer[Settings]
	queue    chan Event

	mu     sync.Mutex
	recent map[string]*seen // canal|chave → último envio
	hist   []Delivery
}

type seen struct {
	at         time.Time
	suppressed int
}

const (
	queueSize = 256
	histSize  = 50
)

func New(opts Options) *Manager {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Dedup <= 0 {
		opts.Dedup = 10 * time.Minute
	}
	if opts.HTTP == nil {
		opts.HTTP = &http.Client{Timeout: 15 * time.Second}
	}
	if opts.TelegramAPI == "" {
		opts.TelegramAPI = "https://api.telegram.org"
	}
	m := &Manager{opts: opts, log: opts.Logger, queue: make(chan Event, queueSize), recent: map[string]*seen{}}
	m.settings.Store(&Settings{Channels: []Channel{}})
	return m
}

// Settings devolve a configuração em uso (com os segredos).
func (m *Manager) Settings() Settings {
	s := *m.settings.Load()
	s.Channels = slices.Clone(s.Channels)
	if s.Channels == nil {
		s.Channels = []Channel{}
	}
	return s
}

// SetSettings confere e aplica.
func (m *Manager) SetSettings(s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	m.settings.Store(&s)
	return nil
}

// Validate confere os canais.
func (s *Settings) Validate() error {
	ids := map[string]bool{}
	email := false
	if s.Channels == nil {
		s.Channels = []Channel{}
	}
	for i := range s.Channels {
		c := &s.Channels[i]
		c.Name = strings.TrimSpace(c.Name)
		if c.ID == "" || ids[c.ID] {
			return fmt.Errorf("canal %q sem identificador único", c.Name)
		}
		ids[c.ID] = true
		if c.Name == "" {
			return errors.New("dê um nome ao canal")
		}
		if c.MinSeverity == "" {
			c.MinSeverity = SevMedium
		}
		if _, ok := sevRank[c.MinSeverity]; !ok {
			return fmt.Errorf("%s: gravidade %q (use low, medium, high ou critical)", c.Name, c.MinSeverity)
		}
		for _, e := range c.Events {
			if !slices.Contains(Events, e) {
				return fmt.Errorf("%s: tipo de evento %q desconhecido", c.Name, e)
			}
		}
		switch c.Type {
		case TypeTelegram:
			if c.BotToken == "" || strings.TrimSpace(c.ChatID) == "" {
				return fmt.Errorf("%s: informe o token do bot e o chat", c.Name)
			}
		case TypeTeams, TypeWebhook:
			if !strings.HasPrefix(c.URL, "https://") && !strings.HasPrefix(c.URL, "http://") {
				return fmt.Errorf("%s: endereço do webhook inválido", c.Name)
			}
		case TypeEmail:
			if len(c.To) == 0 {
				return fmt.Errorf("%s: informe ao menos um destinatário", c.Name)
			}
			for _, to := range c.To {
				if !validEmail(to) {
					return fmt.Errorf("%s: e-mail %q inválido", c.Name, to)
				}
			}
			email = email || c.Enabled
		default:
			return fmt.Errorf("%s: tipo %q (use telegram, teams, email ou webhook)", c.Name, c.Type)
		}
	}
	if email || s.SMTP.Host != "" {
		if err := s.SMTP.validate(); err != nil {
			return err
		}
	}
	return nil
}

func validEmail(s string) bool {
	at := strings.LastIndexByte(s, '@')
	return at > 0 && at < len(s)-3 && strings.Contains(s[at:], ".") && !strings.ContainsAny(s, " \r\n<>,;")
}

// Wants diz se o canal quer o evento.
func (c Channel) Wants(e Event) bool {
	if !c.Enabled && e.Type != EventTest {
		return false
	}
	if e.Type == EventTest {
		return true
	}
	if len(c.Events) > 0 && !slices.Contains(c.Events, e.Type) {
		return false
	}
	// A gravidade mínima filtra os alertas de segurança (que vêm em volume);
	// os outros tipos são poucos e sempre importam a quem os escolheu.
	return e.Type != EventSecurity || sevRank[e.Severity] >= sevRank[c.MinSeverity]
}

// Send põe o aviso na fila (não bloqueia; com a fila cheia o aviso se perde
// e fica no log). Seguro com Manager nil.
func (m *Manager) Send(e Event) {
	if m == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	if e.Severity == "" {
		e.Severity = SevMedium
	}
	select {
	case m.queue <- e:
	default:
		m.log.Warn("fila de notificações cheia; aviso descartado", "titulo", e.Title)
	}
}

// Run entrega a fila até o contexto acabar.
func (m *Manager) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-m.queue:
			m.dispatch(ctx, e, "")
		}
	}
}

// Test envia um aviso de teste para um canal agora e devolve o erro.
func (m *Manager) Test(ctx context.Context, channelID string) error {
	e := Event{Type: EventTest, Severity: SevLow, Title: "Teste do HeimdallDNS",
		Text: "Se você está lendo isto, o canal está funcionando.", Time: time.Now()}
	ds := m.dispatch(ctx, e, channelID)
	if len(ds) == 0 {
		return errors.New("canal não encontrado")
	}
	if !ds[0].OK {
		return errors.New(ds[0].Error)
	}
	return nil
}

// dispatch entrega para os canais que querem o evento (ou só para um).
func (m *Manager) dispatch(ctx context.Context, e Event, only string) []Delivery {
	s := m.settings.Load()
	if e.Link == "" {
		e.Link = s.PanelURL
	}
	var out []Delivery
	for _, c := range s.Channels {
		if only != "" && c.ID != only {
			continue
		}
		if only == "" && !c.Wants(e) {
			continue
		}
		suppressed, skip := m.dedup(c.ID, e)
		if skip {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := m.deliver(cctx, c, s.SMTP, e, suppressed)
		cancel()
		d := Delivery{Time: time.Now(), Channel: c.ID, Name: c.Name, Type: c.Type, Title: e.Title, OK: err == nil, Suppressed: suppressed}
		if err != nil {
			d.Error = redact(err.Error(), c)
			m.log.Warn("notificação não enviada", "canal", c.Name, "tipo", c.Type, "erro", d.Error)
		}
		m.record(d)
		out = append(out, d)
	}
	return out
}

// dedup: o mesmo evento no mesmo canal dentro da janela não sai de novo;
// o próximo aviso depois da janela diz quantos foram juntados.
func (m *Manager) dedup(channel string, e Event) (suppressed int, skip bool) {
	if e.Type == EventTest || e.Type == EventReport {
		return 0, false
	}
	key := e.Key
	if key == "" {
		key = e.Type + "|" + e.Title
	}
	k := channel + "|" + key
	m.mu.Lock()
	defer m.mu.Unlock()
	now := e.Time
	if r, ok := m.recent[k]; ok && now.Sub(r.at) < m.opts.Dedup {
		r.suppressed++
		return 0, true
	} else if ok {
		suppressed = r.suppressed
	}
	m.recent[k] = &seen{at: now}
	if len(m.recent) > 5000 {
		for kk, r := range m.recent {
			if now.Sub(r.at) > m.opts.Dedup {
				delete(m.recent, kk)
			}
		}
	}
	return suppressed, false
}

func (m *Manager) record(d Delivery) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hist = append(m.hist, d)
	if len(m.hist) > histSize {
		m.hist = m.hist[len(m.hist)-histSize:]
	}
}

// History devolve os últimos envios, mais recentes primeiro.
func (m *Manager) History() []Delivery {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := slices.Clone(m.hist)
	slices.Reverse(out)
	if out == nil {
		out = []Delivery{}
	}
	return out
}

func (m *Manager) deliver(ctx context.Context, c Channel, smtp SMTP, e Event, suppressed int) error {
	switch c.Type {
	case TypeTelegram:
		return m.telegram(ctx, c, e, suppressed)
	case TypeTeams:
		return m.teams(ctx, c, e, suppressed)
	case TypeWebhook:
		return m.webhook(ctx, c, e, suppressed)
	case TypeEmail:
		return m.email(ctx, smtp, c, e, suppressed)
	}
	return fmt.Errorf("tipo %q", c.Type)
}

// redact tira os segredos de mensagens de erro (a URL do Telegram leva o token).
func redact(msg string, c Channel) string {
	for _, s := range []string{c.BotToken, c.Secret} {
		if len(s) > 4 {
			msg = strings.ReplaceAll(msg, s, "***")
		}
	}
	if c.Type == TypeTeams && c.URL != "" {
		msg = strings.ReplaceAll(msg, c.URL, "<webhook do Teams>")
	}
	return msg
}

// SevLabel é o nome da gravidade em português, para as mensagens.
func SevLabel(s string) string {
	switch s {
	case SevCritical:
		return "Crítica"
	case SevHigh:
		return "Alta"
	case SevMedium:
		return "Média"
	}
	return "Baixa"
}

func (m *Manager) footer(e Event) string {
	f := e.Time.Format("02/01/2006 15:04:05")
	if m.opts.Node != "" {
		f += " · " + m.opts.Node
	}
	return f
}
