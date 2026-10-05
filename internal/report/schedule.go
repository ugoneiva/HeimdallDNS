// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package report

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Frequências do relatório automático.
const (
	FreqWeekly  = "weekly"
	FreqMonthly = "monthly"
)

// Settings do relatório automático (editáveis no painel).
type Settings struct {
	Enabled   bool   `json:"enabled"`
	Frequency string `json:"frequency"` // weekly (segunda-feira, semana anterior) ou monthly (dia 1, mês anterior)
	Hour      int    `json:"hour"`      // hora local do envio (0–23)
	Keep      int    `json:"keep"`      // quantos PDFs guardar (padrão 24)
}

func (s *Settings) Validate() error {
	if s.Frequency == "" {
		s.Frequency = FreqWeekly
	}
	if s.Frequency != FreqWeekly && s.Frequency != FreqMonthly {
		return fmt.Errorf("frequência %q (use weekly ou monthly)", s.Frequency)
	}
	if s.Hour < 0 || s.Hour > 23 {
		return errors.New("hora entre 0 e 23")
	}
	if s.Keep <= 0 {
		s.Keep = 24
	}
	s.Keep = min(s.Keep, 500)
	return nil
}

// Saved é um relatório guardado no disco.
type Saved struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	Created time.Time `json:"created"`
}

// Options do agendador.
type Options struct {
	Source Source
	Dir    string // onde guardar os PDFs (<data_dir>/reports)
	// Deliver entrega o relatório pronto (notificações: e-mail com o PDF).
	Deliver func(d *Data, pdf []byte, name string)
	// LastRun e SetLastRun guardam o fim do último período enviado, para não
	// repetir depois de reiniciar.
	LastRun    func() time.Time
	SetLastRun func(time.Time)
	Logger     *slog.Logger
}

// Scheduler gera e envia o relatório na hora marcada.
type Scheduler struct {
	opts     Options
	log      *slog.Logger
	settings atomic.Pointer[Settings]
	mu       sync.Mutex // um relatório de cada vez
}

func NewScheduler(opts Options) *Scheduler {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	s := &Scheduler{opts: opts, log: opts.Logger}
	def := Settings{Frequency: FreqWeekly, Hour: 7, Keep: 24}
	s.settings.Store(&def)
	return s
}

func (s *Scheduler) Settings() Settings { return *s.settings.Load() }

func (s *Scheduler) SetSettings(st Settings) error {
	if err := st.Validate(); err != nil {
		return err
	}
	s.settings.Store(&st)
	return nil
}

// Title do relatório de um período.
func Title(freq string) string {
	if freq == FreqMonthly {
		return "Relatório mensal"
	}
	return "Relatório semanal"
}

// Generate monta o PDF de [from, to) e guarda no disco.
func (s *Scheduler) Generate(from, to time.Time, title string) (*Data, []byte, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := Collect(s.opts.Source, from, to)
	if err != nil {
		return nil, nil, "", err
	}
	d.Title = title
	pdf, err := Render(d)
	if err != nil {
		return nil, nil, "", err
	}
	name := fmt.Sprintf("heimdalldns-relatorio-%s-a-%s.pdf", from.Format("2006-01-02"), to.Add(-time.Second).Format("2006-01-02"))
	if s.opts.Dir != "" {
		if err := os.MkdirAll(s.opts.Dir, 0o750); err != nil {
			return nil, nil, "", err
		}
		if err := os.WriteFile(filepath.Join(s.opts.Dir, name), pdf, 0o640); err != nil {
			return nil, nil, "", err
		}
		s.prune()
	}
	return d, pdf, name, nil
}

var savedName = regexp.MustCompile(`^heimdalldns-relatorio-[0-9a-z-]+\.pdf$`)

// List devolve os relatórios guardados, mais novos primeiro.
func (s *Scheduler) List() []Saved {
	out := []Saved{}
	es, _ := os.ReadDir(s.opts.Dir)
	for _, e := range es {
		if !savedName.MatchString(e.Name()) {
			continue
		}
		if fi, err := e.Info(); err == nil {
			out = append(out, Saved{Name: e.Name(), Size: fi.Size(), Created: fi.ModTime()})
		}
	}
	slices.SortFunc(out, func(a, b Saved) int { return b.Created.Compare(a.Created) })
	return out
}

// Path devolve o caminho de um relatório guardado (só nomes válidos).
func (s *Scheduler) Path(name string) (string, bool) {
	if !savedName.MatchString(name) || strings.Contains(name, "..") {
		return "", false
	}
	p := filepath.Join(s.opts.Dir, name)
	_, err := os.Stat(p)
	return p, err == nil
}

func (s *Scheduler) prune() {
	keep := s.settings.Load().Keep
	list := s.List()
	for _, r := range list[min(len(list), keep):] {
		os.Remove(filepath.Join(s.opts.Dir, r.Name))
	}
}

// Due diz se o último período fechado já pode ser enviado (depois da hora
// marcada) e ainda não foi. Na primeira vez só marca o período atual: ligar
// o relatório não manda na hora um resumo velho.
func (s *Scheduler) Due(now time.Time) (from, to time.Time, ok bool) {
	st := s.settings.Load()
	if !st.Enabled {
		return
	}
	from, to = Period(st.Frequency, now)
	var last time.Time
	if s.opts.LastRun != nil {
		last = s.opts.LastRun()
	}
	if last.IsZero() {
		if s.opts.SetLastRun != nil {
			s.opts.SetLastRun(to)
		}
		return from, to, false
	}
	send := to.Add(time.Duration(st.Hour) * time.Hour)
	return from, to, to.After(last) && !now.Before(send)
}

// Run confere a cada 10 minutos se é hora de mandar.
func (s *Scheduler) Run(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		s.tick(time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Scheduler) tick(now time.Time) {
	from, to, ok := s.Due(now)
	if !ok {
		return
	}
	// Marca antes de enviar: uma falha não vira um envio a cada 10 minutos.
	if s.opts.SetLastRun != nil {
		s.opts.SetLastRun(to)
	}
	d, pdf, name, err := s.Generate(from, to, Title(s.settings.Load().Frequency))
	if err != nil {
		s.log.Error("relatório periódico falhou", "erro", err)
		return
	}
	s.log.Info("relatório periódico gerado", "arquivo", name)
	if s.opts.Deliver != nil {
		s.opts.Deliver(d, pdf, name)
	}
}

// SendNow gera o relatório do último período fechado e entrega já.
func (s *Scheduler) SendNow() (string, error) {
	freq := s.settings.Load().Frequency
	from, to := Period(freq, time.Now())
	d, pdf, name, err := s.Generate(from, to, Title(freq))
	if err != nil {
		return "", err
	}
	if s.opts.Deliver != nil {
		s.opts.Deliver(d, pdf, name)
	}
	return name, nil
}

// Summary resume o relatório em texto, para os canais sem anexo.
func Summary(d *Data) (text string, fields [][2]string) {
	period := d.From.Format("02/01/2006") + " a " + d.To.Add(-time.Second).Format("02/01/2006")
	text = "Resumo do período " + period + ". O PDF completo vai anexo no e-mail e fica no painel (Configurações → Relatórios)."
	fields = [][2]string{
		{"Consultas", num(d.Total)},
		{"Bloqueadas", num(d.Blocked+d.Isolated) + " (" + pct(d.Blocked+d.Isolated, d.Total) + ")"},
		{"Dispositivos ativos", num(int64(d.Devices))},
		{"Alertas", fmt.Sprintf("%d (%d críticos/altos)", d.AlertTotal, d.AlertsBy["critical"]+d.AlertsBy["high"])},
	}
	if len(d.TopBlocked) > 0 {
		fields = append(fields, [2]string{"Mais bloqueado", d.TopBlocked[0].Key})
	}
	return text, fields
}
