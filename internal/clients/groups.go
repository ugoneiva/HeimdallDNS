// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package clients

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/filter"
)

// Group reúne dispositivos com a mesma política: regras próprias e horários.
// Precedência numa consulta: regras do próprio aparelho, depois os horários
// ativos do grupo, depois as regras do grupo, por fim as listas globais.
type Group struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Description     string     `json:"description,omitempty"`
	Allow           []string   `json:"allow,omitempty"`
	Deny            []string   `json:"deny,omitempty"`
	SkipGlobalLists bool       `json:"skip_global_lists,omitempty"`
	Schedules       []Schedule `json:"schedules,omitempty"`
}

// Schedule é uma janela de horário com regras extras. Se End vier antes de
// Start, a janela passa da meia-noite (ex.: 22:00 a 07:00). Start igual a
// End vale o dia inteiro.
type Schedule struct {
	Name     string   `json:"name"`
	Days     []int    `json:"days,omitempty"` // 0 = domingo … 6 = sábado; vazio = todos
	Start    string   `json:"start"`          // "HH:MM"
	End      string   `json:"end"`            // "HH:MM"
	BlockAll bool     `json:"block_all,omitempty"`
	Allow    []string `json:"allow,omitempty"`
	Deny     []string `json:"deny,omitempty"`
	Disabled bool     `json:"disabled,omitempty"`
}

type compiledSchedule struct {
	name       string
	days       [7]bool
	start, end int // minutos desde a meia-noite
	blockAll   bool
	rules      *filter.Matcher
}

// active diz se a janela vale no instante t (no fuso local do servidor).
func (s *compiledSchedule) active(t time.Time) bool {
	m := t.Hour()*60 + t.Minute()
	wd := int(t.Weekday())
	switch {
	case s.start == s.end:
		return s.days[wd]
	case s.start < s.end:
		return s.days[wd] && m >= s.start && m < s.end
	}
	// Passa da meia-noite: a parte da noite pertence ao dia em que começou.
	return (s.days[wd] && m >= s.start) || (s.days[(wd+6)%7] && m < s.end)
}

type compiledGroup struct {
	Group
	rules     *filter.Matcher
	schedules []*compiledSchedule
}

type groupSet struct {
	list []Group
	byID map[string]*compiledGroup
}

func parseClock(s string) (int, error) {
	h, m, ok := strings.Cut(strings.TrimSpace(s), ":")
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if !ok || err1 != nil || err2 != nil || hh < 0 || hh > 23 || mm < 0 || mm > 59 {
		return 0, fmt.Errorf("horário %q: use HH:MM", s)
	}
	return hh*60 + mm, nil
}

func compileGroups(gs []Group) (*groupSet, error) {
	set := &groupSet{list: slices.Clone(gs), byID: map[string]*compiledGroup{}}
	for _, g := range gs {
		if g.ID == "" || strings.TrimSpace(g.Name) == "" {
			return nil, errors.New("todo grupo precisa de id e nome")
		}
		if _, dup := set.byID[g.ID]; dup {
			return nil, fmt.Errorf("grupo %q repetido", g.ID)
		}
		cg := &compiledGroup{Group: g}
		var bad []string
		cg.rules, bad = filter.CompileUserRules(g.Allow, g.Deny)
		if len(bad) > 0 {
			return nil, fmt.Errorf("grupo %s: regras inválidas: %s", g.Name, strings.Join(bad, ", "))
		}
		for _, s := range g.Schedules {
			if s.Disabled {
				continue
			}
			cs := &compiledSchedule{name: s.Name, blockAll: s.BlockAll}
			var err error
			if cs.start, err = parseClock(s.Start); err != nil {
				return nil, fmt.Errorf("grupo %s, horário %s: %w", g.Name, s.Name, err)
			}
			if cs.end, err = parseClock(s.End); err != nil {
				return nil, fmt.Errorf("grupo %s, horário %s: %w", g.Name, s.Name, err)
			}
			if len(s.Days) == 0 {
				cs.days = [7]bool{true, true, true, true, true, true, true}
			}
			for _, d := range s.Days {
				if d < 0 || d > 6 {
					return nil, fmt.Errorf("grupo %s, horário %s: dia %d (use 0 a 6)", g.Name, s.Name, d)
				}
				cs.days[d] = true
			}
			if !s.BlockAll && len(s.Allow)+len(s.Deny) == 0 {
				return nil, fmt.Errorf("grupo %s, horário %s: informe o que bloquear ou marque a pausa total", g.Name, s.Name)
			}
			cs.rules, bad = filter.CompileUserRules(s.Allow, s.Deny)
			if len(bad) > 0 {
				return nil, fmt.Errorf("grupo %s, horário %s: regras inválidas: %s", g.Name, s.Name, strings.Join(bad, ", "))
			}
			cg.schedules = append(cg.schedules, cs)
		}
		set.byID[g.ID] = cg
	}
	return set, nil
}

// matchGroup aplica os horários ativos e depois as regras do grupo.
func (g *compiledGroup) match(name string, now time.Time) filter.Result {
	for _, s := range g.schedules {
		if !s.active(now) {
			continue
		}
		res := s.rules.Match(name)
		switch {
		case res.Verdict != filter.Pass:
			res.Rule = "horário " + s.name + ": " + res.Rule
			return res
		case s.blockAll:
			return filter.Result{Verdict: filter.Blocked, Rule: "horário " + s.name + ": pausa"}
		}
	}
	res := g.rules.Match(name)
	if res.Verdict != filter.Pass {
		res.Rule = "grupo " + g.Name + ": " + res.Rule
	}
	return res
}

// ActiveSchedules lista as janelas que valem agora no grupo (para o painel).
func (r *Registry) ActiveSchedules(groupID string) []string {
	g := r.groups.Load().byID[groupID]
	if g == nil {
		return nil
	}
	var out []string
	now := r.now()
	for _, s := range g.schedules {
		if s.active(now) {
			out = append(out, s.name)
		}
	}
	return out
}

// Groups devolve os grupos cadastrados.
func (r *Registry) Groups() []Group {
	return slices.Clone(r.groups.Load().list)
}

// ValidateGroups confere sem aplicar.
func ValidateGroups(gs []Group) error {
	_, err := compileGroups(gs)
	return err
}

// SetGroups troca os grupos e recompila a política de todos os aparelhos.
func (r *Registry) SetGroups(gs []Group) error {
	set, err := compileGroups(gs)
	if err != nil {
		return err
	}
	r.groups.Store(set)
	for _, c := range r.all() {
		c.mu.Lock()
		c.rebuildLocked(r)
		c.mu.Unlock()
	}
	return nil
}

func (r *Registry) now() time.Time {
	if r.opts.Now != nil {
		return r.opts.Now()
	}
	return time.Now()
}
