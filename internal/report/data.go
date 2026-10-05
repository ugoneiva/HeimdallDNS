// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

// Package report gera o relatório periódico em PDF (semanal ou mensal): o
// volume de consultas, o que foi bloqueado, os aparelhos mais ativos e os
// alertas de segurança do período.
package report

import (
	"slices"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

// Data é o conteúdo de um relatório.
type Data struct {
	From, To  time.Time
	Generated time.Time
	Node      string
	Version   string
	Title     string

	Total, Blocked, Cached, Forwarded, Isolated, Errors int64
	AvgMS                                               float64
	Devices                                             int

	Days       []Day
	TopBlocked []store.Ranked
	TopClients []Client
	Alerts     []store.SecurityEvent // os mais graves do período
	AlertsBy   map[string]int        // por gravidade
	AlertKinds map[string]int        // por tipo
	AlertTotal int
}

// Day é um dia do gráfico.
type Day struct {
	Date    time.Time
	Total   int64
	Blocked int64
}

// Client é um aparelho no ranking.
type Client struct {
	Name    string
	Queries int64
	Blocked int64
}

// Source é de onde vêm os números (o banco) e os nomes dos aparelhos.
type Source struct {
	Store   *store.Store
	Name    func(clientID string) string // nil = mostra o id
	Node    string
	Version string
}

// Collect junta os números de [from, to).
func Collect(src Source, from, to time.Time) (*Data, error) {
	st := src.Store
	d := &Data{From: from, To: to, Generated: time.Now(), Node: src.Node, Version: src.Version,
		AlertsBy: map[string]int{}, AlertKinds: map[string]int{}}
	end := to.Add(-time.Second)
	sum, devices, err := st.Summary(from, end, nil)
	if err != nil {
		return nil, err
	}
	d.Total, d.Blocked, d.Cached, d.Forwarded = sum.Total, sum.Blocked, sum.Cached, sum.Forwarded
	d.Isolated, d.Errors, d.AvgMS, d.Devices = sum.Isolated, sum.Errors, sum.AvgForwardMS, devices

	// Um ponto por dia, no fuso local.
	for day := from; day.Before(to); day = day.AddDate(0, 0, 1) {
		next := day.AddDate(0, 0, 1)
		if next.After(to) {
			next = to
		}
		b, _, err := st.Summary(day, next.Add(-time.Second), nil)
		if err != nil {
			return nil, err
		}
		d.Days = append(d.Days, Day{Date: day, Total: b.Total, Blocked: b.Blocked + b.Isolated})
	}
	if d.TopBlocked, err = st.TopDomains(from, end, true, "", 10); err != nil {
		return nil, err
	}
	tops, err := st.TopClients(from, end, 10)
	if err != nil {
		return nil, err
	}
	for _, c := range tops {
		name := c.Key
		if src.Name != nil {
			if n := src.Name(c.Key); n != "" {
				name = n
			}
		}
		d.TopClients = append(d.TopClients, Client{Name: name, Queries: c.Count, Blocked: c.Blocked})
	}
	evs, err := st.Events(store.EventQuery{Since: from, Limit: 1000})
	if err != nil {
		return nil, err
	}
	var inPeriod []store.SecurityEvent
	for _, e := range evs {
		if e.FirstSeen.Before(to) {
			inPeriod = append(inPeriod, e)
			d.AlertsBy[e.Severity]++
			d.AlertKinds[e.Kind]++
		}
	}
	d.AlertTotal = len(inPeriod)
	rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	slices.SortStableFunc(inPeriod, func(a, b store.SecurityEvent) int {
		if r := rank[a.Severity] - rank[b.Severity]; r != 0 {
			return r
		}
		return b.Count - a.Count
	})
	d.Alerts = inPeriod[:min(len(inPeriod), 12)]
	return d, nil
}

// Period devolve o último período fechado antes de now: a semana (segunda a
// domingo) ou o mês anterior.
func Period(freq string, now time.Time) (from, to time.Time) {
	y, m, dd := now.Date()
	today := time.Date(y, m, dd, 0, 0, 0, 0, now.Location())
	if freq == FreqMonthly {
		to = time.Date(y, m, 1, 0, 0, 0, 0, now.Location())
		return to.AddDate(0, -1, 0), to
	}
	// Segunda-feira desta semana.
	back := (int(today.Weekday()) + 6) % 7
	to = today.AddDate(0, 0, -back)
	return to.AddDate(0, 0, -7), to
}
