// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package report

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/querylog"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

// sample grava uma semana de números de exemplo.
func sample(t *testing.T, from time.Time) *store.Store {
	st, err := store.Open(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	var stats []querylog.MinuteStat
	var tops []querylog.DomainCount
	for d := range 7 {
		for h := 8; h < 22; h++ {
			at := from.AddDate(0, 0, d).Add(time.Duration(h) * time.Hour)
			for i, c := range []string{"aa11", "bb22", "cc33"} {
				total := int64(400 + 90*d + 40*i + 10*h)
				stats = append(stats, querylog.MinuteStat{Minute: at.Unix() / 60, ClientID: c,
					Counts: querylog.Counts{Total: total, Blocked: total / 7, Cached: total / 3, Forwarded: total / 2, ForwardUS: total / 2 * 18000}})
			}
			tops = append(tops, querylog.DomainCount{Hour: at.Unix() / 3600, Name: "ads.exemplo.com", Blocked: true, Count: int64(30 + d)},
				querylog.DomainCount{Hour: at.Unix() / 3600, Name: "telemetria.exemplo.net", Blocked: true, Count: 12})
		}
	}
	if err := st.AddStats(stats, tops); err != nil {
		t.Fatal(err)
	}
	for i, e := range []store.SecurityEvent{
		{Kind: "threat_blocked", Severity: "high", ClientID: "aa11", ClientIP: "192.168.0.20", Domain: "malware.exemplo", Summary: "x", Count: 4},
		{Kind: "dga", Severity: "critical", ClientID: "bb22", ClientIP: "192.168.0.21", Domain: "q8x7z.exemplo", Summary: "y", Count: 1},
		{Kind: "new_device", Severity: "low", ClientID: "cc33", ClientIP: "192.168.0.22", Summary: "z", Count: 1},
	} {
		e.FirstSeen = from.Add(time.Duration(30+i) * time.Hour)
		e.LastSeen = e.FirstSeen
		if err := st.InsertEvent(&e); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

func TestPeriod(t *testing.T) {
	loc := time.Local
	wed := time.Date(2026, 10, 7, 15, 0, 0, 0, loc) // quarta
	from, to := Period(FreqWeekly, wed)
	if !from.Equal(time.Date(2026, 9, 28, 0, 0, 0, 0, loc)) || !to.Equal(time.Date(2026, 10, 5, 0, 0, 0, 0, loc)) {
		t.Errorf("semana = %v a %v", from, to)
	}
	from, to = Period(FreqMonthly, wed)
	if !from.Equal(time.Date(2026, 9, 1, 0, 0, 0, 0, loc)) || !to.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, loc)) {
		t.Errorf("mês = %v a %v", from, to)
	}
}

func TestReportAndSchedule(t *testing.T) {
	from := time.Date(2026, 9, 28, 0, 0, 0, 0, time.Local)
	to := from.AddDate(0, 0, 7)
	st := sample(t, from)
	names := map[string]string{"aa11": "notebook-joão", "bb22": "Celular da Ana"}
	var delivered []string
	var last time.Time
	dir := t.TempDir()
	s := NewScheduler(Options{
		Source: Source{Store: st, Name: func(id string) string { return names[id] }, Node: "dns1", Version: "teste"},
		Dir:    dir,
		Deliver: func(d *Data, pdf []byte, name string) {
			delivered = append(delivered, name)
		},
		LastRun: func() time.Time { return last }, SetLastRun: func(t time.Time) { last = t },
	})
	d, pdf, name, err := s.Generate(from, to, "Relatório semanal")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pdf, []byte("%PDF-")) || len(pdf) < 5000 {
		t.Fatalf("PDF inválido (%d bytes)", len(pdf))
	}
	if len(d.Days) != 7 || d.Total == 0 || d.Devices != 3 || len(d.TopBlocked) != 2 || d.TopClients[0].Name == "" || d.AlertTotal != 3 || d.Alerts[0].Severity != "critical" {
		t.Errorf("dados = dias %d total %d aparelhos %d bloqueados %d alertas %d", len(d.Days), d.Total, d.Devices, len(d.TopBlocked), d.AlertTotal)
	}
	if name != "heimdalldns-relatorio-2026-09-28-a-2026-10-04.pdf" {
		t.Errorf("nome = %s", name)
	}
	if l := s.List(); len(l) != 1 || l[0].Name != name {
		t.Errorf("lista = %+v", l)
	}
	if _, ok := s.Path("../../etc/passwd"); ok {
		t.Error("caminho fora da pasta")
	}
	if out := os.Getenv("HEIMDALL_REPORT_SAMPLE"); out != "" {
		os.WriteFile(out, pdf, 0o644)
	}

	// Agendamento: na primeira vez só marca; na semana seguinte, depois da hora, envia uma vez.
	s.SetSettings(Settings{Enabled: true, Frequency: FreqWeekly, Hour: 7})
	s.tick(time.Date(2026, 10, 7, 10, 0, 0, 0, time.Local))
	if len(delivered) != 0 || !last.Equal(to) {
		t.Fatalf("primeira vez: %v %v", delivered, last)
	}
	s.tick(time.Date(2026, 10, 12, 6, 0, 0, 0, time.Local)) // segunda antes das 7h
	if len(delivered) != 0 {
		t.Fatal("antes da hora")
	}
	s.tick(time.Date(2026, 10, 12, 7, 5, 0, 0, time.Local))
	s.tick(time.Date(2026, 10, 12, 7, 15, 0, 0, time.Local))
	if len(delivered) != 1 || delivered[0] != "heimdalldns-relatorio-2026-10-05-a-2026-10-11.pdf" {
		t.Errorf("enviados = %v", delivered)
	}
}
