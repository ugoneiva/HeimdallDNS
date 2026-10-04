// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package clients

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/filter"
)

func TestGroupsAndSchedules(t *testing.T) {
	now := time.Date(2026, 10, 5, 23, 30, 0, 0, time.Local) // segunda-feira, 23:30
	r, err := NewRegistry(Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	err = r.SetGroups([]Group{{
		ID: "kids", Name: "Crianças", Deny: []string{"apostas.com"},
		Schedules: []Schedule{
			{Name: "noite", Start: "22:00", End: "07:00", Deny: []string{"service:tiktok", "jogo.com"}},
			{Name: "aula", Days: []int{1, 2, 3, 4, 5}, Start: "08:00", End: "12:00", BlockAll: true, Allow: []string{"escola.edu.br"}},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	c := r.Observe(netip.MustParseAddr("192.168.0.30"), now)
	if err := r.Update(c, func(s *Settings) error { s.Group = "kids"; s.Allow = []string{"jogo.com"}; return nil }); err != nil {
		t.Fatal(err)
	}
	check := func(when time.Time, name string, want filter.Verdict, rule string) {
		t.Helper()
		now = when
		res := c.Policy().Match(name)
		if res.Verdict != want || (rule != "" && !strings.Contains(res.Rule, rule)) {
			t.Errorf("%s às %s: %v %q, quero %v %q", name, when.Format("Mon 15:04"), res.Verdict, res.Rule, want, rule)
		}
	}
	seg2330 := now
	ter0630 := time.Date(2026, 10, 6, 6, 30, 0, 0, time.Local)
	ter0900 := time.Date(2026, 10, 6, 9, 0, 0, 0, time.Local)
	sab0900 := time.Date(2026, 10, 10, 9, 0, 0, 0, time.Local)
	ter1500 := time.Date(2026, 10, 6, 15, 0, 0, 0, time.Local)

	check(seg2330, "www.tiktok.com", filter.Blocked, "horário noite")
	check(ter0630, "www.tiktok.com", filter.Blocked, "horário noite") // continua depois da meia-noite
	check(ter1500, "www.tiktok.com", filter.Pass, "")
	check(seg2330, "jogo.com", filter.Allowed, "") // a regra do próprio aparelho vence o horário
	check(ter1500, "apostas.com", filter.Blocked, "grupo Crianças")
	check(ter0900, "youtube.com", filter.Blocked, "horário aula: pausa")
	check(ter0900, "portal.escola.edu.br", filter.Allowed, "horário aula")
	check(sab0900, "youtube.com", filter.Pass, "") // sábado não tem aula

	if got := r.ActiveSchedules("kids"); len(got) != 0 {
		t.Errorf("ativos no sábado de manhã = %v", got)
	}
	now = ter0900
	if got := r.ActiveSchedules("kids"); len(got) != 1 || got[0] != "aula" {
		t.Errorf("ativos na terça 9h = %v", got)
	}
	// Tirar o grupo vale na hora.
	r.SetGroups(nil)
	check(ter1500, "apostas.com", filter.Pass, "")
}

func TestGroupValidation(t *testing.T) {
	for _, gs := range [][]Group{
		{{ID: "a", Name: ""}},
		{{ID: "a", Name: "A"}, {ID: "a", Name: "B"}},
		{{ID: "a", Name: "A", Schedules: []Schedule{{Name: "x", Start: "25:00", End: "07:00", BlockAll: true}}}},
		{{ID: "a", Name: "A", Schedules: []Schedule{{Name: "x", Start: "08:00", End: "09:00"}}}},
		{{ID: "a", Name: "A", Deny: []string{"service:nada"}}},
	} {
		if ValidateGroups(gs) == nil {
			t.Errorf("deveria recusar %+v", gs)
		}
	}
}
