// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package topology

import (
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	for name, want := range map[string]string{
		"www.youtube.com.":             "youtube",
		"rr3---sn-x.googlevideo.com":   "youtube",
		"i.instagram.com":              "instagram",
		"fonts.gstatic.com":            "google",
		"gateway.icloud.com":           "apple",
		"ctldl.windowsupdate.com":      "microsoft",
		"s3.amazonaws.com":             "amazon",
		"api.empresa-desconhecida.com": "d:empresa-desconhecida.com",
		"servidor.casa.com.br":         "d:casa.com.br",
	} {
		if got := Classify(name).ID; got != want {
			t.Errorf("%s = %s, quero %s", name, got, want)
		}
	}
}

func TestGuessKind(t *testing.T) {
	cases := []struct {
		name, host, vendor string
		queried            []string
		want               string
	}{
		{"iPhone-de-Ana", "", "Apple, Inc.", nil, KindPhone},
		{"", "DESKTOP-7QH2K1", "Intel Corporate", nil, KindComputer},
		{"", "ludovico.lan", "Cloud Network Technology Singapore Pte. Ltd.", nil, KindComputer},
		{"TV da sala", "", "Samsung Electronics", nil, KindTV},
		{"", "", "Samsung Electronics", []string{"x.samsungcloudsolution.com"}, KindTV},
		{"", "", "Samsung Electronics", nil, KindPhone},
		{"", "EPSON1A2B3C", "", nil, KindPrinter},
		{"", "esp-a1b2c3", "Espressif Inc.", nil, KindIoT},
		{"", "", "", []string{"title.mgt.xboxlive.com"}, KindConsole},
		// Caso real: Chrome no Linux consulta o teste de conectividade do Google.
		{"", "ludovico.lan", "", []string{"connectivitycheck.gstatic.com", "repo.manjaro.org"}, KindComputer},
		{"", "", "", nil, KindUnknown},
	}
	for _, c := range cases {
		if got := Guess(c.name, c.host, c.vendor, c.queried); got != c.want {
			t.Errorf("%q/%q/%q = %s, quero %s", c.name, c.host, c.vendor, got, c.want)
		}
	}
}

func TestBuild(t *testing.T) {
	now := time.Now()
	in := Input{
		Devices: []DeviceIn{
			{ID: "a", Name: "Notebook", IPs: []string{"192.168.1.10"}, LastSeen: now},
			{ID: "b", Name: "Celular", IPs: []string{"192.168.1.11"}, LastSeen: now.Add(-time.Hour), Isolated: true, Kind: KindPhone},
			{ID: "s", Name: "este", IPs: []string{"192.168.1.2"}, LastSeen: now},
			{ID: "r", Name: "gw", IPs: []string{"192.168.1.1"}},
		},
		Counts: []Count{
			{"a", "www.youtube.com", 50, 0},
			{"a", "ads.rastreio.net", 10, 10},
			{"a", "um.com", 1, 0},
			{"a", "dois.com", 1, 0},
			{"b", "i.instagram.com", 20, 20},
			{"b", "www.youtube.com", 5, 0},
			{"", "sem-dono.com", 3, 0},
		},
		Alerts:     map[string]int{"b": 2},
		SelfIPs:    []string{"192.168.1.2"},
		GatewayIP:  "192.168.1.1",
		MaxDest:    3, // youtube, instagram e bloqueados; um.com/dois.com viram "Outros"
		Now:        now,
		ActiveSpan: 5 * time.Minute,
	}
	m := Build(in)
	byID := map[string]Device{}
	for _, d := range m.Devices {
		byID[d.ID] = d
	}
	if !byID["a"].Active || byID["b"].Active || !byID["b"].Isolated || byID["b"].Alerts != 2 {
		t.Errorf("estados = %+v", byID)
	}
	if byID["a"].Kind != KindComputer || byID["b"].KindAuto || byID["s"].Kind != KindServer || !byID["s"].Self || byID["r"].Kind != KindRouter {
		t.Errorf("tipos = %+v", byID)
	}
	dests := map[string]Dest{}
	for _, d := range m.Destinations {
		dests[d.ID] = d
	}
	if dests["youtube"].Queries != 55 || dests["youtube"].Devices != 2 || dests[BlockedDest.ID].Queries != 10 ||
		dests[OthersDest.ID].Queries != 2 || dests["instagram"].Blocked != 20 {
		t.Errorf("destinos = %+v", dests)
	}
	if last := m.Destinations[len(m.Destinations)-1].ID; last != OthersDest.ID {
		t.Errorf("Outros deveria vir por último: %s", last)
	}
	if byID["a"].Queries != 62 || byID["a"].Blocked != 10 {
		t.Errorf("contas do aparelho a = %+v", byID["a"])
	}
	for _, l := range m.Links {
		if l.Device == "" {
			t.Error("consulta sem aparelho não vira ligação")
		}
	}
}
