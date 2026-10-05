// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package forward

import (
	"net/netip"
	"slices"
	"testing"
	"time"
)

func TestReverseZones(t *testing.T) {
	for in, want := range map[string][]string{
		"192.168.1.0/24": {"1.168.192.in-addr.arpa."},
		"10.0.0.0/8":     {"10.in-addr.arpa."},
		"172.16.0.0/12":  {"16.172.in-addr.arpa.", "17.172.in-addr.arpa.", "18.172.in-addr.arpa.", "19.172.in-addr.arpa.", "20.172.in-addr.arpa.", "21.172.in-addr.arpa.", "22.172.in-addr.arpa.", "23.172.in-addr.arpa.", "24.172.in-addr.arpa.", "25.172.in-addr.arpa.", "26.172.in-addr.arpa.", "27.172.in-addr.arpa.", "28.172.in-addr.arpa.", "29.172.in-addr.arpa.", "30.172.in-addr.arpa.", "31.172.in-addr.arpa."},
		"192.168.4.0/22": {"4.168.192.in-addr.arpa.", "5.168.192.in-addr.arpa.", "6.168.192.in-addr.arpa.", "7.168.192.in-addr.arpa."},
		"fd12:3456::/32": {"6.5.4.3.2.1.d.f.ip6.arpa."},
	} {
		got, err := ReverseZones(netip.MustParsePrefix(in))
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%s = %v %v", in, got, err)
		}
	}
	if _, err := ReverseZones(netip.MustParsePrefix("10.0.0.0/4")); err == nil {
		t.Error("/4 deveria falhar")
	}
}

func TestPrivateReverse(t *testing.T) {
	for name, want := range map[string]bool{
		"10.1.168.192.in-addr.arpa.": true,
		"5.0.0.10.in-addr.arpa.":     true,
		"1.20.172.in-addr.arpa.":     true,
		"1.32.172.in-addr.arpa.":     false, // 172.32 é público
		"8.8.8.8.in-addr.arpa.":      false,
		"1.0.0.0.d.f.ip6.arpa.":      true,
		"exemplo.com.":               false,
	} {
		if got := IsPrivateReverse(name); got != want {
			t.Errorf("%s = %v", name, got)
		}
	}
}

func TestTable(t *testing.T) {
	if _, err := Normalize([]Rule{{Domain: "empresa.local"}}); err == nil {
		t.Error("regra sem servidor")
	}
	if _, err := Normalize([]Rule{{Domain: "a.local", Network: "10.0.0.0/8", Servers: []string{"10.0.0.1"}}}); err == nil {
		t.Error("domínio e rede juntos")
	}
	if _, err := Normalize([]Rule{{Domain: "a.local", Servers: []string{"dc01"}}}); err == nil {
		t.Error("servidor tem que ser IP")
	}
	rules, err := Normalize([]Rule{{Domain: "Empresa.Local.", Servers: []string{"10.0.0.10", "10.0.0.11:5353"}}})
	if err != nil || rules[0].Domain != "empresa.local" || rules[0].Servers[0] != "10.0.0.10:53" || rules[0].Servers[1] != "10.0.0.11:5353" {
		t.Fatalf("normalizar = %+v %v", rules, err)
	}
	tb, err := Build([]Rule{
		{Domain: "empresa.local", Servers: []string{"10.0.0.10"}},
		{Domain: "filial.empresa.local", Servers: []string{"10.1.0.10"}},
		{Network: "192.168.1.0/24", Servers: []string{"192.168.1.1"}},
	}, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tb.Close()
	for name, want := range map[string]string{
		"dc01.empresa.local.":        "empresa.local",
		"empresa.local.":             "empresa.local",
		"srv.filial.empresa.local.":  "filial.empresa.local", // o mais específico vence
		"25.1.168.192.in-addr.arpa.": "192.168.1.0/24",
		"naoempresa.local.":          "",
		"www.google.com.":            "",
	} {
		_, label, ok := tb.Match(name)
		if label != want || ok != (want != "") {
			t.Errorf("%s = %q %v", name, label, ok)
		}
	}
}

func TestManager(t *testing.T) {
	m, err := NewManager([]Rule{{Domain: "empresa.local", Servers: []string{"10.0.0.10"}}}, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if _, l, ok := m.Match("dc.empresa.local."); !ok || l != "empresa.local" {
		t.Error("regra do arquivo")
	}
	if err := m.Apply([]Rule{{Network: "10.0.0.0/8", Servers: []string{"10.0.0.10"}}, {Network: "10.0.0.0/8", Servers: []string{"10.0.0.11"}}}); err == nil {
		t.Error("regra repetida")
	}
	if err := m.Apply([]Rule{{Network: "10.0.0.0/8", Servers: []string{"10.0.0.10"}}}); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := m.Match("5.0.0.10.in-addr.arpa."); !ok {
		t.Error("regra do painel")
	}
	if _, _, ok := m.Match("dc.empresa.local."); !ok {
		t.Error("o arquivo continua valendo")
	}
	var nilM *Manager
	if _, _, ok := nilM.Match("x."); ok {
		t.Error("nil")
	}
	for in, want := range map[string]bool{
		"192.168.1.1": true, "tls://1.1.1.1": false, "https://dns.google/dns-query": false,
		"10.0.0.1:53": true, "[fd00::1]:53": true, "udp://172.20.0.1": true, "9.9.9.9": false,
	} {
		if HasPrivate([]string{in}) != want {
			t.Errorf("HasPrivate(%s)", in)
		}
	}
}
