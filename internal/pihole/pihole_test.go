// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package pihole

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"database/sql"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const toml6 = `
[dns]
  upstreams = ["9.9.9.9", "1.1.1.1#5353"]
  hosts = ["192.168.0.10 nas.lan nas", "fd00::10 nas6.lan"]
  cnameRecords = ["fotos.lan,nas.lan", "a.lan,b.lan,nas.lan,300"]
[dhcp]
  hosts = ["AA:BB:CC:DD:EE:01,192.168.0.50,impressora", "aa:bb:cc:dd:ee:02,192.168.0.51,infinite"]
`

func gravity(t *testing.T) []byte {
	t.Helper()
	p := filepath.Join(t.TempDir(), "gravity.db")
	db, err := sql.Open("sqlite", "file:"+p)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE adlist (id INTEGER PRIMARY KEY, address TEXT, enabled BOOLEAN, comment TEXT, type INTEGER DEFAULT 0)`,
		`CREATE TABLE domainlist (id INTEGER PRIMARY KEY, type INTEGER, domain TEXT, enabled BOOLEAN, comment TEXT)`,
		`CREATE TABLE client (id INTEGER PRIMARY KEY, ip TEXT, comment TEXT)`,
		`CREATE TABLE "group" (id INTEGER PRIMARY KEY, name TEXT)`,
		`INSERT INTO adlist (address, enabled, comment, type) VALUES
			('https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', 1, 'Padrão', 0),
			('https://exemplo.com/off.txt', 0, '', 0),
			('https://exemplo.com/libera.txt', 1, 'allow', 1)`,
		`INSERT INTO domainlist (type, domain, enabled) VALUES
			(0, 's.youtube.com', 1), (1, 'Ads.Exemplo.com', 1), (1, 'desligado.com', 0),
			(3, '(\.|^)tiktok\.com$', 1), (3, '^exato\.net$', 1), (3, '^ad[0-9]+\.', 1),
			(3, 'abc;querytype=AAAA', 1), (2, '(\.|^)libera\.org$', 1)`,
		`INSERT INTO client (ip, comment) VALUES ('192.168.0.20', 'Notebook da Ana'), ('192.168.0.21', '')`,
		`INSERT INTO "group" (id, name) VALUES (0, 'Default'), (1, 'Crianças')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	db.Close()
	b, _ := os.ReadFile(p)
	return b
}

func TestV6(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, b := range map[string][]byte{"etc/pihole/pihole.toml": []byte(toml6), "etc/pihole/gravity.db": gravity(t)} {
		w, _ := zw.Create(name)
		w.Write(b)
	}
	zw.Close()
	e, err := Parse(&buf, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if e.Version != "v6" || len(e.Lists) != 3 || !e.Lists[2].Allow || e.Lists[1].Enabled || e.Lists[0].Name != "Padrão" {
		t.Errorf("listas = %+v", e.Lists)
	}
	wantDeny := []string{"/^ad[0-9]+\\./", "ads.exemplo.com", "exato.net", "tiktok.com"}
	if !slices.Equal(e.Deny, wantDeny) {
		t.Errorf("deny = %q", e.Deny)
	}
	if !slices.Equal(e.Allow, []string{"libera.org", "s.youtube.com"}) {
		t.Errorf("allow = %q", e.Allow)
	}
	if len(e.Skipped) != 2 {
		t.Errorf("ignorados = %q", e.Skipped)
	}
	want := []Host{{"nas.lan", "A", "192.168.0.10"}, {"nas", "A", "192.168.0.10"}, {"nas6.lan", "AAAA", "fd00::10"},
		{"fotos.lan", "CNAME", "nas.lan"}, {"a.lan", "CNAME", "nas.lan"}, {"b.lan", "CNAME", "nas.lan"}}
	if !slices.Equal(e.Hosts, want) {
		t.Errorf("hosts = %+v", e.Hosts)
	}
	if len(e.Reservations) != 2 || e.Reservations[0] != (Reservation{"aa:bb:cc:dd:ee:01", "192.168.0.50", "impressora"}) || e.Reservations[1].Name != "" {
		t.Errorf("reservas = %+v", e.Reservations)
	}
	if !slices.Equal(e.Upstreams, []string{"9.9.9.9", "1.1.1.1:5353"}) {
		t.Errorf("upstreams = %q", e.Upstreams)
	}
	if len(e.Clients) != 1 || e.Clients[0].Name != "Notebook da Ana" || e.Groups != 1 {
		t.Errorf("clientes = %+v, grupos = %d", e.Clients, e.Groups)
	}
}

func TestV5(t *testing.T) {
	files := map[string]string{
		"adlist.json":                 `[{"id":1,"address":"https://lista.com/a.txt","enabled":1,"comment":"A"}]`,
		"blacklist.exact.json":        `[{"domain":"ruim.com","enabled":1}]`,
		"whitelist.regex.json":        `[{"domain":"(\\.|^)bom\\.com$","enabled":1}]`,
		"custom.list":                 "10.0.0.2 router.lan\n# comentário\n",
		"05-pihole-custom-cname.conf": "cname=www.lan,router.lan\n",
		"04-pihole-static-dhcp.conf":  "dhcp-host=aa:bb:cc:00:00:01,10.0.0.9,tv\n",
		"setupVars.conf":              "PIHOLE_DNS_1=8.8.8.8\nPIHOLE_DNS_2=\nWEBPASSWORD=xyz\n",
		"client.json":                 `[{"ip":"10.0.0.5","comment":"Celular"}]`,
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, c := range files {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(c)), Typeflag: tar.TypeReg})
		tw.Write([]byte(c))
	}
	tw.Close()
	gz.Close()
	e, err := Parse(&buf, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if e.Version != "v5" || len(e.Lists) != 1 || !slices.Equal(e.Deny, []string{"ruim.com"}) || !slices.Equal(e.Allow, []string{"bom.com"}) {
		t.Errorf("v5 = %+v", e)
	}
	if len(e.Hosts) != 2 || e.Hosts[1] != (Host{"www.lan", "CNAME", "router.lan"}) {
		t.Errorf("hosts = %+v", e.Hosts)
	}
	if len(e.Reservations) != 1 || !slices.Equal(e.Upstreams, []string{"8.8.8.8"}) || len(e.Clients) != 1 {
		t.Errorf("reservas/upstreams/clientes = %+v %q %+v", e.Reservations, e.Upstreams, e.Clients)
	}
}

func TestNotPihole(t *testing.T) {
	if _, err := Parse(strings.NewReader("texto qualquer"), t.TempDir()); err == nil {
		t.Error("deveria recusar")
	}
}
