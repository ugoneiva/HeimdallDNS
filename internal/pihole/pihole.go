// Package pihole lê o backup do Pi-hole (Teleporter) para migrar listas,
// regras, registros locais, reservas de DHCP, upstreams e nomes de clientes.
//
// Formatos aceitos:
//   - Pi-hole v6: .zip com etc/pihole/pihole.toml e etc/pihole/gravity.db;
//   - Pi-hole v5: .tar.gz com adlist.json, whitelist/blacklist.*.json,
//     custom.list, 05-pihole-custom-cname.conf, 04-pihole-static-dhcp.conf
//     e setupVars.conf.
package pihole

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	_ "modernc.org/sqlite"
)

const maxFile = 64 << 20

// List é uma lista de bloqueio (adlist) do Pi-hole.
type List struct {
	URL     string `json:"url"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Allow   bool   `json:"allow"` // lista de liberação (sem equivalente aqui)
}

// Host é um registro local: A/AAAA ou CNAME.
type Host struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Reservation é uma reserva fixa de DHCP.
type Reservation struct {
	MAC  string `json:"mac"`
	IP   string `json:"ip"`
	Name string `json:"name,omitempty"`
}

// Client é um nome dado a um cliente (IP, MAC ou rede) no Pi-hole.
type Client struct {
	Ref  string `json:"ref"`
	Name string `json:"name"`
}

// Export é o conteúdo útil de um backup do Pi-hole.
type Export struct {
	Version      string        `json:"version"` // v5 ou v6
	Lists        []List        `json:"lists"`
	Deny         []string      `json:"deny"`  // regras já no formato daqui
	Allow        []string      `json:"allow"` // idem
	Hosts        []Host        `json:"hosts"`
	Reservations []Reservation `json:"reservations"`
	Upstreams    []string      `json:"upstreams"`
	Clients      []Client      `json:"clients"`
	Groups       int           `json:"groups"`  // grupos além do padrão (não migrados)
	Skipped      []string      `json:"skipped"` // o que não deu para converter, com o motivo
}

// Parse lê o backup (detecta zip ou tar.gz pelo conteúdo).
func Parse(r io.Reader, tempDir string) (*Export, error) {
	data, err := io.ReadAll(io.LimitReader(r, 512<<20))
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	switch {
	case bytes.HasPrefix(data, []byte("PK\x03\x04")):
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, fmt.Errorf("zip inválido: %w", err)
		}
		for _, f := range zr.File {
			if f.UncompressedSize64 > maxFile || f.FileInfo().IsDir() {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			b, err := io.ReadAll(io.LimitReader(rc, maxFile))
			rc.Close()
			if err != nil {
				return nil, err
			}
			files[path.Clean(f.Name)] = b
		}
	case bytes.HasPrefix(data, []byte{0x1f, 0x8b}):
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		tr := tar.NewReader(gz)
		for {
			h, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("tar.gz inválido: %w", err)
			}
			if h.Typeflag != tar.TypeReg || h.Size > maxFile {
				continue
			}
			b, err := io.ReadAll(io.LimitReader(tr, maxFile))
			if err != nil {
				return nil, err
			}
			files[path.Clean(strings.TrimPrefix(h.Name, "./"))] = b
		}
	default:
		return nil, errors.New("formato desconhecido: envie o arquivo do Teleporter do Pi-hole (.zip da v6 ou .tar.gz da v5)")
	}
	find := func(name string) []byte {
		for k, v := range files {
			if k == name || strings.HasSuffix(k, "/"+name) {
				return v
			}
		}
		return nil
	}
	e := &Export{}
	if t := find("pihole.toml"); t != nil {
		e.Version = "v6"
		if err := e.parseTOML(t); err != nil {
			return nil, err
		}
		if g := find("gravity.db"); g != nil {
			if err := e.parseGravity(g, tempDir); err != nil {
				return nil, err
			}
		}
	} else if find("adlist.json") != nil || find("setupVars.conf") != nil {
		e.Version = "v5"
		if err := e.parseV5(find); err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("o arquivo não parece um backup do Pi-hole (faltam pihole.toml ou adlist.json)")
	}
	e.dedupe()
	return e, nil
}

// --- v6 ---

func (e *Export) parseTOML(b []byte) error {
	var c struct {
		DNS struct {
			Upstreams    []string `toml:"upstreams"`
			Hosts        []string `toml:"hosts"`
			CNAMERecords []string `toml:"cnameRecords"`
		} `toml:"dns"`
		DHCP struct {
			Hosts []string `toml:"hosts"`
		} `toml:"dhcp"`
	}
	if _, err := toml.Decode(string(b), &c); err != nil {
		return fmt.Errorf("pihole.toml: %w", err)
	}
	e.Upstreams = append(e.Upstreams, normalizeUpstreams(c.DNS.Upstreams)...)
	for _, l := range c.DNS.Hosts {
		e.addHostsLine(l)
	}
	for _, l := range c.DNS.CNAMERecords {
		e.addCNAME(l)
	}
	for _, l := range c.DHCP.Hosts {
		e.addDHCPHost(l)
	}
	return nil
}

func (e *Export) parseGravity(b []byte, tempDir string) error {
	f, err := os.CreateTemp(tempDir, ".gravity-*.db")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	f.Close()
	db, err := sql.Open("sqlite", "file:"+f.Name()+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()

	// adlist.type existe a partir da v5.x recente (0 = bloqueio, 1 = liberação).
	rows, err := db.Query(`SELECT address, enabled, COALESCE(comment, ''), COALESCE(type, 0) FROM adlist`)
	if err != nil {
		rows, err = db.Query(`SELECT address, enabled, COALESCE(comment, ''), 0 FROM adlist`)
	}
	if err != nil {
		return fmt.Errorf("gravity.db: %w", err)
	}
	for rows.Next() {
		var l List
		var typ int
		if err := rows.Scan(&l.URL, &l.Enabled, &l.Name, &typ); err != nil {
			rows.Close()
			return err
		}
		l.Allow = typ == 1
		e.Lists = append(e.Lists, l)
	}
	rows.Close()

	rows, err = db.Query(`SELECT type, domain, enabled FROM domainlist`)
	if err != nil {
		return fmt.Errorf("gravity.db: %w", err)
	}
	for rows.Next() {
		var typ int
		var dom string
		var enabled bool
		if err := rows.Scan(&typ, &dom, &enabled); err != nil {
			rows.Close()
			return err
		}
		e.addDomain(typ, dom, enabled)
	}
	rows.Close()

	if rows, err = db.Query(`SELECT ip, COALESCE(comment, '') FROM client`); err == nil {
		for rows.Next() {
			var c Client
			if rows.Scan(&c.Ref, &c.Name) == nil && strings.TrimSpace(c.Name) != "" {
				e.Clients = append(e.Clients, c)
			}
		}
		rows.Close()
	}
	var groups int
	if db.QueryRow(`SELECT count(*) FROM "group" WHERE id != 0`).Scan(&groups) == nil {
		e.Groups = groups
	}
	return nil
}

// --- v5 ---

func (e *Export) parseV5(find func(string) []byte) error {
	var adlists []struct {
		Address string `json:"address"`
		Enabled int    `json:"enabled"`
		Comment string `json:"comment"`
	}
	if b := find("adlist.json"); b != nil {
		if err := json.Unmarshal(b, &adlists); err != nil {
			return fmt.Errorf("adlist.json: %w", err)
		}
	}
	for _, a := range adlists {
		e.Lists = append(e.Lists, List{URL: a.Address, Name: a.Comment, Enabled: a.Enabled == 1})
	}
	// Tipos da domainlist: 0 liberar exato, 1 bloquear exato, 2 liberar regex, 3 bloquear regex.
	for file, typ := range map[string]int{"whitelist.exact.json": 0, "blacklist.exact.json": 1,
		"whitelist.regex.json": 2, "blacklist.regex.json": 3} {
		b := find(file)
		if b == nil {
			continue
		}
		var items []struct {
			Domain  string `json:"domain"`
			Enabled int    `json:"enabled"`
		}
		if err := json.Unmarshal(b, &items); err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		for _, it := range items {
			e.addDomain(typ, it.Domain, it.Enabled == 1)
		}
	}
	if b := find("custom.list"); b != nil {
		eachLine(b, e.addHostsLine)
	}
	if b := find("05-pihole-custom-cname.conf"); b != nil {
		eachLine(b, func(l string) {
			if v, ok := strings.CutPrefix(l, "cname="); ok {
				e.addCNAME(v)
			}
		})
	}
	if b := find("04-pihole-static-dhcp.conf"); b != nil {
		eachLine(b, func(l string) {
			if v, ok := strings.CutPrefix(l, "dhcp-host="); ok {
				e.addDHCPHost(v)
			}
		})
	}
	if b := find("setupVars.conf"); b != nil {
		var ups []string
		eachLine(b, func(l string) {
			k, v, ok := strings.Cut(l, "=")
			if ok && strings.HasPrefix(k, "PIHOLE_DNS_") && v != "" {
				ups = append(ups, v)
			}
		})
		e.Upstreams = append(e.Upstreams, normalizeUpstreams(ups)...)
	}
	var clients []struct {
		IP      string `json:"ip"`
		Comment string `json:"comment"`
	}
	if b := find("client.json"); b != nil && json.Unmarshal(b, &clients) == nil {
		for _, c := range clients {
			if strings.TrimSpace(c.Comment) != "" {
				e.Clients = append(e.Clients, Client{Ref: c.IP, Name: c.Comment})
			}
		}
	}
	var groups []struct {
		ID int `json:"id"`
	}
	if b := find("group.json"); b != nil && json.Unmarshal(b, &groups) == nil {
		for _, g := range groups {
			if g.ID != 0 {
				e.Groups++
			}
		}
	}
	return nil
}

// --- conversões ---

// Regex do Pi-hole que equivalem a "domínio e subdomínios".
var (
	reSubdomains = regexp.MustCompile(`^\(\\\.\|\^\)((?:[a-z0-9-]+\\\.)+[a-z0-9-]+)\$$`)
	reExact      = regexp.MustCompile(`^\^((?:[a-z0-9-]+\\\.)+[a-z0-9-]+)\$$`)
)

func (e *Export) addDomain(typ int, dom string, enabled bool) {
	dom = strings.TrimSpace(dom)
	if dom == "" {
		return
	}
	if !enabled {
		e.Skipped = append(e.Skipped, "regra desativada no Pi-hole: "+dom)
		return
	}
	allow := typ == 0 || typ == 2
	rule := ""
	switch typ {
	case 0, 1:
		rule = strings.ToLower(dom) // aqui, domínio simples vale também para os subdomínios
	case 2, 3:
		low := strings.ToLower(dom)
		if m := reSubdomains.FindStringSubmatch(low); m != nil {
			rule = strings.ReplaceAll(m[1], `\.`, ".")
		} else if m := reExact.FindStringSubmatch(low); m != nil {
			rule = strings.ReplaceAll(m[1], `\.`, ".")
		} else if strings.Contains(dom, ";") {
			e.Skipped = append(e.Skipped, "regex com opções do Pi-hole (;querytype etc.): "+dom)
			return
		} else if _, err := regexp.Compile(dom); err != nil {
			e.Skipped = append(e.Skipped, "regex incompatível: "+dom)
			return
		} else {
			rule = "/" + dom + "/"
		}
	default:
		return
	}
	if allow {
		e.Allow = append(e.Allow, rule)
	} else {
		e.Deny = append(e.Deny, rule)
	}
}

// addHostsLine: "IP nome [outros]" (custom.list ou dns.hosts).
func (e *Export) addHostsLine(l string) {
	f := strings.Fields(l)
	if len(f) < 2 || strings.HasPrefix(f[0], "#") {
		return
	}
	ip, err := netip.ParseAddr(f[0])
	if err != nil {
		e.Skipped = append(e.Skipped, "registro local com IP inválido: "+l)
		return
	}
	t := "A"
	if ip.Unmap().Is6() {
		t = "AAAA"
	}
	for _, n := range f[1:] {
		if strings.HasPrefix(n, "#") {
			break
		}
		e.Hosts = append(e.Hosts, Host{Name: strings.ToLower(n), Type: t, Value: ip.Unmap().String()})
	}
}

// addCNAME: "apelido[,apelido2],destino[,ttl]".
func (e *Export) addCNAME(l string) {
	parts := strings.Split(strings.TrimSpace(l), ",")
	if len(parts) >= 3 && isNumber(parts[len(parts)-1]) {
		parts = parts[:len(parts)-1]
	}
	if len(parts) < 2 {
		e.Skipped = append(e.Skipped, "CNAME inválido: "+l)
		return
	}
	target := strings.ToLower(strings.TrimSpace(parts[len(parts)-1]))
	for _, a := range parts[:len(parts)-1] {
		e.Hosts = append(e.Hosts, Host{Name: strings.ToLower(strings.TrimSpace(a)), Type: "CNAME", Value: target})
	}
}

// addDHCPHost: "MAC,IP[,nome][,tempo]" (formato dhcp-host do dnsmasq).
func (e *Export) addDHCPHost(l string) {
	var r Reservation
	for _, p := range strings.Split(strings.TrimSpace(l), ",") {
		p = strings.TrimSpace(p)
		switch {
		case p == "":
		case r.MAC == "" && isMAC(p):
			hw, _ := net.ParseMAC(p)
			r.MAC = hw.String()
		case r.IP == "" && isIPv4(p):
			r.IP = p
		case r.Name == "" && !isNumber(p) && p != "infinite" && !strings.HasSuffix(p, "h") && !strings.HasSuffix(p, "m"):
			r.Name = p
		}
	}
	if r.MAC == "" || r.IP == "" {
		e.Skipped = append(e.Skipped, "reserva de DHCP sem MAC ou IPv4: "+l)
		return
	}
	e.Reservations = append(e.Reservations, r)
}

// normalizeUpstreams: "8.8.8.8#53" (dnsmasq) vira "8.8.8.8:53".
func normalizeUpstreams(in []string) []string {
	var out []string
	for _, u := range in {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if host, port, ok := strings.Cut(u, "#"); ok {
			u = net.JoinHostPort(host, port)
		}
		out = append(out, u)
	}
	return out
}

func (e *Export) dedupe() {
	uniq := func(s []string) []string {
		slices.Sort(s)
		return slices.Compact(s)
	}
	e.Deny, e.Allow = uniq(e.Deny), uniq(e.Allow)
	e.Upstreams = slices.Compact(e.Upstreams)
	seenList := map[string]bool{}
	lists := e.Lists[:0]
	for _, l := range e.Lists {
		if !seenList[l.URL] {
			seenList[l.URL] = true
			lists = append(lists, l)
		}
	}
	e.Lists = lists
	seenHost := map[Host]bool{}
	hosts := e.Hosts[:0]
	for _, h := range e.Hosts {
		if !seenHost[h] {
			seenHost[h] = true
			hosts = append(hosts, h)
		}
	}
	e.Hosts = hosts
	for _, p := range []*[]string{&e.Deny, &e.Allow, &e.Upstreams, &e.Skipped} {
		if *p == nil {
			*p = []string{}
		}
	}
	if e.Lists == nil {
		e.Lists = []List{}
	}
	if e.Hosts == nil {
		e.Hosts = []Host{}
	}
	if e.Reservations == nil {
		e.Reservations = []Reservation{}
	}
	if e.Clients == nil {
		e.Clients = []Client{}
	}
}

func eachLine(b []byte, fn func(string)) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			fn(l)
		}
	}
}

func isMAC(s string) bool {
	hw, err := net.ParseMAC(s)
	return err == nil && len(hw) == 6
}

func isIPv4(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is4()
}

func isNumber(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
