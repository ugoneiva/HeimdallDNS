// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

// Package forward faz o encaminhamento condicional: nomes de um domínio
// interno (empresa.local) e a zona reversa de uma rede (192.168.1.0/24) vão
// para servidores DNS internos (o controlador do AD, o roteador), e não para
// a internet. Se os internos falharem, a resposta é erro: o nome interno
// nunca vaza para fora.
package forward

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/ugoneiva/HeimdallDNS/internal/upstream"
)

// Rule é uma regra de encaminhamento: um domínio ou uma rede (zona reversa).
type Rule struct {
	Domain  string   `json:"domain,omitempty" yaml:"domain"`   // ex.: empresa.local
	Network string   `json:"network,omitempty" yaml:"network"` // ex.: 192.168.1.0/24 (gera a zona in-addr.arpa)
	Servers []string `json:"servers" yaml:"servers"`           // ex.: ["10.0.0.10", "10.0.0.11:53"]
	Comment string   `json:"comment,omitempty" yaml:"comment"`
}

type zone struct {
	suffix string // FQDN minúsculo com ponto final
	group  *upstream.Group
	label  string // para o log e o painel
}

// Table é o conjunto de regras pronto para consulta (imutável).
type Table struct {
	zones  []zone
	groups []*upstream.Group
}

// Normalize confere e normaliza as regras (sem abrir conexões).
func Normalize(rules []Rule) ([]Rule, error) {
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		r.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.Domain), "."))
		r.Network = strings.TrimSpace(r.Network)
		r.Comment = strings.TrimSpace(r.Comment)
		switch {
		case r.Domain == "" && r.Network == "":
			return nil, errors.New("informe o domínio ou a rede da regra")
		case r.Domain != "" && r.Network != "":
			return nil, errors.New("uma regra é de domínio ou de rede, não as duas")
		case r.Domain != "":
			if _, ok := dns.IsDomainName(r.Domain); !ok || strings.Contains(r.Domain, "*") {
				return nil, fmt.Errorf("domínio %q inválido", r.Domain)
			}
		default:
			p, err := netip.ParsePrefix(r.Network)
			if err != nil {
				return nil, fmt.Errorf("rede %q inválida (use 192.168.1.0/24)", r.Network)
			}
			if _, err := ReverseZones(p); err != nil {
				return nil, err
			}
			r.Network = p.Masked().String()
		}
		var servers []string
		for _, s := range r.Servers {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			addr, err := serverAddr(s)
			if err != nil {
				return nil, err
			}
			servers = append(servers, addr)
		}
		if len(servers) == 0 {
			return nil, fmt.Errorf("regra %s: informe ao menos um servidor", r.Domain+r.Network)
		}
		r.Servers = servers
		out = append(out, r)
	}
	return out, nil
}

// serverAddr aceita IP ou IP:porta (padrão 53).
func serverAddr(s string) (string, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.String(), nil
	}
	ip, err := netip.ParseAddr(strings.Trim(s, "[]"))
	if err != nil {
		return "", fmt.Errorf("servidor %q inválido (use o IP, ex.: 10.0.0.10)", s)
	}
	return net.JoinHostPort(ip.String(), "53"), nil
}

// Build monta a tabela, com um grupo de upstreams (em ordem: o segundo só
// responde se o primeiro falhar) por regra.
func Build(rules []Rule, timeout time.Duration, log *slog.Logger) (*Table, error) {
	rules, err := Normalize(rules)
	if err != nil {
		return nil, err
	}
	t := &Table{}
	for _, r := range rules {
		g, err := upstream.New(upstream.Options{Servers: r.Servers, Mode: upstream.ModeFailover, Timeout: timeout, Logger: log})
		if err != nil {
			t.Close()
			return nil, err
		}
		t.groups = append(t.groups, g)
		if r.Domain != "" {
			t.zones = append(t.zones, zone{suffix: r.Domain + ".", group: g, label: r.Domain})
			continue
		}
		p, _ := netip.ParsePrefix(r.Network)
		zs, _ := ReverseZones(p)
		for _, z := range zs {
			t.zones = append(t.zones, zone{suffix: z, group: g, label: r.Network})
		}
	}
	// O sufixo mais longo vence (sub.empresa.local antes de empresa.local).
	slices.SortStableFunc(t.zones, func(a, b zone) int { return len(b.suffix) - len(a.suffix) })
	return t, nil
}

// Match devolve o grupo de servidores para o nome (FQDN), se alguma regra cobre.
func (t *Table) Match(name string) (*upstream.Group, string, bool) {
	if t == nil {
		return nil, "", false
	}
	n := strings.ToLower(name)
	for _, z := range t.zones {
		if n == z.suffix || strings.HasSuffix(n, "."+z.suffix) {
			return z.group, z.label, true
		}
	}
	return nil, "", false
}

// Close fecha as conexões dos servidores.
func (t *Table) Close() {
	if t == nil {
		return
	}
	for _, g := range t.groups {
		g.Close()
	}
}

// Len diz quantas zonas a tabela atende.
func (t *Table) Len() int {
	if t == nil {
		return 0
	}
	return len(t.zones)
}

// ReverseZones converte uma rede nas zonas reversas que a cobrem: IPv4 em
// limites de octeto (/22 vira quatro zonas /24) e IPv6 em limites de nibble.
func ReverseZones(p netip.Prefix) ([]string, error) {
	p = p.Masked()
	if p.Addr().Is4() {
		bits := p.Bits()
		if bits < 8 {
			return nil, fmt.Errorf("rede %s grande demais (mínimo /8)", p)
		}
		zbits := (bits + 7) / 8 * 8
		if zbits-bits > 8 {
			return nil, fmt.Errorf("rede %s gera zonas demais", p)
		}
		count := 1 << (zbits - bits)
		base := p.Addr().As4()
		var out []string
		for i := 0; i < count; i++ {
			a := base
			// incrementa o octeto da borda
			oct := zbits/8 - 1
			a[oct] += byte(i)
			labels := make([]string, 0, zbits/8)
			for j := zbits/8 - 1; j >= 0; j-- {
				labels = append(labels, strconv.Itoa(int(a[j])))
			}
			out = append(out, strings.Join(labels, ".")+".in-addr.arpa.")
		}
		return out, nil
	}
	bits := p.Bits()
	if bits%4 != 0 || bits < 16 {
		return nil, fmt.Errorf("rede IPv6 %s: use um prefixo múltiplo de 4, a partir de /16", p)
	}
	hex := fmt.Sprintf("%x", p.Addr().AsSlice())
	nibbles := strings.Split(hex[:bits/4], "")
	slices.Reverse(nibbles)
	return []string{strings.Join(nibbles, ".") + ".ip6.arpa."}, nil
}

// privateReverse são as zonas reversas de endereços que não existem na
// internet: perguntar por elas lá fora só vaza a rede interna.
var privateReverse = func() []string {
	var out []string
	for _, p := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8"} {
		zs, _ := ReverseZones(netip.MustParsePrefix(p))
		out = append(out, zs...)
	}
	return append(out, "c.f.ip6.arpa.", "d.f.ip6.arpa.", "8.e.f.ip6.arpa.", "9.e.f.ip6.arpa.", "a.e.f.ip6.arpa.", "b.e.f.ip6.arpa.")
}()

// IsPrivateReverse diz se o nome é a consulta reversa de um IP privado.
func IsPrivateReverse(name string) bool {
	n := strings.ToLower(name)
	if !strings.HasSuffix(n, ".arpa.") {
		return false
	}
	for _, z := range privateReverse {
		if n == z || strings.HasSuffix(n, "."+z) {
			return true
		}
	}
	return false
}

// Manager guarda a tabela em uso: as regras do arquivo de configuração mais
// as do painel. Trocar as regras não derruba as consultas em andamento.
type Manager struct {
	table   atomic.Pointer[Table]
	config  []Rule
	timeout time.Duration
	log     *slog.Logger
	mu      sync.Mutex
	// OnChange é chamado depois de trocar as regras (ex.: limpar o cache,
	// que pode ter respostas de antes da regra). Defina antes de usar.
	OnChange func()
}

// NewManager confere as regras do arquivo e monta a tabela inicial.
func NewManager(config []Rule, timeout time.Duration, log *slog.Logger) (*Manager, error) {
	config, err := Normalize(config)
	if err != nil {
		return nil, fmt.Errorf("dns.conditional: %w", err)
	}
	m := &Manager{config: config, timeout: timeout, log: log}
	return m, m.Apply(nil)
}

// Config devolve as regras do arquivo (só leitura no painel).
func (m *Manager) Config() []Rule { return slices.Clone(m.config) }

// Apply troca as regras do painel. Um domínio ou rede que esteja no arquivo
// e no painel fica com a regra do painel.
func (m *Manager) Apply(panel []Rule) error {
	panel, err := Normalize(panel)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, r := range panel {
		k := r.Domain + r.Network
		if seen[k] {
			return fmt.Errorf("%s aparece em duas regras", k)
		}
		seen[k] = true
	}
	all := slices.Clone(panel)
	for _, r := range m.config {
		if !seen[r.Domain+r.Network] {
			all = append(all, r)
		}
	}
	t, err := Build(all, m.timeout, m.log)
	if err != nil {
		return err
	}
	m.mu.Lock()
	old := m.table.Swap(t)
	m.mu.Unlock()
	if old != nil {
		// As consultas que já pegaram a tabela antiga terminam antes de fechar.
		time.AfterFunc(2*m.timeout+time.Second, old.Close)
		if m.OnChange != nil {
			m.OnChange()
		}
	}
	return nil
}

// Match escolhe os servidores internos para o nome, se alguma regra cobre.
func (m *Manager) Match(name string) (*upstream.Group, string, bool) {
	if m == nil {
		return nil, "", false
	}
	return m.table.Load().Match(name)
}

// Close fecha os servidores em uso.
func (m *Manager) Close() {
	if m != nil {
		m.table.Load().Close()
	}
}

// HasPrivate diz se algum upstream é um IP privado (o roteador, um DNS
// interno): nesse caso a consulta reversa de IP privado pode ir para ele.
func HasPrivate(servers []string) bool {
	for _, s := range servers {
		host := s
		if i := strings.Index(host, "://"); i >= 0 {
			host = host[i+3:]
		}
		host, _, _ = strings.Cut(host, "/")
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
			return true
		}
	}
	return false
}
