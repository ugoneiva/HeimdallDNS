// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package filter

import (
	"net/netip"
	"strings"
)

// rule é uma regra extraída de uma linha de lista.
type rule struct {
	domain   string // vazio quando a regra é regex
	regex    string
	wildcard bool // também vale para os subdomínios
	allow    bool // exceção (@@)
}

type lineKind int

const (
	lineRule lineKind = iota
	lineSkip          // comentário, linha vazia ou nome reservado
	lineBad           // formato não suportado
)

// Nomes que aparecem nos arquivos hosts e nunca devem ser bloqueados.
var reservedNames = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true,
	"broadcasthost": true, "ip6-localhost": true, "ip6-loopback": true,
	"ip6-localnet": true, "ip6-mcastprefix": true, "ip6-allnodes": true,
	"ip6-allrouters": true, "ip6-allhosts": true, "0.0.0.0": true,
}

// parseLine entende os formatos mais usados:
//
//	0.0.0.0 dominio [outro...]   hosts (StevenBlack etc.) — só o nome exato
//	dominio                      lista simples — só o nome exato
//	*.dominio                    o domínio e os subdomínios
//	||dominio^                   Adblock — o domínio e os subdomínios
//	@@||dominio^                 exceção Adblock
//	/regex/                      expressão regular (RE2)
//
// Regras Adblock com modificadores ($client, $third-party…) são ignoradas,
// exceto $important, que não muda nada aqui.
func parseLine(line string, wildcardPlain bool) ([]rule, lineKind) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' || line[0] == '!' || line[0] == '[' {
		return nil, lineSkip
	}
	allow := false
	if strings.HasPrefix(line, "@@") {
		allow, line = true, line[2:]
	}
	if len(line) > 2 && line[0] == '/' && line[len(line)-1] == '/' {
		return []rule{{regex: line[1 : len(line)-1], allow: allow}}, lineRule
	}
	if strings.HasPrefix(line, "||") {
		rest := line[2:]
		end := strings.IndexAny(rest, "^$|/")
		tail := ""
		if end >= 0 {
			rest, tail = rest[:end], rest[end:]
		}
		switch tail {
		case "", "^", "^|", "^$important", "$important":
		default:
			return nil, lineBad
		}
		d, ok := normalize(rest)
		if !ok {
			return nil, lineBad
		}
		return []rule{{domain: d, wildcard: true, allow: allow}}, lineRule
	}
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	fields := strings.Fields(line)
	switch {
	case len(fields) == 0:
		return nil, lineSkip
	case len(fields) >= 2:
		if _, err := netip.ParseAddr(fields[0]); err != nil {
			return nil, lineBad
		}
		var out []rule
		for _, f := range fields[1:] {
			if reservedNames[strings.ToLower(f)] {
				continue
			}
			if d, ok := normalize(f); ok {
				out = append(out, rule{domain: d, allow: allow})
			}
		}
		if len(out) == 0 {
			return nil, lineSkip
		}
		return out, lineRule
	}
	f, wild := fields[0], wildcardPlain
	if strings.HasPrefix(f, "*.") {
		f, wild = f[2:], true
	}
	if reservedNames[strings.ToLower(f)] {
		return nil, lineSkip
	}
	d, ok := normalize(f)
	if !ok {
		return nil, lineBad
	}
	return []rule{{domain: d, wildcard: wild, allow: allow}}, lineRule
}

// normalize deixa o domínio em minúsculas, sem ponto final, e recusa o que não
// for um nome DNS válido (inclusive endereços IP).
func normalize(d string) (string, bool) {
	d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
	if d == "" || len(d) > 253 {
		return "", false
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return "", false
	}
	label := 0
	for i := 0; i < len(d); i++ {
		c := d[i]
		switch {
		case c == '.':
			if label == 0 {
				return "", false
			}
			label = 0
			continue
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return "", false
		}
		label++
		if label > 63 {
			return "", false
		}
	}
	if label == 0 {
		return "", false
	}
	return d, true
}
