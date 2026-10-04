// Package filter decide se um domínio deve ser bloqueado, a partir das listas
// de bloqueio e das regras próprias.
package filter

import (
	"bufio"
	"io"
	"regexp"
	"strings"
)

type Verdict uint8

const (
	Pass    Verdict = iota // nenhuma regra casou
	Blocked                // casou com uma regra de bloqueio
	Allowed                // casou com uma exceção (vence o bloqueio)
)

func (v Verdict) String() string {
	switch v {
	case Blocked:
		return "blocked"
	case Allowed:
		return "allowed"
	}
	return "pass"
}

// Result diz o veredito e a regra responsável, para a pergunta
// "por que este domínio foi bloqueado?".
type Result struct {
	Verdict  Verdict
	Rule     string
	Category string // CategoryThreat quando o bloqueio veio de uma lista de ameaças
}

// CategoryThreat marca listas de ameaças (malware, phishing, C2): um bloqueio
// por elas vira alerta de segurança, não só "anúncio bloqueado".
const CategoryThreat = "threat"

type ruleSet struct {
	exact, wild domainSet
	regex       []*regexp.Regexp
}

func (r *ruleSet) match(d string) (string, bool) {
	if r.exact.has(d) {
		return d, true
	}
	if m, ok := r.wild.matchSuffix(d); ok {
		return "||" + m + "^", true
	}
	for _, re := range r.regex {
		if re.MatchString(d) {
			return "/" + re.String() + "/", true
		}
	}
	return "", false
}

func (r *ruleSet) size() int { return r.exact.Len() + r.wild.Len() + len(r.regex) }

// Matcher é imutável: o Manager monta um novo e troca o ponteiro atomicamente,
// então as consultas nunca esperam por lock.
type Matcher struct {
	block, allow, threat ruleSet
}

// Match recebe o nome como vem na pergunta DNS (com ou sem ponto final).
func (m *Matcher) Match(name string) Result {
	if m == nil {
		return Result{}
	}
	d := strings.ToLower(strings.TrimSuffix(name, "."))
	if r, ok := m.allow.match(d); ok {
		return Result{Verdict: Allowed, Rule: r}
	}
	if r, ok := m.threat.match(d); ok {
		return Result{Verdict: Blocked, Rule: r, Category: CategoryThreat}
	}
	if r, ok := m.block.match(d); ok {
		return Result{Verdict: Blocked, Rule: r}
	}
	return Result{}
}

// Rules devolve quantas regras de bloqueio e de exceção estão carregadas.
func (m *Matcher) Rules() (block, allow int) {
	if m == nil {
		return 0, 0
	}
	return m.block.size() + m.threat.size(), m.allow.size()
}

// ListStats conta o resultado da leitura de uma lista.
type ListStats struct {
	Rules   int
	Invalid int
}

// Builder acumula regras de várias listas e monta o Matcher.
type Builder struct {
	blockExact, blockWild, allowExact, allowWild []string
	blockRe, allowRe                             []*regexp.Regexp
	threatExact, threatWild                      []string
	threatRe                                     []*regexp.Regexp
	seenRe                                       map[string]bool
	threatMode                                   bool // bloqueios vão para o conjunto de ameaças
}

func NewBuilder() *Builder { return &Builder{seenRe: map[string]bool{}} }

// AddLine acrescenta uma regra. wildcardPlain faz um domínio simples valer
// também para os subdomínios (usado nas regras próprias do usuário).
func (b *Builder) AddLine(line string, wildcardPlain bool) lineKind {
	rules, kind := parseLine(line, wildcardPlain)
	if kind != lineRule {
		return kind
	}
	for _, r := range rules {
		if r.regex != "" {
			key := r.regex
			if r.allow {
				key = "@@" + key
			}
			if b.seenRe[key] {
				continue
			}
			re, err := regexp.Compile(r.regex)
			if err != nil {
				return lineBad
			}
			b.seenRe[key] = true
			switch {
			case r.allow:
				b.allowRe = append(b.allowRe, re)
			case b.threatMode:
				b.threatRe = append(b.threatRe, re)
			default:
				b.blockRe = append(b.blockRe, re)
			}
			continue
		}
		switch {
		case r.allow && r.wildcard:
			b.allowWild = append(b.allowWild, r.domain)
		case r.allow:
			b.allowExact = append(b.allowExact, r.domain)
		case r.wildcard && b.threatMode:
			b.threatWild = append(b.threatWild, r.domain)
		case b.threatMode:
			b.threatExact = append(b.threatExact, r.domain)
		case r.wildcard:
			b.blockWild = append(b.blockWild, r.domain)
		default:
			b.blockExact = append(b.blockExact, r.domain)
		}
	}
	return lineRule
}

// AddThreatList lê uma lista de ameaças: os bloqueios dela saem com CategoryThreat.
func (b *Builder) AddThreatList(r io.Reader) (ListStats, error) {
	b.threatMode = true
	defer func() { b.threatMode = false }()
	return b.AddList(r)
}

// AddList lê uma lista inteira (formato hosts, Adblock ou domínios).
func (b *Builder) AddList(r io.Reader) (ListStats, error) {
	var st ListStats
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		switch b.AddLine(sc.Text(), false) {
		case lineRule:
			st.Rules++
		case lineBad:
			st.Invalid++
		}
	}
	return st, sc.Err()
}

func (b *Builder) Build() *Matcher {
	return &Matcher{
		block:  ruleSet{exact: newDomainSet(b.blockExact), wild: newDomainSet(b.blockWild), regex: b.blockRe},
		allow:  ruleSet{exact: newDomainSet(b.allowExact), wild: newDomainSet(b.allowWild), regex: b.allowRe},
		threat: ruleSet{exact: newDomainSet(b.threatExact), wild: newDomainSet(b.threatWild), regex: b.threatRe},
	}
}
