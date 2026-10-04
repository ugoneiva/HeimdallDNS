package filter

import (
	"slices"
	"strings"
)

// domainSet é um conjunto imutável e compacto de domínios: todos os nomes
// ficam concatenados numa string só, com um índice ordenado de deslocamentos.
// Gasta ~4 bytes por domínio além do próprio texto (um map gastaria ~10x mais)
// e a busca é binária, sem lock.
type domainSet struct {
	data string
	offs []uint32 // len = n+1; o domínio i é data[offs[i]:offs[i+1]]
}

func newDomainSet(domains []string) domainSet {
	slices.Sort(domains)
	domains = slices.Compact(domains)
	var b strings.Builder
	size := 0
	for _, d := range domains {
		size += len(d)
	}
	b.Grow(size)
	offs := make([]uint32, 0, len(domains)+1)
	for _, d := range domains {
		offs = append(offs, uint32(b.Len()))
		b.WriteString(d)
	}
	offs = append(offs, uint32(b.Len()))
	return domainSet{data: b.String(), offs: offs}
}

func (s domainSet) Len() int {
	if len(s.offs) == 0 {
		return 0
	}
	return len(s.offs) - 1
}

func (s domainSet) at(i int) string { return s.data[s.offs[i]:s.offs[i+1]] }

func (s domainSet) has(d string) bool {
	lo, hi := 0, s.Len()
	for lo < hi {
		m := int(uint(lo+hi) >> 1)
		switch c := strings.Compare(s.at(m), d); {
		case c == 0:
			return true
		case c < 0:
			lo = m + 1
		default:
			hi = m
		}
	}
	return false
}

// matchSuffix procura d e cada domínio pai (a.b.c → b.c → c) e devolve o
// primeiro que estiver no conjunto.
func (s domainSet) matchSuffix(d string) (string, bool) {
	if s.Len() == 0 {
		return "", false
	}
	for {
		if s.has(d) {
			return d, true
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			return "", false
		}
		d = d[i+1:]
	}
}
