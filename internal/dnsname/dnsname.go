// Package dnsname separa um nome DNS no domínio registrável (o que alguém
// registrou num registro, como exemplo.com.br) e no resto (os subdomínios).
package dnsname

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Registrable devolve o domínio registrável pelas regras ICANN da Public
// Suffix List, ignorando os sufixos "privados" (cloudfront.net, github.io…):
// abc123.cloudfront.net → cloudfront.net, que é o que existe no registro.
// ok = false para nomes de um rótulo só, IPs reversos (.arpa) e sufixos puros.
func Registrable(name string) (domain string, ok bool) {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	if n == "" || !strings.Contains(n, ".") || strings.HasSuffix(n, ".arpa") {
		return "", false
	}
	ps, icann := publicsuffix.PublicSuffix(n)
	for !icann { // sobe até achar o sufixo ICANN por baixo do privado
		i := strings.IndexByte(ps, '.')
		if i < 0 {
			return "", false
		}
		ps, icann = publicsuffix.PublicSuffix(ps[i+1:])
	}
	// Sufixos que não estão na lista (TLD inventado, "lan", "local") vêm como
	// não ICANN de um rótulo só; quem chega aqui tem um sufixo real.
	rest, found := strings.CutSuffix(n, "."+ps)
	if !found || rest == "" {
		return "", false
	}
	if j := strings.LastIndexByte(rest, '.'); j >= 0 {
		rest = rest[j+1:]
	}
	return rest + "." + ps, true
}

// Split devolve o domínio registrável, o rótulo registrado (sem o sufixo) e
// os subdomínios: www.mail.exemplo.com.br → exemplo.com.br, exemplo, www.mail.
func Split(name string) (domain, label, sub string, ok bool) {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	domain, ok = Registrable(n)
	if !ok {
		return "", "", "", false
	}
	label = domain[:strings.IndexByte(domain, '.')]
	sub = strings.TrimSuffix(strings.TrimSuffix(n, domain), ".")
	return domain, label, sub, true
}
