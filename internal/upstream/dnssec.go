package upstream

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Nomes do teste de validação. dnssec-failed.org tem a assinatura quebrada de
// propósito (mantido pela Comcast para isso): quem valida responde SERVFAIL.
// Os outros são zonas assinadas, que um validador devolve com o bit AD.
var (
	dnssecBroken = "dnssec-failed.org."
	dnssecSigned = []string{"isc.org.", "ietf.org.", "cloudflare.com."}
)

const dnssecEvery = 6 * time.Hour

// usable devolve os upstreams a usar: todos, ou só os que validam DNSSEC
// quando exigido (se nenhum validar, todos, para não derrubar a rede).
func (st *set) usable() []*member {
	if !st.requireDNSSEC {
		return st.members
	}
	ok := make([]*member, 0, len(st.members))
	for _, m := range st.members {
		if m.dnssec.Load() == dnssecYes {
			ok = append(ok, m)
		}
	}
	if len(ok) == 0 {
		return st.members
	}
	return ok
}

func inUse(st *set, m *member) bool { return slices.Contains(st.usable(), m) }

// checkDNSSEC testa um upstream: o domínio quebrado tem que falhar e um
// assinado tem que vir validado.
func (g *Group) checkDNSSEC(ctx context.Context, m *member) int32 {
	q := func(name string) (*dns.Msg, error) {
		req := new(dns.Msg)
		req.SetQuestion(name, dns.TypeA)
		req.RecursionDesired = true
		req.AuthenticatedData = true
		req.SetEdns0(1232, true)
		return g.exchange(ctx, m, req)
	}
	broken, err := q(dnssecBroken)
	if err != nil {
		return dnssecUnknown
	}
	if broken.Rcode != dns.RcodeServerFailure {
		return dnssecNo // respondeu um nome com assinatura inválida
	}
	for _, n := range dnssecSigned {
		if r, err := q(n); err == nil && r.Rcode == dns.RcodeSuccess {
			if r.AuthenticatedData {
				return dnssecYes
			}
			return dnssecNo
		}
	}
	return dnssecUnknown
}

// CheckDNSSEC testa todos os upstreams em paralelo e registra o resultado.
func (g *Group) CheckDNSSEC(ctx context.Context) {
	st := g.cur.Load()
	var wg sync.WaitGroup
	for _, m := range st.members {
		wg.Go(func() {
			r := g.checkDNSSEC(ctx, m)
			if r == dnssecUnknown && m.dnssec.Load() != dnssecUnknown {
				return // falha passageira: mantém o último resultado
			}
			m.dnssec.Store(r)
			if r == dnssecNo {
				g.log.Warn("upstream não valida DNSSEC", "upstream", m.addr)
			}
		})
	}
	wg.Wait()
	if st.requireDNSSEC && len(st.usable()) == len(st.members) && !slices.ContainsFunc(st.members, func(m *member) bool { return m.dnssec.Load() == dnssecYes }) {
		g.log.Error("dnssec exigido, mas nenhum upstream valida: usando todos; troque os upstreams")
	}
}
