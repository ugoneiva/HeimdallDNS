// Package server atende as consultas DNS: controle de acesso, registros
// locais, filtro, cache e encaminhamento para os upstreams.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"

	"github.com/ugoneiva/HeimdallDNS/internal/cache"
	"github.com/ugoneiva/HeimdallDNS/internal/config"
	"github.com/ugoneiva/HeimdallDNS/internal/filter"
)

// Status de uma consulta, para o log ao vivo e as estatísticas.
const (
	StatusForwarded = "forwarded" // respondida pelo upstream
	StatusCached    = "cached"
	StatusStale     = "stale" // do cache, vencida, renovando em segundo plano
	StatusBlocked   = "blocked"
	StatusLocal     = "local"   // registro local
	StatusRefused   = "refused" // cliente fora das redes permitidas
	StatusError     = "error"   // upstream falhou (SERVFAIL)
	StatusInvalid   = "invalid" // pergunta malformada
)

// ednsSize é o tamanho de UDP anunciado (recomendação do DNS Flag Day 2020).
const ednsSize = 1232

// Event descreve uma consulta atendida.
type Event struct {
	Time     time.Time     `json:"time"`
	Client   netip.Addr    `json:"client"`
	Proto    string        `json:"proto"`
	Name     string        `json:"name"`
	Type     string        `json:"type"`
	Status   string        `json:"status"`
	Rcode    string        `json:"rcode"`
	Rule     string        `json:"rule,omitempty"`
	Upstream string        `json:"upstream,omitempty"`
	Duration time.Duration `json:"duration_ns"`
}

// Exchanger é o que o servidor precisa dos upstreams.
type Exchanger interface {
	Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, string, error)
}

type Options struct {
	Listen       []string
	Allowed      []netip.Prefix
	BlockMode    string
	BlockTTL     uint32
	LocalRecords map[string][]netip.Addr // nome FQDN minúsculo → IPs
	Cache        *cache.Cache
	Filter       func() *filter.Matcher
	Upstream     Exchanger
	Timeout      time.Duration
	Logger       *slog.Logger
	OnQuery      func(Event) // chamado para cada consulta; não deve bloquear
}

type Counters struct {
	Total     uint64 `json:"total"`
	Forwarded uint64 `json:"forwarded"`
	Cached    uint64 `json:"cached"`
	Blocked   uint64 `json:"blocked"`
	Local     uint64 `json:"local"`
	Refused   uint64 `json:"refused"`
	Errors    uint64 `json:"errors"`
}

type Server struct {
	opts    Options
	log     *slog.Logger
	sf      singleflight.Group
	servers []*dns.Server
	addrs   []net.Addr

	total, forwarded, cached, blocked, local, refused, errs atomic.Uint64
}

func New(opts Options) *Server {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.Filter == nil {
		opts.Filter = func() *filter.Matcher { return nil }
	}
	return &Server{opts: opts, log: opts.Logger}
}

// Start abre UDP e TCP em cada endereço. Falha de bind volta como erro.
func (s *Server) Start() error {
	for _, addr := range s.opts.Listen {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			s.Shutdown(context.Background())
			return fmt.Errorf("udp %s: %w", addr, err)
		}
		// O TCP usa a mesma porta que o UDP recebeu (importa quando a porta é 0).
		tcpAddr := pc.LocalAddr().String()
		ln, err := net.Listen("tcp", tcpAddr)
		if err != nil {
			pc.Close()
			s.Shutdown(context.Background())
			return fmt.Errorf("tcp %s: %w", tcpAddr, err)
		}
		for _, srv := range []*dns.Server{
			{PacketConn: pc, Handler: s},
			{Listener: ln, Handler: s, ReadTimeout: 5 * time.Second, IdleTimeout: func() time.Duration { return 10 * time.Second }},
		} {
			s.servers = append(s.servers, srv)
			go func() {
				if err := srv.ActivateAndServe(); err != nil {
					s.log.Error("servidor DNS parou", "erro", err)
				}
			}()
		}
		s.addrs = append(s.addrs, pc.LocalAddr())
		s.log.Info("DNS ouvindo", "endereco", tcpAddr)
	}
	return nil
}

// Addrs devolve os endereços UDP efetivos (útil quando a porta é 0).
func (s *Server) Addrs() []net.Addr { return s.addrs }

func (s *Server) Shutdown(ctx context.Context) {
	for _, srv := range s.servers {
		_ = srv.ShutdownContext(ctx)
	}
}

func (s *Server) Counters() Counters {
	return Counters{
		Total: s.total.Load(), Forwarded: s.forwarded.Load(), Cached: s.cached.Load(),
		Blocked: s.blocked.Load(), Local: s.local.Load(), Refused: s.refused.Load(), Errors: s.errs.Load(),
	}
}

func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	ev := Event{Time: time.Now(), Proto: "udp"}
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		ev.Proto = "tcp"
	}
	ev.Client = addrOf(w.RemoteAddr())
	s.total.Add(1)

	resp := s.handle(r, &ev)
	if resp != nil {
		s.write(w, r, resp, ev.Proto)
		ev.Rcode = dns.RcodeToString[resp.Rcode]
	} else {
		ev.Rcode = "DROP"
		if ev.Proto == "tcp" {
			_ = w.Close()
		}
	}
	ev.Duration = time.Since(ev.Time)

	switch ev.Status {
	case StatusForwarded:
		s.forwarded.Add(1)
	case StatusCached, StatusStale:
		s.cached.Add(1)
	case StatusBlocked:
		s.blocked.Add(1)
	case StatusLocal:
		s.local.Add(1)
	case StatusRefused:
		s.refused.Add(1)
	case StatusError:
		s.errs.Add(1)
	}
	if s.opts.OnQuery != nil {
		s.opts.OnQuery(ev)
	}
}

// handle devolve a resposta (sem EDNS; write cuida disso) ou nil para não responder.
func (s *Server) handle(r *dns.Msg, ev *Event) *dns.Msg {
	if !s.allowed(ev.Client) {
		ev.Status = StatusRefused
		return reply(r, dns.RcodeRefused)
	}
	if r.Response || len(r.Question) != 1 {
		ev.Status = StatusInvalid
		return reply(r, dns.RcodeFormatError)
	}
	q := r.Question[0]
	ev.Name = strings.ToLower(q.Name)
	ev.Type = dns.TypeToString[q.Qtype]
	if ev.Type == "" {
		ev.Type = fmt.Sprintf("TYPE%d", q.Qtype)
	}
	if r.Opcode != dns.OpcodeQuery {
		ev.Status = StatusInvalid
		return reply(r, dns.RcodeNotImplemented)
	}

	if m := s.localAnswer(r, ev.Name); m != nil {
		ev.Status = StatusLocal
		return m
	}

	switch res := s.opts.Filter().Match(ev.Name); res.Verdict {
	case filter.Blocked:
		ev.Status, ev.Rule = StatusBlocked, res.Rule
		return s.blockedAnswer(r, ev.Name)
	case filter.Allowed:
		ev.Rule = "@@" + res.Rule // liberado por exceção; segue o fluxo normal
	}

	do := false
	if opt := r.IsEdns0(); opt != nil {
		do = opt.Do()
	}
	key := cache.Key{Name: ev.Name, Qtype: q.Qtype, Qclass: q.Qclass, DO: do}
	if m, stale, ok := s.opts.Cache.Get(key); ok {
		ev.Status = StatusCached
		if stale {
			ev.Status = StatusStale
			go s.resolve(key, r.CheckingDisabled)
		}
		return m
	}

	m, ups, err := s.resolve(key, r.CheckingDisabled)
	ev.Upstream = ups
	if err != nil {
		ev.Status = StatusError
		s.log.Debug("upstream falhou", "nome", ev.Name, "erro", err)
		return reply(r, dns.RcodeServerFailure)
	}
	ev.Status = StatusForwarded
	return m.Copy()
}

type resolved struct {
	msg  *dns.Msg
	addr string
}

// resolve consulta o upstream e guarda no cache. Consultas iguais que chegam
// ao mesmo tempo esperam a mesma resposta (uma ida só ao upstream).
func (s *Server) resolve(key cache.Key, cd bool) (*dns.Msg, string, error) {
	sfKey := fmt.Sprintf("%s|%d|%d|%t|%t", key.Name, key.Qtype, key.Qclass, key.DO, cd)
	v, err, _ := s.sf.Do(sfKey, func() (any, error) {
		req := new(dns.Msg)
		req.SetQuestion(key.Name, key.Qtype)
		req.Question[0].Qclass = key.Qclass
		req.RecursionDesired = true
		req.CheckingDisabled = cd
		req.AuthenticatedData = true
		req.SetEdns0(ednsSize, key.DO)
		ctx, cancel := context.WithTimeout(context.Background(), s.opts.Timeout)
		defer cancel()
		resp, addr, err := s.opts.Upstream.Exchange(ctx, req)
		if err != nil {
			return nil, err
		}
		if !cd {
			s.opts.Cache.Set(key, resp)
		}
		return resolved{resp, addr}, nil
	})
	if err != nil {
		return nil, "", err
	}
	res := v.(resolved)
	return res.msg, res.addr, nil
}

func (s *Server) localAnswer(r *dns.Msg, name string) *dns.Msg {
	ips, ok := s.opts.LocalRecords[name]
	if !ok {
		return nil
	}
	q := r.Question[0]
	m := reply(r, dns.RcodeSuccess)
	m.Authoritative = true
	for _, ip := range ips {
		hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: 300}
		switch {
		case q.Qtype == dns.TypeA && ip.Is4():
			hdr.Rrtype = dns.TypeA
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: ip.AsSlice()})
		case q.Qtype == dns.TypeAAAA && ip.Is6():
			hdr.Rrtype = dns.TypeAAAA
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: ip.AsSlice()})
		}
	}
	return m
}

func (s *Server) blockedAnswer(r *dns.Msg, name string) *dns.Msg {
	q := r.Question[0]
	var m *dns.Msg
	switch s.opts.BlockMode {
	case config.BlockDrop:
		return nil
	case config.BlockRefused:
		m = reply(r, dns.RcodeRefused)
	case config.BlockNXDomain:
		m = reply(r, dns.RcodeNameError)
		m.Ns = []dns.RR{s.soa(q.Name)}
	default: // null
		m = reply(r, dns.RcodeSuccess)
		hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: s.opts.BlockTTL}
		switch q.Qtype {
		case dns.TypeA:
			hdr.Rrtype = dns.TypeA
			m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.IPv4zero.To4()}}
		case dns.TypeAAAA:
			hdr.Rrtype = dns.TypeAAAA
			m.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.IPv6zero}}
		default:
			m.Ns = []dns.RR{s.soa(q.Name)}
		}
	}
	m.Extra = append(m.Extra, blockedEDE())
	return m
}

// soa sintética, para o cliente guardar a resposta negativa por BlockTTL.
func (s *Server) soa(name string) dns.RR {
	return &dns.SOA{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: s.opts.BlockTTL},
		Ns:  "heimdall.", Mbox: "hostmaster.heimdall.",
		Serial: 1, Refresh: 1800, Retry: 900, Expire: 604800, Minttl: s.opts.BlockTTL,
	}
}

// blockedEDE marca a resposta com o Extended DNS Error 15 (Blocked, RFC 8914).
// Vai num OPT provisório que write funde no OPT final (ou descarta sem EDNS).
func blockedEDE() dns.RR {
	o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	o.Option = append(o.Option, &dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeBlocked, ExtraText: "HeimdallDNS"})
	return o
}

// write ajusta a resposta ao pedido do cliente (ID, caixa da pergunta, EDNS,
// truncamento) e envia.
func (s *Server) write(w dns.ResponseWriter, r, m *dns.Msg, proto string) {
	m.Id = r.Id
	m.Response = true
	m.Opcode = r.Opcode
	m.RecursionDesired = r.RecursionDesired
	m.RecursionAvailable = true
	m.Question = r.Question

	var opts []dns.EDNS0
	extra := m.Extra[:0]
	for _, rr := range m.Extra {
		if o, ok := rr.(*dns.OPT); ok {
			opts = append(opts, o.Option...)
			continue
		}
		extra = append(extra, rr)
	}
	m.Extra = extra

	size := dns.MinMsgSize
	if ro := r.IsEdns0(); ro != nil {
		o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		o.SetUDPSize(ednsSize)
		o.SetDo(ro.Do())
		for _, e := range opts {
			if _, ok := e.(*dns.EDNS0_EDE); ok {
				o.Option = append(o.Option, e)
			}
		}
		m.Extra = append(m.Extra, o)
		size = max(dns.MinMsgSize, min(int(ro.UDPSize()), ednsSize))
	}
	if proto == "tcp" {
		size = dns.MaxMsgSize
	}
	m.Compress = true
	m.Truncate(size)
	if err := w.WriteMsg(m); err != nil {
		s.log.Debug("falha ao responder", "erro", err)
	}
}

func (s *Server) allowed(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	for _, p := range s.opts.Allowed {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func reply(r *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(r, rcode)
	return m
}

func addrOf(a net.Addr) netip.Addr {
	var ip net.IP
	switch v := a.(type) {
	case *net.UDPAddr:
		ip = v.IP
	case *net.TCPAddr:
		ip = v.IP
	default:
		if ap, err := netip.ParseAddrPort(a.String()); err == nil {
			return ap.Addr().Unmap()
		}
		return netip.Addr{}
	}
	addr, _ := netip.AddrFromSlice(ip)
	return addr.Unmap()
}
