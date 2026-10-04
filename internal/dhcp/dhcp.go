// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

// Package dhcp é um servidor DHCPv4 opcional. Além de entregar endereços,
// ele alimenta o radar (MAC e nome de cada aparelho direto da concessão) e o
// DNS local (<nome>.<domínio> e o reverso resolvem sozinhos).
//
// Dois servidores DHCP na mesma rede brigam: desligue o do roteador antes.
package dhcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
)

const (
	offerHold    = time.Minute      // um IP oferecido fica guardado para o cliente por 1 min
	declineHold  = 10 * time.Minute // IP recusado (conflito) fica fora por 10 min
	stickyLeases = 7 * 24 * time.Hour
)

type Lease struct {
	IP       netip.Addr `json:"ip"`
	MAC      string     `json:"mac"`
	Hostname string     `json:"hostname,omitempty"`
	Expires  time.Time  `json:"expires"`
}

type Reservation struct {
	MAC  string     `json:"mac"`
	IP   netip.Addr `json:"ip"`
	Name string     `json:"name,omitempty"`
}

// Persister guarda concessões e reservas (o store SQLite).
type Persister interface {
	DHCPLeases() ([]Lease, error)
	SaveDHCPLease(Lease) error
	DeleteDHCPLease(netip.Addr) error
	DHCPReservations() ([]Reservation, error)
	SaveDHCPReservation(Reservation) error
	DeleteDHCPReservation(mac string) error
}

type Options struct {
	Interface  string
	Start, End netip.Addr
	Subnet     netip.Prefix
	ServerIP   netip.Addr // identificador do servidor (o IP desta máquina na interface)
	Routers    []netip.Addr
	DNS        []netip.Addr
	Domain     string
	LeaseTime  time.Duration
	Store      Persister
	OnLease    func(Lease) // concessão confirmada (radar e DNS local)
	Logger     *slog.Logger
	Now        func() time.Time
}

type offer struct {
	ip    netip.Addr
	until time.Time
}

type Server struct {
	opts Options
	log  *slog.Logger

	mu       sync.Mutex
	leases   map[netip.Addr]*Lease
	byMAC    map[string]netip.Addr
	resv     map[string]Reservation // por MAC
	resvIP   map[netip.Addr]string
	offers   map[string]offer
	declined map[netip.Addr]time.Time
}

func New(o Options) (*Server, error) {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.LeaseTime <= 0 {
		o.LeaseTime = 24 * time.Hour
	}
	if !o.Start.Is4() || !o.End.Is4() || o.End.Less(o.Start) {
		return nil, errors.New("dhcp: faixa inválida (range_start/range_end IPv4, início ≤ fim)")
	}
	if !o.Subnet.Contains(o.Start) || !o.Subnet.Contains(o.End) {
		return nil, fmt.Errorf("dhcp: a faixa %s–%s não está na sub-rede %s", o.Start, o.End, o.Subnet)
	}
	if !o.ServerIP.Is4() {
		return nil, errors.New("dhcp: sem IP do servidor na interface")
	}
	if len(o.DNS) == 0 {
		o.DNS = []netip.Addr{o.ServerIP}
	}
	s := &Server{opts: o, log: o.Logger, leases: map[netip.Addr]*Lease{}, byMAC: map[string]netip.Addr{},
		resv: map[string]Reservation{}, resvIP: map[netip.Addr]string{}, offers: map[string]offer{},
		declined: map[netip.Addr]time.Time{}}
	if o.Store != nil {
		ls, err := o.Store.DHCPLeases()
		if err != nil {
			return nil, err
		}
		for _, l := range ls {
			l := l
			s.leases[l.IP], s.byMAC[l.MAC] = &l, l.IP
		}
		rs, err := o.Store.DHCPReservations()
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			s.resv[r.MAC], s.resvIP[r.IP] = r, r.MAC
		}
	}
	return s, nil
}

func normMAC(hw net.HardwareAddr) string { return strings.ToLower(hw.String()) }

func ip4(a netip.Addr) net.IP { return a.AsSlice() }

func addrOf(ip net.IP) netip.Addr {
	a, _ := netip.AddrFromSlice(ip.To4())
	return a
}

func (s *Server) inRange(a netip.Addr) bool {
	return a.Is4() && !a.Less(s.opts.Start) && !s.opts.End.Less(a)
}

// usable diz se o IP pode ir para o MAC (com a trava já tomada).
func (s *Server) usable(a netip.Addr, mac string, now time.Time) bool {
	if !a.Is4() || !s.opts.Subnet.Contains(a) || a == s.opts.ServerIP || slices.Contains(s.opts.Routers, a) {
		return false
	}
	if a == s.opts.Subnet.Addr() || a == broadcast(s.opts.Subnet) {
		return false
	}
	if owner, ok := s.resvIP[a]; ok && owner != mac {
		return false
	}
	if r, ok := s.resv[mac]; ok && r.IP != a {
		return false // quem tem reserva só recebe o IP reservado
	}
	if l, ok := s.leases[a]; ok && l.MAC != mac && l.Expires.After(now) {
		return false
	}
	if until, ok := s.declined[a]; ok && until.After(now) {
		return false
	}
	for m, o := range s.offers {
		if m != mac && o.ip == a && o.until.After(now) {
			return false
		}
	}
	// IP reservado só vale para o dono; IP fora da faixa só por reserva.
	if _, reserved := s.resvIP[a]; !reserved && !s.inRange(a) {
		return false
	}
	return true
}

// pick escolhe o IP para o MAC: reserva, último IP dele, o pedido, um nunca
// usado e, por fim, o de concessão vencida há mais tempo.
func (s *Server) pick(mac string, requested netip.Addr, now time.Time) (netip.Addr, bool) {
	if r, ok := s.resv[mac]; ok {
		return r.IP, s.usable(r.IP, mac, now)
	}
	if ip, ok := s.byMAC[mac]; ok && s.usable(ip, mac, now) {
		return ip, true
	}
	if o, ok := s.offers[mac]; ok && o.until.After(now) && s.usable(o.ip, mac, now) {
		return o.ip, true
	}
	if requested.IsValid() && s.usable(requested, mac, now) {
		return requested, true
	}
	var oldest netip.Addr
	var oldestExp time.Time
	for a := s.opts.Start; !s.opts.End.Less(a); a = a.Next() {
		if !s.usable(a, mac, now) {
			continue
		}
		l, leased := s.leases[a]
		if !leased {
			return a, true
		}
		if !oldest.IsValid() || l.Expires.Before(oldestExp) {
			oldest, oldestExp = a, l.Expires
		}
	}
	return oldest, oldest.IsValid()
}

func broadcast(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	ones := p.Bits()
	for i := ones; i < 32; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	return netip.AddrFrom4(b)
}

func (s *Server) options(req *dhcpv4.DHCPv4, mt dhcpv4.MessageType, yiaddr netip.Addr) (*dhcpv4.DHCPv4, error) {
	mask := net.CIDRMask(s.opts.Subnet.Bits(), 32)
	mods := []dhcpv4.Modifier{
		dhcpv4.WithMessageType(mt),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(ip4(s.opts.ServerIP))),
		dhcpv4.WithNetmask(mask),
		dhcpv4.WithOption(dhcpv4.OptBroadcastAddress(ip4(broadcast(s.opts.Subnet)))),
	}
	if len(s.opts.Routers) > 0 {
		r := make([]net.IP, len(s.opts.Routers))
		for i, a := range s.opts.Routers {
			r[i] = ip4(a)
		}
		mods = append(mods, dhcpv4.WithRouter(r...))
	}
	d := make([]net.IP, len(s.opts.DNS))
	for i, a := range s.opts.DNS {
		d[i] = ip4(a)
	}
	mods = append(mods, dhcpv4.WithDNS(d...))
	if s.opts.Domain != "" {
		mods = append(mods, dhcpv4.WithOption(dhcpv4.OptDomainName(s.opts.Domain)))
	}
	if yiaddr.IsValid() {
		lt := s.opts.LeaseTime
		mods = append(mods, dhcpv4.WithYourIP(ip4(yiaddr)),
			dhcpv4.WithLeaseTime(uint32(lt/time.Second)),
			dhcpv4.WithOption(dhcpv4.OptRenewTimeValue(lt/2)),
			dhcpv4.WithOption(dhcpv4.OptRebindingTimeValue(lt*7/8)))
	}
	return dhcpv4.NewReplyFromRequest(req, mods...)
}

func (s *Server) nak(req *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
	r, err := dhcpv4.NewReplyFromRequest(req, dhcpv4.WithMessageType(dhcpv4.MessageTypeNak),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(ip4(s.opts.ServerIP))))
	if err != nil {
		return nil
	}
	return r
}

// Handle decide a resposta para uma mensagem (nil = não responder). Não toca
// em rede: dá para testar sem socket.
func (s *Server) Handle(req *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
	if req.OpCode != dhcpv4.OpcodeBootRequest || len(req.ClientHWAddr) != 6 {
		return nil
	}
	mac := normMAC(req.ClientHWAddr)
	now := s.opts.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	switch req.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		ip, ok := s.pick(mac, addrOf(req.RequestedIPAddress()), now)
		if !ok {
			s.log.Warn("DHCP: faixa esgotada", "mac", mac)
			return nil
		}
		s.offers[mac] = offer{ip: ip, until: now.Add(offerHold)}
		r, err := s.options(req, dhcpv4.MessageTypeOffer, ip)
		if err != nil {
			return nil
		}
		return r

	case dhcpv4.MessageTypeRequest:
		if sid := req.ServerIdentifier(); sid != nil && !sid.IsUnspecified() && addrOf(sid) != s.opts.ServerIP {
			delete(s.offers, mac) // o cliente escolheu outro servidor
			return nil
		}
		want := addrOf(req.RequestedIPAddress())
		if !want.IsValid() || want.IsUnspecified() {
			want = addrOf(req.ClientIPAddr) // renovação
		}
		if !want.IsValid() || !s.usable(want, mac, now) {
			s.log.Info("DHCP: pedido negado", "mac", mac, "ip", want)
			return s.nak(req)
		}
		l := &Lease{IP: want, MAC: mac, Hostname: cleanHost(req.HostName()), Expires: now.Add(s.opts.LeaseTime)}
		if old, ok := s.byMAC[mac]; ok && old != want {
			delete(s.leases, old)
			if s.opts.Store != nil {
				_ = s.opts.Store.DeleteDHCPLease(old)
			}
		}
		s.leases[want], s.byMAC[mac] = l, want
		delete(s.offers, mac)
		if s.opts.Store != nil {
			if err := s.opts.Store.SaveDHCPLease(*l); err != nil {
				s.log.Error("DHCP: falha ao gravar concessão", "erro", err)
			}
		}
		r, err := s.options(req, dhcpv4.MessageTypeAck, want)
		if err != nil {
			return nil
		}
		s.log.Info("DHCP: concessão", "ip", want, "mac", mac, "nome", l.Hostname)
		if s.opts.OnLease != nil {
			go s.opts.OnLease(*l)
		}
		return r

	case dhcpv4.MessageTypeRelease:
		ip := addrOf(req.ClientIPAddr)
		if l, ok := s.leases[ip]; ok && l.MAC == mac {
			l.Expires = now // vence agora, mas o IP fica "lembrado" para o mesmo MAC
			if s.opts.Store != nil {
				_ = s.opts.Store.SaveDHCPLease(*l)
			}
		}
		return nil

	case dhcpv4.MessageTypeDecline:
		ip := addrOf(req.RequestedIPAddress())
		s.declined[ip] = now.Add(declineHold)
		if l, ok := s.leases[ip]; ok && l.MAC == mac {
			delete(s.leases, ip)
			delete(s.byMAC, mac)
			if s.opts.Store != nil {
				_ = s.opts.Store.DeleteDHCPLease(ip)
			}
		}
		s.log.Warn("DHCP: IP recusado pelo cliente (conflito na rede?)", "ip", ip, "mac", mac)
		return nil

	case dhcpv4.MessageTypeInform:
		r, err := s.options(req, dhcpv4.MessageTypeAck, netip.Addr{})
		if err != nil {
			return nil
		}
		return r
	}
	return nil
}

// cleanHost deixa o nome do aparelho apto a virar rótulo DNS.
func cleanHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	var b strings.Builder
	for _, c := range h {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
			b.WriteRune(c)
		case c == ' ' || c == '_' || c == '.':
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// Leases devolve as concessões (ativas e vencidas há menos de 7 dias).
func (s *Server) Leases() []Lease {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.opts.Now()
	out := make([]Lease, 0, len(s.leases))
	for _, l := range s.leases {
		if now.Sub(l.Expires) < stickyLeases {
			out = append(out, *l)
		}
	}
	slices.SortFunc(out, func(a, b Lease) int { return a.IP.Compare(b.IP) })
	return out
}

func (s *Server) Reservations() []Reservation {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Reservation, 0, len(s.resv))
	for _, r := range s.resv {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b Reservation) int { return a.IP.Compare(b.IP) })
	return out
}

// Reserve fixa um IP para o MAC.
func (s *Server) Reserve(r Reservation) error {
	hw, err := net.ParseMAC(r.MAC)
	if err != nil || len(hw) != 6 {
		return errors.New("MAC inválido")
	}
	r.MAC = normMAC(hw)
	if !r.IP.Is4() || !s.opts.Subnet.Contains(r.IP) || r.IP == s.opts.ServerIP || r.IP == s.opts.Subnet.Addr() ||
		r.IP == broadcast(s.opts.Subnet) || slices.Contains(s.opts.Routers, r.IP) {
		return fmt.Errorf("IP %s fora da sub-rede %s ou já usado pelo servidor/roteador", r.IP, s.opts.Subnet)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if owner, ok := s.resvIP[r.IP]; ok && owner != r.MAC {
		return fmt.Errorf("o IP %s já está reservado para %s", r.IP, owner)
	}
	if l, ok := s.leases[r.IP]; ok && l.MAC != r.MAC && l.Expires.After(s.opts.Now()) {
		return fmt.Errorf("o IP %s está em uso por %s até %s", r.IP, l.MAC, l.Expires.Format("02/01 15:04"))
	}
	if old, ok := s.resv[r.MAC]; ok {
		delete(s.resvIP, old.IP)
	}
	if s.opts.Store != nil {
		if err := s.opts.Store.SaveDHCPReservation(r); err != nil {
			return err
		}
	}
	s.resv[r.MAC], s.resvIP[r.IP] = r, r.MAC
	return nil
}

func (s *Server) Unreserve(mac string) error {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return errors.New("MAC inválido")
	}
	mac = normMAC(hw)
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.resv[mac]
	if !ok {
		return errors.New("reserva não encontrada")
	}
	if s.opts.Store != nil {
		if err := s.opts.Store.DeleteDHCPReservation(mac); err != nil {
			return err
		}
	}
	delete(s.resv, mac)
	delete(s.resvIP, r.IP)
	return nil
}

// Lookup resolve <nome>.<domínio> (e <nome> sozinho) pelas concessões ativas
// e pelos nomes das reservas.
func (s *Server) Lookup(name string) []netip.Addr {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	if s.opts.Domain != "" {
		n = strings.TrimSuffix(n, "."+strings.ToLower(s.opts.Domain))
	}
	if n == "" || strings.Contains(n, ".") {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.resv {
		if r.Name != "" && cleanHost(r.Name) == n {
			return []netip.Addr{r.IP}
		}
	}
	now := s.opts.Now()
	for _, l := range s.leases {
		if l.Hostname == n && l.Expires.After(now) {
			return []netip.Addr{l.IP}
		}
	}
	return nil
}

// PTR devolve o nome (FQDN) do IP, se houver concessão ativa ou reserva com nome.
func (s *Server) PTR(ip netip.Addr) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	host := ""
	if mac, ok := s.resvIP[ip]; ok && s.resv[mac].Name != "" {
		host = cleanHost(s.resv[mac].Name)
	} else if l, ok := s.leases[ip]; ok && l.Hostname != "" && l.Expires.After(s.opts.Now()) {
		host = l.Hostname
	}
	if host == "" {
		return ""
	}
	if s.opts.Domain != "" {
		host += "." + s.opts.Domain
	}
	return host + "."
}

// Start abre a porta 67 na interface (erro de permissão ou de interface volta
// aqui) e atende em segundo plano até ctx terminar.
func (s *Server) Start(ctx context.Context) error {
	srv, err := server4.NewServer(s.opts.Interface, &net.UDPAddr{IP: net.IPv4zero, Port: dhcpv4.ServerPort}, s.serve)
	if err != nil {
		return fmt.Errorf("dhcp na interface %s: %w", s.opts.Interface, err)
	}
	s.log.Info("DHCP ouvindo", "interface", s.opts.Interface, "faixa", fmt.Sprintf("%s–%s", s.opts.Start, s.opts.End),
		"servidor", s.opts.ServerIP)
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	go func() {
		if err := srv.Serve(); err != nil && ctx.Err() == nil {
			s.log.Error("DHCP parou", "erro", err)
		}
	}()
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.Expire()
			}
		}
	}()
	return nil
}

// Info resume a configuração para o painel.
func (s *Server) Info() map[string]any {
	return map[string]any{
		"interface": s.opts.Interface, "range_start": s.opts.Start, "range_end": s.opts.End,
		"subnet": s.opts.Subnet.String(), "server_ip": s.opts.ServerIP, "routers": s.opts.Routers,
		"dns": s.opts.DNS, "domain": s.opts.Domain, "lease_time": s.opts.LeaseTime.String(),
	}
}

func (s *Server) serve(conn net.PacketConn, peer net.Addr, req *dhcpv4.DHCPv4) {
	resp := s.Handle(req)
	if resp == nil {
		return
	}
	// Para onde responder (RFC 2131 §4.1): relay, cliente já configurado, ou broadcast.
	dst := &net.UDPAddr{IP: net.IPv4bcast, Port: dhcpv4.ClientPort}
	switch {
	case !req.GatewayIPAddr.IsUnspecified() && req.GatewayIPAddr != nil:
		dst = &net.UDPAddr{IP: req.GatewayIPAddr, Port: dhcpv4.ServerPort}
	case !req.ClientIPAddr.IsUnspecified() && req.ClientIPAddr != nil && resp.MessageType() != dhcpv4.MessageTypeNak:
		dst = &net.UDPAddr{IP: req.ClientIPAddr, Port: dhcpv4.ClientPort}
	}
	if _, err := conn.WriteTo(resp.ToBytes(), dst); err != nil {
		s.log.Warn("DHCP: falha ao responder", "destino", dst, "erro", err)
	}
	_ = peer
}

// Expire limpa concessões vencidas há mais de 7 dias.
func (s *Server) Expire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.opts.Now()
	for ip, l := range s.leases {
		if now.Sub(l.Expires) > stickyLeases {
			delete(s.leases, ip)
			if s.byMAC[l.MAC] == ip {
				delete(s.byMAC, l.MAC)
			}
			if s.opts.Store != nil {
				_ = s.opts.Store.DeleteDHCPLease(ip)
			}
		}
	}
	for m, o := range s.offers {
		if o.until.Before(now) {
			delete(s.offers, m)
		}
	}
	for ip, until := range s.declined {
		if until.Before(now) {
			delete(s.declined, ip)
		}
	}
}

// InterfaceAddr devolve o primeiro IPv4 da interface e a sub-rede dele.
func InterfaceAddr(name string) (netip.Addr, netip.Prefix, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return netip.Addr{}, netip.Prefix{}, fmt.Errorf("interface %q: %w", name, err)
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return netip.Addr{}, netip.Prefix{}, err
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
			p, err := netip.ParsePrefix(n.String())
			if err == nil {
				return p.Addr(), p.Masked(), nil
			}
		}
	}
	return netip.Addr{}, netip.Prefix{}, fmt.Errorf("interface %q sem IPv4", name)
}
