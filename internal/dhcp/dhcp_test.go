package dhcp

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTest(t *testing.T, start, end string) (*Server, *clock) {
	t.Helper()
	ck := &clock{t: time.Unix(1_800_000_000, 0)}
	s, err := New(Options{
		Start: netip.MustParseAddr(start), End: netip.MustParseAddr(end),
		Subnet: netip.MustParsePrefix("10.99.0.0/24"), ServerIP: netip.MustParseAddr("10.99.0.1"),
		Routers: []netip.Addr{netip.MustParseAddr("10.99.0.254")}, Domain: "lan", LeaseTime: time.Hour, Now: ck.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, ck
}

func hw(last byte) net.HardwareAddr { return net.HardwareAddr{0x02, 0, 0, 0, 0, last} }

// lease faz DISCOVER/OFFER/REQUEST/ACK e devolve o IP.
func lease(t *testing.T, s *Server, mac net.HardwareAddr, host string) netip.Addr {
	t.Helper()
	d, _ := dhcpv4.NewDiscovery(mac, dhcpv4.WithOption(dhcpv4.OptHostName(host)))
	offer := s.Handle(d)
	if offer == nil || offer.MessageType() != dhcpv4.MessageTypeOffer {
		t.Fatalf("sem OFFER para %s", mac)
	}
	req, _ := dhcpv4.NewRequestFromOffer(offer, dhcpv4.WithOption(dhcpv4.OptHostName(host)))
	ack := s.Handle(req)
	if ack == nil || ack.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("sem ACK para %s: %v", mac, ack)
	}
	return addrOf(ack.YourIPAddr)
}

func TestFullExchangeAndOptions(t *testing.T) {
	s, _ := newTest(t, "10.99.0.100", "10.99.0.110")
	d, _ := dhcpv4.NewDiscovery(hw(1), dhcpv4.WithOption(dhcpv4.OptHostName("Notebook da Ana")))
	offer := s.Handle(d)
	if addrOf(offer.YourIPAddr) != netip.MustParseAddr("10.99.0.100") {
		t.Fatalf("oferta = %s", offer.YourIPAddr)
	}
	if !offer.ServerIdentifier().Equal(net.ParseIP("10.99.0.1")) || offer.SubnetMask().String() != "ffffff00" ||
		!offer.Router()[0].Equal(net.ParseIP("10.99.0.254")) || !offer.DNS()[0].Equal(net.ParseIP("10.99.0.1")) ||
		offer.DomainName() != "lan" || offer.IPAddressLeaseTime(0) != time.Hour {
		t.Errorf("opções da oferta: %s", offer.Summary())
	}
	req, _ := dhcpv4.NewRequestFromOffer(offer, dhcpv4.WithOption(dhcpv4.OptHostName("Notebook da Ana")))
	ack := s.Handle(req)
	if ack.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("ACK = %v", ack.MessageType())
	}
	ls := s.Leases()
	if len(ls) != 1 || ls[0].Hostname != "notebook-da-ana" || ls[0].MAC != "02:00:00:00:00:01" {
		t.Errorf("concessão = %+v", ls)
	}
	// DNS local
	if got := s.Lookup("notebook-da-ana.lan."); len(got) != 1 || got[0] != netip.MustParseAddr("10.99.0.100") {
		t.Errorf("Lookup = %v", got)
	}
	if s.PTR(netip.MustParseAddr("10.99.0.100")) != "notebook-da-ana.lan." {
		t.Errorf("PTR = %q", s.PTR(netip.MustParseAddr("10.99.0.100")))
	}
}

func TestStickyAndRenewal(t *testing.T) {
	s, ck := newTest(t, "10.99.0.100", "10.99.0.110")
	a := lease(t, s, hw(1), "a")
	b := lease(t, s, hw(2), "b")
	if a == b {
		t.Fatal("dois aparelhos com o mesmo IP")
	}
	// Renovação (ciaddr preenchido, sem server id): mantém o IP.
	r, _ := dhcpv4.New(dhcpv4.WithHwAddr(hw(1)), dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithClientIP(a.AsSlice()))
	if ack := s.Handle(r); ack == nil || addrOf(ack.YourIPAddr) != a {
		t.Errorf("renovação: %v", ack)
	}
	// Depois de vencer, o mesmo aparelho volta para o mesmo IP.
	ck.t = ck.t.Add(3 * time.Hour)
	if again := lease(t, s, hw(1), "a"); again != a {
		t.Errorf("IP grudento: %s, quero %s", again, a)
	}
}

func TestNakAndOtherServer(t *testing.T) {
	s, _ := newTest(t, "10.99.0.100", "10.99.0.110")
	b := lease(t, s, hw(2), "b")
	// Pede o IP de outro aparelho: NAK.
	r, _ := dhcpv4.New(dhcpv4.WithHwAddr(hw(1)), dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(b.AsSlice())))
	if nak := s.Handle(r); nak == nil || nak.MessageType() != dhcpv4.MessageTypeNak {
		t.Errorf("IP alheio deveria dar NAK: %v", nak)
	}
	// Fora da sub-rede: NAK.
	r2, _ := dhcpv4.New(dhcpv4.WithHwAddr(hw(1)), dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("192.168.5.5"))))
	if nak := s.Handle(r2); nak == nil || nak.MessageType() != dhcpv4.MessageTypeNak {
		t.Errorf("outra rede deveria dar NAK: %v", nak)
	}
	// O cliente escolheu outro servidor: silêncio.
	r3, _ := dhcpv4.New(dhcpv4.WithHwAddr(hw(3)), dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(net.ParseIP("10.99.0.2"))),
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("10.99.0.105"))))
	if resp := s.Handle(r3); resp != nil {
		t.Errorf("pedido para outro servidor não tem resposta: %v", resp.MessageType())
	}
}

func TestReservation(t *testing.T) {
	s, _ := newTest(t, "10.99.0.100", "10.99.0.110")
	if err := s.Reserve(Reservation{MAC: "02-00-00-00-00-07", IP: netip.MustParseAddr("10.99.0.50"), Name: "Impressora"}); err != nil {
		t.Fatal(err)
	}
	if ip := lease(t, s, hw(7), ""); ip != netip.MustParseAddr("10.99.0.50") {
		t.Errorf("reserva (fora da faixa vale) = %s", ip)
	}
	// O IP reservado não vai para outro aparelho, nem pedindo.
	d, _ := dhcpv4.NewDiscovery(hw(8), dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("10.99.0.50"))))
	if o := s.Handle(d); addrOf(o.YourIPAddr) == netip.MustParseAddr("10.99.0.50") {
		t.Error("IP reservado oferecido a outro MAC")
	}
	if s.PTR(netip.MustParseAddr("10.99.0.50")) != "impressora.lan." || len(s.Lookup("impressora")) != 1 {
		t.Error("nome da reserva deveria resolver")
	}
	for _, bad := range []Reservation{
		{MAC: "xx", IP: netip.MustParseAddr("10.99.0.51")},
		{MAC: "02:00:00:00:00:09", IP: netip.MustParseAddr("10.99.0.1")},   // o próprio servidor
		{MAC: "02:00:00:00:00:09", IP: netip.MustParseAddr("10.99.0.254")}, // o roteador
		{MAC: "02:00:00:00:00:09", IP: netip.MustParseAddr("10.99.0.50")},  // já reservado
		{MAC: "02:00:00:00:00:09", IP: netip.MustParseAddr("172.16.0.5")},  // outra rede
	} {
		if s.Reserve(bad) == nil {
			t.Errorf("reserva inválida aceita: %+v", bad)
		}
	}
	if err := s.Unreserve("02:00:00:00:00:07"); err != nil || len(s.Reservations()) != 0 {
		t.Errorf("remover reserva: %v", err)
	}
}

func TestExhaustionDeclineRelease(t *testing.T) {
	s, ck := newTest(t, "10.99.0.100", "10.99.0.101")
	a := lease(t, s, hw(1), "")
	lease(t, s, hw(2), "")
	d, _ := dhcpv4.NewDiscovery(hw(3))
	if s.Handle(d) != nil {
		t.Fatal("faixa esgotada não deveria oferecer")
	}
	// Liberação: o IP vence na hora e pode ir para outro.
	rel, _ := dhcpv4.New(dhcpv4.WithHwAddr(hw(1)), dhcpv4.WithMessageType(dhcpv4.MessageTypeRelease), dhcpv4.WithClientIP(a.AsSlice()))
	s.Handle(rel)
	if o := s.Handle(d); o == nil || addrOf(o.YourIPAddr) != a {
		t.Errorf("IP liberado deveria ir para o novo: %v", o)
	}
	// Recusa (conflito): o IP fica fora por 10 min.
	dec, _ := dhcpv4.New(dhcpv4.WithHwAddr(hw(3)), dhcpv4.WithMessageType(dhcpv4.MessageTypeDecline),
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(a.AsSlice())))
	s.Handle(dec)
	if o := s.Handle(d); o != nil {
		t.Errorf("IP recusado não pode ser oferecido: %s", o.YourIPAddr)
	}
	ck.t = ck.t.Add(11 * time.Minute)
	s.Expire()
	if o := s.Handle(d); o == nil {
		t.Error("depois de 10 min o IP volta")
	}
}

func TestCleanHost(t *testing.T) {
	for in, want := range map[string]string{
		"Galaxy-S24":    "galaxy-s24",
		"iPhone de Ana": "iphone-de-ana",
		"  _x_ ":        "x",
		"DESKTOP.local": "desktop-local",
		"çãé!":          "",
	} {
		if got := cleanHost(in); got != want {
			t.Errorf("cleanHost(%q) = %q, quero %q", in, got, want)
		}
	}
}
