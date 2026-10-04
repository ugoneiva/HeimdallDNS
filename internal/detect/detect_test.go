package detect

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/filter"
	"github.com/ugoneiva/HeimdallDNS/internal/security"
	"github.com/ugoneiva/HeimdallDNS/internal/server"
)

func newTestDetector(s security.Settings) (*Detector, *[]security.Alert) {
	var got []security.Alert
	d := New(Options{
		Settings: func() security.Settings { return s },
		Raise:    func(a security.Alert) { got = append(got, a) },
	})
	return d, &got
}

func ev(name, status, rcode, qtype, client string, t time.Time) server.Event {
	return server.Event{Time: t, Client: netip.MustParseAddr(client), ClientID: "id-" + client,
		Name: name + ".", Type: qtype, Status: status, Rcode: rcode}
}

var on = security.Settings{DGA: true, Tunnel: true}

func TestDGAAlert(t *testing.T) {
	d, got := newTestDetector(on)
	now := time.Now()
	for i, l := range generated[:9] {
		d.process(ev(l+".com", server.StatusForwarded, "NXDOMAIN", "A", "10.0.0.5", now.Add(time.Duration(i)*time.Second)))
	}
	if len(*got) != 0 {
		t.Fatalf("9 nomes ainda não bastam: %+v", *got)
	}
	d.process(ev(generated[9]+".net", server.StatusForwarded, "NXDOMAIN", "A", "10.0.0.5", now.Add(10*time.Second)))
	if len(*got) != 1 || (*got)[0].Kind != security.KindDGA || (*got)[0].ClientIP != "10.0.0.5" {
		t.Fatalf("alerta de DGA = %+v", *got)
	}
	// Na mesma janela, não repete.
	d.process(ev(generated[10]+".org", server.StatusForwarded, "NXDOMAIN", "A", "10.0.0.5", now.Add(11*time.Second)))
	if len(*got) != 1 {
		t.Error("um alerta por janela")
	}
}

func TestDGANoFalsePositive(t *testing.T) {
	d, got := newTestDetector(on)
	now := time.Now()
	// Muitos NXDOMAIN de nomes normais (erro de digitação, domínio expirado): sem alerta.
	for i, l := range benign {
		d.process(ev(l+".com.br", server.StatusForwarded, "NXDOMAIN", "A", "10.0.0.6", now.Add(time.Duration(i)*time.Second)))
	}
	// Nomes aleatórios que EXISTEM (CDN com rótulo aleatório resolve): sem alerta.
	for i, l := range generated {
		d.process(ev(l+".com", server.StatusForwarded, "NOERROR", "A", "10.0.0.7", now.Add(time.Duration(i)*time.Second)))
	}
	// Teste de intranet do Chrome: rótulo único aleatório, sem TLD.
	for i := range 20 {
		d.process(ev(fmt.Sprintf("qwkzjxmbvt%d", i), server.StatusForwarded, "NXDOMAIN", "A", "10.0.0.8", now))
	}
	if len(*got) != 0 {
		t.Errorf("falsos positivos: %+v", *got)
	}
}

func TestTunnelAlert(t *testing.T) {
	d, got := newTestDetector(on)
	now := time.Now()
	for i := range tunMinUnique {
		sub := fmt.Sprintf("%x%x.%d", now.UnixNano()+int64(i)*7919, i*104729, i)
		d.process(ev(sub+".exfil-teste.com", server.StatusForwarded, "NOERROR", "A", "10.0.0.9", now.Add(time.Duration(i)*time.Second)))
	}
	if len(*got) != 1 || (*got)[0].Kind != security.KindTunnel || (*got)[0].Domain != "exfil-teste.com" {
		t.Fatalf("alerta de túnel = %+v", *got)
	}
	// CDN conhecida, mesmo padrão: ignorada.
	for i := range tunMinUnique * 2 {
		sub := fmt.Sprintf("d%xabcdef%x", i*31, i*17)
		d.process(ev(sub+".cloudfront.net", server.StatusForwarded, "NOERROR", "A", "10.0.0.10", now))
	}
	if len(*got) != 1 {
		t.Errorf("CDN não pode alertar: %+v", (*got)[1:])
	}
}

func TestTunnelTXT(t *testing.T) {
	d, got := newTestDetector(on)
	now := time.Now()
	for i := range tunMinTXT {
		d.process(ev(fmt.Sprintf("c%d.t.iodine-teste.org", i), server.StatusForwarded, "NOERROR", "TXT", "10.0.0.11", now))
	}
	if len(*got) != 1 || (*got)[0].Severity != security.SevHigh {
		t.Fatalf("rajada de TXT = %+v", *got)
	}
}

func TestThreatAlertAndIgnore(t *testing.T) {
	s := on
	s.Ignore = []string{"permitido.com"}
	d, got := newTestDetector(s)
	e := ev("cdn.c2-ruim.com", server.StatusBlocked, "NOERROR", "A", "10.0.0.12", time.Now())
	e.Category = filter.CategoryThreat
	e.Rule = "||c2-ruim.com^"
	d.process(e)
	if len(*got) != 1 || (*got)[0].Kind != security.KindThreat || (*got)[0].Domain != "c2-ruim.com" {
		t.Fatalf("ameaça = %+v", *got)
	}
	// Bloqueio comum (anúncio): não é alerta de segurança.
	d.process(ev("ads.exemplo.com", server.StatusBlocked, "NOERROR", "A", "10.0.0.12", time.Now()))
	// Domínio ignorado nas configurações.
	e2 := ev("x.permitido.com", server.StatusBlocked, "NOERROR", "A", "10.0.0.12", time.Now())
	e2.Category = filter.CategoryThreat
	d.process(e2)
	if len(*got) != 1 {
		t.Errorf("só a ameaça alerta: %+v", *got)
	}
	// TLD fora da Public Suffix List: alerta com o nome inteiro.
	e3 := ev("beacon.malware.invalido", server.StatusBlocked, "NOERROR", "A", "10.0.0.12", time.Now())
	e3.Category = filter.CategoryThreat
	d.process(e3)
	if len(*got) != 2 || (*got)[1].Domain != "beacon.malware.invalido" {
		t.Errorf("sem domínio registrável: %+v", *got)
	}
}

func TestDisabledDetections(t *testing.T) {
	d, got := newTestDetector(security.Settings{})
	now := time.Now()
	for i, l := range generated {
		d.process(ev(l+".com", server.StatusForwarded, "NXDOMAIN", "A", "10.0.0.13", now.Add(time.Duration(i)*time.Second)))
	}
	if len(*got) != 0 {
		t.Error("DGA desligado não alerta")
	}
}
