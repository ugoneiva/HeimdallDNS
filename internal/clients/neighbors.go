// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package clients

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Neighbors lê a tabela de vizinhos do kernel (ARP no IPv4, NDP no IPv6) e
// devolve IP → MAC. Usa `ip neigh`; sem o iproute2, cai para /proc/net/arp
// (só IPv4).
func Neighbors() (map[netip.Addr]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", "neigh", "show").Output()
	if err == nil {
		return parseIPNeigh(out), nil
	}
	b, ferr := os.ReadFile("/proc/net/arp")
	if ferr != nil {
		return nil, errors.Join(err, ferr)
	}
	return parseProcARP(b), nil
}

// parseIPNeigh entende linhas como
// "192.168.1.1 dev wlan0 lladdr bc:f8:7e:e7:78:0a REACHABLE".
func parseIPNeigh(out []byte) map[netip.Addr]string {
	m := map[netip.Addr]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 {
			continue
		}
		ip, err := netip.ParseAddr(f[0])
		if err != nil {
			continue
		}
		state := f[len(f)-1]
		if state == "FAILED" || state == "INCOMPLETE" {
			continue
		}
		for i := 1; i+1 < len(f); i++ {
			if f[i] == "lladdr" {
				if mac := normMAC(f[i+1]); mac != "" {
					m[ip.WithZone("")] = mac
				}
				break
			}
		}
	}
	return m
}

func parseProcARP(b []byte) map[netip.Addr]string {
	m := map[netip.Addr]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Scan() // cabeçalho
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[2] == "0x0" { // flags 0x0 = entrada incompleta
			continue
		}
		ip, err := netip.ParseAddr(f[0])
		if err != nil {
			continue
		}
		if mac := normMAC(f[3]); mac != "" {
			m[ip] = mac
		}
	}
	return m
}

// normMAC deixa o MAC em minúsculas com dois-pontos; "" se inválido ou zerado.
func normMAC(s string) string {
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return ""
	}
	if bytes.Equal(hw, make(net.HardwareAddr, 6)) {
		return ""
	}
	return hw.String()
}

// DefaultGateway lê o gateway IPv4 padrão em /proc/net/route.
func DefaultGateway() (netip.Addr, error) {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return netip.Addr{}, err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Scan()
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || f[1] != "00000000" {
			continue
		}
		raw, err := hex.DecodeString(f[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		var ip [4]byte
		binary.BigEndian.PutUint32(ip[:], binary.LittleEndian.Uint32(raw))
		if a := netip.AddrFrom4(ip); !a.IsUnspecified() {
			return a, nil
		}
	}
	return netip.Addr{}, errors.New("sem rota padrão IPv4")
}

// PTRLookup pergunta o nome reverso ao servidor indicado (normalmente o
// roteador, que conhece os nomes entregues pelo DHCP).
func PTRLookup(server string) func(context.Context, netip.Addr) (string, error) {
	c := &dns.Client{Timeout: 2 * time.Second}
	return func(ctx context.Context, ip netip.Addr) (string, error) {
		arpa, err := dns.ReverseAddr(ip.String())
		if err != nil {
			return "", err
		}
		m := new(dns.Msg)
		m.SetQuestion(arpa, dns.TypePTR)
		r, _, err := c.ExchangeContext(ctx, m, server)
		if err != nil {
			return "", err
		}
		for _, rr := range r.Answer {
			if p, ok := rr.(*dns.PTR); ok {
				return strings.TrimSuffix(p.Ptr, "."), nil
			}
		}
		return "", nil
	}
}
