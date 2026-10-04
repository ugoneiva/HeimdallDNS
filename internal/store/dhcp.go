// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package store

import (
	"net/netip"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/dhcp"
)

func (s *Store) DHCPLeases() ([]dhcp.Lease, error) {
	rows, err := s.db.Query(`SELECT ip, mac, hostname, expires FROM dhcp_leases`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []dhcp.Lease
	for rows.Next() {
		var (
			l   dhcp.Lease
			ip  string
			exp int64
		)
		if err := rows.Scan(&ip, &l.MAC, &l.Hostname, &exp); err != nil {
			return nil, err
		}
		if l.IP, err = netip.ParseAddr(ip); err != nil {
			continue
		}
		l.Expires = time.Unix(exp, 0)
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *Store) SaveDHCPLease(l dhcp.Lease) error {
	_, err := s.db.Exec(`INSERT INTO dhcp_leases (ip, mac, hostname, expires) VALUES (?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET mac = excluded.mac, hostname = excluded.hostname, expires = excluded.expires`,
		l.IP.String(), l.MAC, l.Hostname, l.Expires.Unix())
	return err
}

func (s *Store) DeleteDHCPLease(ip netip.Addr) error {
	_, err := s.db.Exec(`DELETE FROM dhcp_leases WHERE ip = ?`, ip.String())
	return err
}

func (s *Store) DHCPReservations() ([]dhcp.Reservation, error) {
	rows, err := s.db.Query(`SELECT mac, ip, name FROM dhcp_reservations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []dhcp.Reservation
	for rows.Next() {
		var (
			r  dhcp.Reservation
			ip string
		)
		if err := rows.Scan(&r.MAC, &ip, &r.Name); err != nil {
			return nil, err
		}
		if r.IP, err = netip.ParseAddr(ip); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) SaveDHCPReservation(r dhcp.Reservation) error {
	_, err := s.db.Exec(`INSERT INTO dhcp_reservations (mac, ip, name) VALUES (?, ?, ?)
		ON CONFLICT(mac) DO UPDATE SET ip = excluded.ip, name = excluded.name`, r.MAC, r.IP.String(), r.Name)
	return err
}

func (s *Store) DeleteDHCPReservation(mac string) error {
	_, err := s.db.Exec(`DELETE FROM dhcp_reservations WHERE mac = ?`, mac)
	return err
}
