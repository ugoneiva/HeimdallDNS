// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"

	"github.com/ugoneiva/HeimdallDNS/internal/dhcp"
)

func (a *api) dhcpState(w http.ResponseWriter, _ *http.Request) {
	if a.DHCP == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	type lease struct {
		dhcp.Lease
		Active     bool   `json:"active"`
		ClientID   string `json:"client_id,omitempty"`
		ClientName string `json:"client_name,omitempty"`
		Reserved   bool   `json:"reserved"`
	}
	resv := a.DHCP.Reservations()
	reserved := map[string]bool{}
	for _, r := range resv {
		reserved[r.MAC] = true
	}
	ls := a.DHCP.Leases()
	out := make([]lease, len(ls))
	for i, l := range ls {
		out[i] = lease{Lease: l, Active: l.Expires.After(timeNow()), Reserved: reserved[l.MAC]}
		if c, err := a.Clients.Find(l.MAC); err == nil {
			out[i].ClientID, out[i].ClientName = c.ID(), c.Policy().Display
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "config": a.DHCP.Info(), "leases": out, "reservations": resv})
}

func (a *api) dhcpReserve(w http.ResponseWriter, r *http.Request) {
	if a.DHCP == nil {
		writeErr(w, http.StatusConflict, errors.New("o DHCP está desligado"))
		return
	}
	var body struct {
		MAC  string `json:"mac"`
		IP   string `json:"ip"`
		Name string `json:"name"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(body.IP))
	if err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("IP inválido"))
		return
	}
	if err := a.DHCP.Reserve(dhcp.Reservation{MAC: strings.TrimSpace(body.MAC), IP: ip, Name: strings.TrimSpace(body.Name)}); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	a.dhcpState(w, r)
}

func (a *api) dhcpUnreserve(w http.ResponseWriter, r *http.Request) {
	if a.DHCP == nil {
		writeErr(w, http.StatusConflict, errors.New("o DHCP está desligado"))
		return
	}
	if err := a.DHCP.Unreserve(r.PathValue("mac")); err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	a.dhcpState(w, r)
}
