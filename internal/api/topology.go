// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"net"
	"net/http"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/clients"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
	"github.com/ugoneiva/HeimdallDNS/internal/topology"
)

// topology monta o mapa da rede do período (range=15m, 1h, 24h…).
func (a *api) topology(w http.ResponseWriter, r *http.Request) {
	from, _, err := period(r, time.Hour)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	in := topology.Input{Now: timeNow(), ActiveSpan: 5 * time.Minute, MaxDest: intParam(r, "destinations", 24), Alerts: map[string]int{}}
	for _, c := range a.Clients.List() {
		d := topology.DeviceIn{ID: c.ID, Name: c.Display, Hostname: c.Hostname, Vendor: c.Vendor, LastSeen: c.LastSeen,
			Isolated: c.Settings.Isolated, Kind: c.Settings.Kind}
		for _, ip := range c.IPs {
			d.IPs = append(d.IPs, ip.String())
		}
		if g := c.Settings.Group; g != "" {
			for _, gr := range a.Clients.Groups() {
				if gr.ID == g {
					d.Group = gr.Name
				}
			}
		}
		in.Devices = append(in.Devices, d)
	}
	counts, err := a.Store.ClientDomains(from, 20000)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	for _, c := range counts {
		in.Counts = append(in.Counts, topology.Count{ClientID: c.ClientID, Name: c.Name, Queries: c.Queries, Blocked: c.Blocked})
	}
	if evs, err := a.Store.Events(store.EventQuery{Since: timeNow().Add(-30 * 24 * time.Hour), Status: "open", Limit: 1000}); err == nil {
		for _, e := range evs {
			in.Alerts[e.ClientID]++
		}
	}
	if gw, err := clients.DefaultGateway(); err == nil {
		in.GatewayIP = gw.String()
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, ad := range addrs {
			if n, ok := ad.(*net.IPNet); ok {
				in.SelfIPs = append(in.SelfIPs, n.IP.String())
			}
		}
	}
	m := topology.Build(in)
	var ups any
	if a.Upstream != nil {
		ups = a.Upstream.Stats()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"map": m, "upstreams": ups, "gateway": in.GatewayIP, "version": a.Version,
		"history": a.Log.StoresQueries(), "kinds": topology.Kinds,
	})
}
