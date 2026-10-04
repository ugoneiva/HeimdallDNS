// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package topology

import (
	"slices"
	"strings"
	"time"
)

// DeviceIn é um aparelho do radar.
type DeviceIn struct {
	ID, Name, Hostname, Vendor string
	IPs                        []string
	LastSeen                   time.Time
	Isolated                   bool
	Group                      string
	Kind                       string // escolhido à mão ("" = deduzir)
}

// Count é quantas vezes um aparelho consultou um nome no período.
type Count struct {
	ClientID string
	Name     string
	Queries  int
	Blocked  int
}

type Input struct {
	Devices    []DeviceIn
	Counts     []Count
	Alerts     map[string]int // alertas abertos por aparelho
	SelfIPs    []string       // IPs deste servidor
	GatewayIP  string
	MaxDest    int // destinos mostrados (o resto vira "Outros sites")
	Now        time.Time
	ActiveSpan time.Duration // visto há menos que isso = ativo
}

type Device struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	IPs      []string `json:"ips"`
	Vendor   string   `json:"vendor,omitempty"`
	Kind     string   `json:"kind"`
	KindAuto bool     `json:"kind_auto"` // deduzido (não escolhido à mão)
	Active   bool     `json:"active"`
	Isolated bool     `json:"isolated"`
	Group    string   `json:"group,omitempty"`
	Alerts   int      `json:"alerts"`
	Queries  int      `json:"queries"` // no período
	Blocked  int      `json:"blocked"`
	Self     bool     `json:"self,omitempty"` // o próprio servidor
}

type Dest struct {
	Destination
	Queries int `json:"queries"`
	Blocked int `json:"blocked"`
	Devices int `json:"devices"`
}

type Link struct {
	Device  string `json:"device"`
	Dest    string `json:"dest"`
	Queries int    `json:"queries"`
	Blocked int    `json:"blocked"`
}

type Map struct {
	Devices      []Device `json:"devices"`
	Destinations []Dest   `json:"destinations"`
	Links        []Link   `json:"links"`
}

// Destinos de agregação.
var (
	BlockedDest = Destination{ID: "bloqueados", Name: "Bloqueados (anúncios e rastreio)", Category: CatBlocked}
	OthersDest  = Destination{ID: "outros", Name: "Outros sites", Category: CatOther}
)

// Build monta o mapa.
func Build(in Input) Map {
	if in.MaxDest <= 0 {
		in.MaxDest = 24
	}
	type key struct{ dev, dest string }
	links := map[key]*Link{}
	dests := map[string]*Dest{}
	queried := map[string][]string{}
	devQ, devB := map[string]int{}, map[string]int{}
	for _, c := range in.Counts {
		if c.ClientID == "" || c.Queries <= 0 {
			continue
		}
		d := Classify(c.Name)
		if c.Blocked >= c.Queries && d.Category == CatOther {
			d = BlockedDest // bloqueado por lista e sem serviço conhecido: anúncio/rastreio
		}
		if dests[d.ID] == nil {
			dests[d.ID] = &Dest{Destination: d}
		}
		dests[d.ID].Queries += c.Queries
		dests[d.ID].Blocked += c.Blocked
		k := key{c.ClientID, d.ID}
		if links[k] == nil {
			links[k] = &Link{Device: c.ClientID, Dest: d.ID}
		}
		links[k].Queries += c.Queries
		links[k].Blocked += c.Blocked
		devQ[c.ClientID] += c.Queries
		devB[c.ClientID] += c.Blocked
		if len(queried[c.ClientID]) < 200 {
			queried[c.ClientID] = append(queried[c.ClientID], c.Name)
		}
	}

	// Os destinos mais consultados ficam; o resto vira "Outros sites".
	ranked := make([]*Dest, 0, len(dests))
	for _, d := range dests {
		ranked = append(ranked, d)
	}
	slices.SortFunc(ranked, func(a, b *Dest) int {
		if a.Queries != b.Queries {
			return b.Queries - a.Queries
		}
		return strings.Compare(a.Name, b.Name)
	})
	keep := map[string]bool{BlockedDest.ID: true}
	for _, d := range ranked {
		if len(keep) >= in.MaxDest {
			break
		}
		keep[d.ID] = true
	}
	merged := map[key]*Link{}
	outDest := map[string]*Dest{}
	for k, l := range links {
		id := k.dest
		if !keep[id] {
			id = OthersDest.ID
		}
		nk := key{k.dev, id}
		if merged[nk] == nil {
			merged[nk] = &Link{Device: k.dev, Dest: id}
		}
		merged[nk].Queries += l.Queries
		merged[nk].Blocked += l.Blocked
		if outDest[id] == nil {
			if id == OthersDest.ID {
				outDest[id] = &Dest{Destination: OthersDest}
			} else {
				outDest[id] = &Dest{Destination: dests[id].Destination}
			}
		}
		outDest[id].Queries += l.Queries
		outDest[id].Blocked += l.Blocked
	}

	m := Map{Devices: []Device{}, Destinations: []Dest{}, Links: []Link{}}
	for _, l := range merged {
		outDest[l.Dest].Devices++
		m.Links = append(m.Links, *l)
	}
	slices.SortFunc(m.Links, func(a, b Link) int {
		if a.Queries != b.Queries {
			return b.Queries - a.Queries
		}
		return strings.Compare(a.Device+a.Dest, b.Device+b.Dest)
	})
	for _, d := range outDest {
		m.Destinations = append(m.Destinations, *d)
	}
	slices.SortFunc(m.Destinations, func(a, b Dest) int {
		// "Outros" e "Bloqueados" no fim; o resto por volume.
		ra, rb := destRank(a.ID), destRank(b.ID)
		if ra != rb {
			return ra - rb
		}
		if a.Queries != b.Queries {
			return b.Queries - a.Queries
		}
		return strings.Compare(a.Name, b.Name)
	})

	for _, d := range in.Devices {
		dev := Device{ID: d.ID, Name: d.Name, IPs: d.IPs, Vendor: d.Vendor, Isolated: d.Isolated, Group: d.Group,
			Alerts: in.Alerts[d.ID], Queries: devQ[d.ID], Blocked: devB[d.ID],
			Active: !d.LastSeen.IsZero() && in.Now.Sub(d.LastSeen) < in.ActiveSpan}
		for _, ip := range d.IPs {
			if slices.Contains(in.SelfIPs, ip) {
				dev.Self = true
			}
		}
		switch {
		case d.Kind != "":
			dev.Kind = d.Kind
		case dev.Self:
			dev.Kind, dev.KindAuto = KindServer, true
		case in.GatewayIP != "" && slices.Contains(d.IPs, in.GatewayIP):
			dev.Kind, dev.KindAuto = KindRouter, true
		default:
			dev.Kind, dev.KindAuto = Guess(d.Name, d.Hostname, d.Vendor, queried[d.ID]), true
		}
		m.Devices = append(m.Devices, dev)
	}
	slices.SortFunc(m.Devices, func(a, b Device) int {
		if a.Group != b.Group {
			return strings.Compare(a.Group, b.Group)
		}
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	return m
}

func destRank(id string) int {
	switch id {
	case BlockedDest.ID:
		return 1
	case OthersDest.ID:
		return 2
	}
	return 0
}
