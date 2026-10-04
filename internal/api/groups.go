// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/ugoneiva/HeimdallDNS/internal/clients"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

// GroupsKey guarda os grupos de dispositivos.
const GroupsKey = "clients.groups"

// LoadGroups aplica no radar os grupos salvos.
func LoadGroups(st *store.Store, reg *clients.Registry) error {
	var gs []clients.Group
	if _, err := st.GetJSON(GroupsKey, &gs); err != nil {
		return err
	}
	return reg.SetGroups(gs)
}

type groupView struct {
	clients.Group
	Members []string `json:"members"` // ids dos aparelhos
	Active  []string `json:"active"`  // horários valendo agora
}

func (a *api) listGroups(w http.ResponseWriter, _ *http.Request) {
	members := map[string][]string{}
	for _, c := range a.Clients.List() {
		if g := c.Settings.Group; g != "" {
			members[g] = append(members[g], c.ID)
		}
	}
	out := []groupView{}
	for _, g := range a.Clients.Groups() {
		v := groupView{Group: g, Members: nonNil(members[g.ID]), Active: nonNil(a.Clients.ActiveSchedules(g.ID))}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

// putGroups troca todos os grupos (o painel edita a lista inteira). Grupos
// novos chegam sem id e ganham um.
func (a *api) putGroups(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Groups []clients.Group `json:"groups"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	for i := range body.Groups {
		g := &body.Groups[i]
		g.Name = strings.TrimSpace(g.Name)
		g.Allow, g.Deny = clean(g.Allow), clean(g.Deny)
		if g.ID == "" {
			b := make([]byte, 4)
			_, _ = rand.Read(b)
			g.ID = hex.EncodeToString(b)
		}
		for j := range g.Schedules {
			s := &g.Schedules[j]
			s.Name = strings.TrimSpace(s.Name)
			s.Allow, s.Deny = clean(s.Allow), clean(s.Deny)
		}
	}
	err := clients.ValidateGroups(body.Groups)
	if err == nil {
		err = a.Store.SetJSON(GroupsKey, body.Groups)
	}
	if err == nil {
		err = a.Clients.SetGroups(body.Groups)
	}
	a.audit(r, "groups.update", "", map[string]any{"groups": len(body.Groups)}, err)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	a.listGroups(w, r)
}
