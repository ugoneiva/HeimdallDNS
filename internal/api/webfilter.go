// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"fmt"
	"net/http"
	"slices"

	"github.com/ugoneiva/HeimdallDNS/internal/clients"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
	"github.com/ugoneiva/HeimdallDNS/internal/webfilter"
)

// WebFilterKey guarda as escolhas globais do filtro web.
const WebFilterKey = "webfilter"

// LoadWebFilter aplica as configurações salvas e marca as categorias em uso
// (globais e as dos grupos), para carregar só essas listas.
func LoadWebFilter(st *store.Store, wf *webfilter.Manager, reg *clients.Registry) error {
	var s webfilter.Settings
	if _, err := st.GetJSON(WebFilterKey, &s); err != nil {
		return err
	}
	if err := wf.SetSettings(s); err != nil {
		return err
	}
	UpdateWebUsed(wf, reg)
	return nil
}

// UpdateWebUsed recalcula as categorias em uso.
func UpdateWebUsed(wf *webfilter.Manager, reg *clients.Registry) {
	wf.SetUsed(append(wf.Settings().Global, reg.UsedCategories()...))
}

type webCategoryView struct {
	webfilter.Category
	Global bool             `json:"global"`
	Groups []string         `json:"groups"` // grupos que usam (sempre ou em horário)
	Status webfilter.Status `json:"status"`
}

func (a *api) getWebFilter(w http.ResponseWriter, _ *http.Request) {
	s := a.WebFilter.Settings()
	st := a.WebFilter.Status()
	groups := a.Clients.Groups()
	out := []webCategoryView{}
	for _, c := range webfilter.Catalog {
		v := webCategoryView{Category: c, Global: slices.Contains(s.Global, c.ID), Groups: []string{}, Status: st[c.ID]}
		if v.Sources == nil {
			v.Sources = []webfilter.Source{} // nunca null no JSON
		}
		for _, g := range groups {
			use := slices.Contains(g.Categories, c.ID)
			for _, sc := range g.Schedules {
				use = use || (!sc.Disabled && slices.Contains(sc.Categories, c.ID))
			}
			if use {
				v.Groups = append(v.Groups, g.Name)
			}
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": s, "categories": out})
}

func (a *api) putWebFilter(w http.ResponseWriter, r *http.Request) {
	var body webfilter.Settings
	if !readJSON(w, r, &body) {
		return
	}
	err := a.WebFilter.SetSettings(body)
	if err == nil {
		err = a.Store.SetJSON(WebFilterKey, a.WebFilter.Settings())
	}
	a.audit(r, "webfilter.update", "", map[string]any{"global": body.Global, "safesearch": body.SafeSearch}, err)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	UpdateWebUsed(a.WebFilter, a.Clients)
	a.Cache.Flush() // respostas antigas (de antes do bloqueio) saem do cache
	a.getWebFilter(w, r)
}

func (a *api) refreshWebFilter(w http.ResponseWriter, _ *http.Request) {
	go a.WebFilter.Refresh(a.Context)
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "atualizando"})
}

// validWebCategories confere as categorias citadas pelos grupos.
func validWebCategories(gs []clients.Group) error {
	for _, g := range gs {
		if id, ok := webfilter.Valid(g.Categories); !ok {
			return fmt.Errorf("grupo %s: categoria do filtro web desconhecida: %s", g.Name, id)
		}
		for _, s := range g.Schedules {
			if id, ok := webfilter.Valid(s.Categories); !ok {
				return fmt.Errorf("grupo %s, horário %s: categoria do filtro web desconhecida: %s", g.Name, s.Name, id)
			}
		}
	}
	return nil
}
