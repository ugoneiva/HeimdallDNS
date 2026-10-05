// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"errors"
	"net/http"

	"github.com/ugoneiva/HeimdallDNS/internal/forward"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

// ForwardKey guarda as regras de encaminhamento condicional do painel.
const ForwardKey = "dns.forward"

// LoadForward aplica as regras do painel (as do arquivo já estão no Manager).
func LoadForward(st *store.Store, fwd *forward.Manager) error {
	var rules []forward.Rule
	if _, err := st.GetJSON(ForwardKey, &rules); err != nil {
		return err
	}
	return fwd.Apply(rules)
}

func (a *api) forwardRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/dns/forward", a.getForward)
	mux.HandleFunc("PUT /api/dns/forward", a.putForward)
}

func (a *api) getForward(w http.ResponseWriter, _ *http.Request) {
	if a.Forward == nil {
		writeErr(w, http.StatusNotFound, errors.New("encaminhamento condicional indisponível"))
		return
	}
	rules := []forward.Rule{}
	if _, err := a.Store.GetJSON(ForwardKey, &rules); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if rules == nil {
		rules = []forward.Rule{}
	}
	cfg := a.Forward.Config()
	if cfg == nil {
		cfg = []forward.Rule{}
	}
	private := false
	if a.Upstream != nil {
		servers, _ := a.Upstream.Config()
		private = forward.HasPrivate(servers)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rules": rules, "config": cfg,
		// Reverso de IP privado sem regra: respondido aqui (NXDOMAIN) ou pelo
		// upstream privado (o roteador).
		"private_reverse": map[bool]string{true: "upstream", false: "local"}[private],
	})
}

func (a *api) putForward(w http.ResponseWriter, r *http.Request) {
	if a.Forward == nil {
		writeErr(w, http.StatusNotFound, errors.New("encaminhamento condicional indisponível"))
		return
	}
	var body struct {
		Rules []forward.Rule `json:"rules"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	rules, err := forward.Normalize(body.Rules)
	if err == nil {
		err = a.Forward.Apply(rules)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := a.Store.SetJSON(ForwardKey, rules); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	a.audit(r, "dns.forward.update", "", map[string]any{"rules": len(rules)}, nil)
	a.getForward(w, r)
}
