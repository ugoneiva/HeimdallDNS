// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"

	"github.com/ugoneiva/HeimdallDNS/internal/console"
)

func (a *api) consoleTenants(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.Console.States())
}

func (a *api) consoleAlerts(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.Console.Alerts())
}

func (a *api) consoleAdd(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string `json:"name"`
		URL         string `json:"url"`
		Token       string `json:"token"`
		InsecureTLS bool   `json:"insecure_tls"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	t, err := a.Console.Add(r.Context(), console.Tenant{Name: body.Name, URL: body.URL, Token: body.Token, InsecureTLS: body.InsecureTLS})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (a *api) consoleRemove(w http.ResponseWriter, r *http.Request) {
	if err := a.Console.Remove(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) consoleAck(w http.ResponseWriter, r *http.Request) {
	ev, err := strconv.ParseInt(r.PathValue("event"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("alerta inválido"))
		return
	}
	if err := a.Console.Ack(r.Context(), r.PathValue("id"), ev); err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, a.Console.Alerts())
}

// TemplatesKey guarda os modelos de política do console.
const TemplatesKey = "console.templates"

func (a *api) templates() ([]console.Template, error) {
	ts := []console.Template{}
	_, err := a.Store.GetJSON(TemplatesKey, &ts)
	return ts, err
}

func (a *api) consoleTemplates(w http.ResponseWriter, _ *http.Request) {
	ts, err := a.templates()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, ts)
}

// consolePutTemplates troca a lista de modelos (novos chegam sem id).
func (a *api) consolePutTemplates(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Templates []console.Template `json:"templates"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	var err error
	for i := range body.Templates {
		t := &body.Templates[i]
		if t.ID == "" {
			t.ID = randomToken(4)
		}
		t.Deny, t.Allow, t.Upstreams = clean(t.Deny), clean(t.Allow), clean(t.Upstreams)
		if err = console.ValidateTemplate(*t); err != nil {
			break
		}
	}
	if err == nil {
		err = a.Store.SetJSON(TemplatesKey, body.Templates)
	}
	a.audit(r, "console.templates", "", map[string]any{"templates": len(body.Templates)}, err)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	a.consoleTemplates(w, r)
}

func (a *api) consoleApply(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Tenants []string `json:"tenants"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	ts, err := a.templates()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	i := slices.IndexFunc(ts, func(t console.Template) bool { return t.ID == r.PathValue("id") })
	if i < 0 {
		writeErr(w, http.StatusNotFound, errors.New("modelo não encontrado"))
		return
	}
	if len(body.Tenants) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("escolha ao menos um cliente"))
		return
	}
	res := a.Console.Apply(r.Context(), ts[i], body.Tenants)
	failed := 0
	for _, x := range res {
		if !x.OK {
			failed++
		}
	}
	var aerr error
	if failed > 0 {
		aerr = fmt.Errorf("%d de %d clientes falharam", failed, len(res))
	}
	a.audit(r, "console.apply", ts[i].Name, map[string]any{"tenants": len(res), "failed": failed}, aerr)
	writeJSON(w, http.StatusOK, res)
}
