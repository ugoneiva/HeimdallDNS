// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/ugoneiva/HeimdallDNS/internal/filter"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

// Chaves das regras próprias globais nas configurações.
const (
	AllowKey = "filter.allow"
	DenyKey  = "filter.deny"
	allowKey = AllowKey
	denyKey  = DenyKey
)

// LoadUserFilter lê do banco as listas e regras criadas pela interface e
// entrega ao filtro. Não remonta as regras: chame Apply ou Start depois.
func LoadUserFilter(st *store.Store, f *filter.Manager) error {
	rows, err := st.Lists()
	if err != nil {
		return err
	}
	lists := make([]filter.ListSpec, len(rows))
	for i, l := range rows {
		lists[i] = filter.ListSpec{ID: l.ID, Name: l.Name, URL: l.URL, Enabled: l.Enabled, Category: l.Category}
	}
	var allow, deny []string
	if _, err := st.GetJSON(allowKey, &allow); err != nil {
		return err
	}
	if _, err := st.GetJSON(denyKey, &deny); err != nil {
		return err
	}
	f.SetUser(lists, allow, deny)
	return nil
}

// reloadFilter aplica as mudanças da interface em segundo plano (listas novas
// precisam ser baixadas).
func (a *api) reloadFilter() error {
	if err := LoadUserFilter(a.Store, a.Filter); err != nil {
		return err
	}
	go a.Filter.Apply(context.WithoutCancel(a.Context))
	return nil
}

func (a *api) getRules(w http.ResponseWriter, _ *http.Request) {
	cfgAllow, cfgDeny, allow, deny := a.Filter.UserRules()
	writeJSON(w, http.StatusOK, map[string][]string{
		"config_allow": nonNil(cfgAllow), "config_deny": nonNil(cfgDeny),
		"allow": nonNil(allow), "deny": nonNil(deny),
	})
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (a *api) saveRules(allow, deny []string) error {
	if _, bad := filter.CompileUserRules(allow, deny); len(bad) > 0 {
		return fmt.Errorf("regras inválidas: %s", strings.Join(bad, ", "))
	}
	if err := a.Store.SetJSON(allowKey, allow); err != nil {
		return err
	}
	if err := a.Store.SetJSON(denyKey, deny); err != nil {
		return err
	}
	if err := LoadUserFilter(a.Store, a.Filter); err != nil {
		return err
	}
	a.Filter.Apply(a.Context) // só regras: remonta na hora, sem baixar nada
	return nil
}

func (a *api) putRules(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Allow []string `json:"allow"`
		Deny  []string `json:"deny"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if err := a.saveRules(clean(body.Allow), clean(body.Deny)); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	a.getRules(w, r)
}

// quickRule bloqueia, libera ou tira um domínio das regras (atalho do log ao vivo).
func (a *api) quickRule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain string `json:"domain"`
		Action string `json:"action"` // block, allow ou remove
	}
	if !readJSON(w, r, &body) {
		return
	}
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(body.Domain), "."))
	if d == "" {
		writeErr(w, http.StatusBadRequest, errors.New("informe o domínio"))
		return
	}
	_, _, allow, deny := a.Filter.UserRules()
	drop := func(list []string) []string {
		return slices.DeleteFunc(list, func(s string) bool { return strings.EqualFold(s, d) })
	}
	allow, deny = drop(allow), drop(deny)
	switch body.Action {
	case "block":
		deny = append(deny, d)
	case "allow":
		allow = append(allow, d)
	case "remove":
	default:
		writeErr(w, http.StatusBadRequest, errors.New("action: use block, allow ou remove"))
		return
	}
	if err := a.saveRules(allow, deny); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	a.getRules(w, r)
}

func validCategory(c string) error {
	if c != "" && c != filter.CategoryThreat {
		return errors.New(`category: use "" (anúncios e rastreadores) ou "threat" (ameaças)`)
	}
	return nil
}

func validListURL(raw string) error {
	if strings.HasPrefix(raw, "/") && filepath.IsAbs(raw) {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "file") || (u.Scheme != "file" && u.Host == "") {
		return errors.New("use uma URL http(s)://, file:// ou um caminho absoluto")
	}
	return nil
}

func (a *api) addList(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     string `json:"name"`
		URL      string `json:"url"`
		Category string `json:"category"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	body.Name, body.URL = strings.TrimSpace(body.Name), strings.TrimSpace(body.URL)
	if err := validCategory(body.Category); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := validListURL(body.URL); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	for _, l := range a.Filter.Status() {
		if l.URL == body.URL {
			writeErr(w, http.StatusConflict, errors.New("essa lista já está cadastrada"))
			return
		}
	}
	if body.Name == "" {
		body.Name = body.URL
	}
	if _, err := a.Store.AddList(body.Name, body.URL, body.Category); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if err := a.reloadFilter(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, a.Filter.Status())
}

func (a *api) patchList(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("id inválido"))
		return
	}
	var body struct {
		Name     *string `json:"name"`
		Enabled  *bool   `json:"enabled"`
		Category *string `json:"category"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.Category != nil {
		if err := validCategory(*body.Category); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
	}
	found, err := a.Store.UpdateList(id, body.Name, body.Enabled, body.Category)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if !found {
		writeErr(w, http.StatusNotFound, errors.New("lista não encontrada (as do arquivo de configuração não mudam pela interface)"))
		return
	}
	if err := a.reloadFilter(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, a.Filter.Status())
}

func (a *api) deleteList(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("id inválido"))
		return
	}
	found, err := a.Store.DeleteList(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if !found {
		writeErr(w, http.StatusNotFound, errors.New("lista não encontrada"))
		return
	}
	if err := a.reloadFilter(); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, a.Filter.Status())
}

// testDomain responde "o que acontece com este domínio?", inclusive para um
// dispositivo específico (isolamento e regras próprias).
func (a *api) testDomain(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.URL.Query().Get("name")), "."))
	if name == "" {
		writeErr(w, http.StatusBadRequest, errors.New("informe name"))
		return
	}
	out := map[string]any{"name": name}
	verdict, rule, source := "allowed", "", ""

	global := a.Filter.Matcher().Match(name)
	out["global"] = map[string]string{"verdict": global.Verdict.String(), "rule": global.Rule}
	useGlobal := true

	if ref := r.URL.Query().Get("client"); ref != "" {
		c, err := a.Clients.Find(ref)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		p := c.Policy()
		res := p.Match(name)
		out["client"] = map[string]any{
			"id": c.ID(), "name": p.Display, "isolated": p.Isolated,
			"verdict": res.Verdict.String(), "rule": res.Rule, "skip_global_lists": p.SkipGlobal,
		}
		switch {
		case p.IsolatedFor(name):
			verdict, rule, source = "isolated", "dispositivo isolado ("+p.IsolateMode+")", "client"
			useGlobal = false
		case res.Verdict == filter.Blocked:
			verdict, rule, source = "blocked", res.Rule, "client"
			useGlobal = false
		case res.Verdict == filter.Allowed:
			rule, source = res.Rule, "client"
			useGlobal = false
		case p.SkipGlobal:
			useGlobal = false
		}
	}
	if useGlobal {
		switch global.Verdict {
		case filter.Blocked:
			verdict, rule, source = "blocked", global.Rule, "global"
		case filter.Allowed:
			rule, source = global.Rule, "global"
		default:
			if a.NRD != nil {
				if r, block := a.NRD.Block(name); block {
					verdict, rule, source = "blocked", r, "nrd"
				}
			}
		}
	}
	if global.Category != "" {
		out["category"] = global.Category
	}
	if a.NRD != nil {
		if age, ok := a.NRD.Age(name); ok {
			out["registered_days_ago"] = int(age.Hours() / 24)
		}
	}
	out["verdict"], out["rule"], out["source"] = verdict, rule, source
	writeJSON(w, http.StatusOK, out)
}
