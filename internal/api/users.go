// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

func (a *api) userRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/users", a.listUsers)
	mux.HandleFunc("POST /api/users", a.createUser)
	mux.HandleFunc("PATCH /api/users/{id}", a.patchUser)
	mux.HandleFunc("DELETE /api/users/{id}", a.deleteUser)
	mux.HandleFunc("GET /api/tokens", a.listTokens)
	mux.HandleFunc("POST /api/tokens", a.createToken)
	mux.HandleFunc("DELETE /api/tokens/{id}", a.deleteToken)
	mux.HandleFunc("GET /api/audit", a.auditList)
}

func (a *api) listUsers(w http.ResponseWriter, _ *http.Request) {
	us, err := a.Store.Users()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]userView, len(us))
	for i := range us {
		out[i] = a.view(&us[i])
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) createUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Display  string `json:"display"`
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	name, err := cleanUsername(body.Username)
	if err == nil && !store.ValidRole(body.Role) {
		err = errors.New("papel inválido: use admin, operator ou viewer")
	}
	var hash string
	if err == nil {
		hash, err = hashPassword(body.Password)
	}
	if err == nil {
		if _, e := a.Store.UserByName(name); e == nil {
			err = errors.New("já existe uma conta com esse nome")
		}
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	u := store.User{Username: name, Display: strings.TrimSpace(body.Display), Role: body.Role, Source: sourceLocal, PasswordHash: hash}
	err = a.Store.SaveUser(&u)
	a.audit(r, "user.create", name, map[string]any{"role": body.Role}, err)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, a.view(&u))
}

func (a *api) userFromPath(w http.ResponseWriter, r *http.Request) *store.User {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("id inválido"))
		return nil
	}
	u, err := a.Store.UserByID(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, errors.New("usuário não encontrado"))
		return nil
	}
	return &u
}

// lastAdmin diz se tirar u do papel de admin (ou desativar) deixaria o
// painel sem nenhum administrador ativo.
func (a *api) lastAdmin(u *store.User) bool {
	if u.Role != store.RoleAdmin || u.Disabled {
		return false
	}
	n, err := a.Store.CountAdmins()
	return err != nil || n <= 1
}

func (a *api) patchUser(w http.ResponseWriter, r *http.Request) {
	u := a.userFromPath(w, r)
	if u == nil {
		return
	}
	var body struct {
		Display  *string `json:"display"`
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
		Password *string `json:"password"`
		ResetMFA bool    `json:"reset_mfa"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	details := map[string]any{}
	dropSessions := false
	var err error
	if body.Display != nil {
		u.Display = strings.TrimSpace(*body.Display)
	}
	if body.Role != nil && *body.Role != u.Role {
		switch {
		case !store.ValidRole(*body.Role):
			err = errors.New("papel inválido: use admin, operator ou viewer")
		case u.Source == sourceAD:
			err = errors.New("o papel das contas do AD vem dos grupos (ad.login): mude no AD")
		case *body.Role != store.RoleAdmin && a.lastAdmin(u):
			err = errors.New("este é o último administrador ativo")
		}
		details["role"] = *body.Role
		u.Role, dropSessions = *body.Role, true
	}
	if err == nil && body.Disabled != nil && *body.Disabled != u.Disabled {
		if *body.Disabled && a.lastAdmin(u) {
			err = errors.New("este é o último administrador ativo")
		}
		details["disabled"] = *body.Disabled
		u.Disabled, dropSessions = *body.Disabled, true
	}
	if err == nil && body.Password != nil {
		if u.Source != sourceLocal {
			err = errors.New("a senha desta conta é a do Active Directory")
		} else if u.PasswordHash, err = hashPassword(*body.Password); err == nil {
			details["password"] = "redefinida"
			dropSessions = true
		}
	}
	if err == nil && body.ResetMFA {
		u.MFA = store.MFA{}
		details["mfa"] = "zerado"
		dropSessions = true
	}
	if err == nil {
		err = a.Store.SaveUser(u)
	}
	if err == nil && dropSessions {
		err = a.Store.DeleteUserSessions(u.ID)
	}
	a.audit(r, "user.update", u.Username, details, err)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, a.view(u))
}

func (a *api) deleteUser(w http.ResponseWriter, r *http.Request) {
	u := a.userFromPath(w, r)
	if u == nil {
		return
	}
	var err error
	if p := a.who(r); p != nil && p.Kind == kindSession && p.User.ID == u.ID {
		err = errors.New("não dá para excluir a própria conta")
	} else if a.lastAdmin(u) {
		err = errors.New("este é o último administrador ativo")
	}
	if err == nil {
		err = a.Store.DeleteUser(u.ID)
	}
	a.audit(r, "user.delete", u.Username, nil, err)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) listTokens(w http.ResponseWriter, _ *http.Request) {
	ts, err := a.Store.Tokens()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	for i := range ts {
		ts[i].Hash = ""
	}
	writeJSON(w, http.StatusOK, ts)
}

// createToken cria um token com papel e validade; ele só aparece nesta
// resposta (o banco guarda o hash).
func (a *api) createToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string `json:"name"`
		Role        string `json:"role"`
		ExpiresDays int    `json:"expires_days"` // 0 = não vence
	}
	if !readJSON(w, r, &body) {
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	var err error
	switch {
	case body.Name == "" || len(body.Name) > 64:
		err = errors.New("dê um nome ao token (até 64 caracteres), ex.: \"Grafana\" ou \"script de backup\"")
	case !store.ValidRole(body.Role):
		err = errors.New("papel inválido: use admin, operator ou viewer")
	case body.ExpiresDays < 0 || body.ExpiresDays > 3650:
		err = errors.New("validade entre 0 (não vence) e 3650 dias")
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	secret := tokenPrefix + randomToken(20)
	t := store.APIToken{Name: body.Name, Hash: hashToken(secret), Prefix: secret[:len(tokenPrefix)+6], Role: body.Role}
	if p := a.who(r); p != nil {
		t.CreatedBy = p.Actor()
	}
	if body.ExpiresDays > 0 {
		t.Expires = time.Now().Add(time.Duration(body.ExpiresDays) * 24 * time.Hour)
	}
	err = a.Store.CreateToken(&t)
	a.audit(r, "token.create", t.Name, map[string]any{"role": t.Role, "expires_days": body.ExpiresDays}, err)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	t.Hash = ""
	writeJSON(w, http.StatusCreated, map[string]any{"token": secret, "info": t})
}

func (a *api) deleteToken(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("id inválido"))
		return
	}
	ok, err := a.Store.DeleteToken(id)
	if err == nil && !ok {
		err = errors.New("token não encontrado")
	}
	a.audit(r, "token.delete", strconv.FormatInt(id, 10), nil, err)
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
