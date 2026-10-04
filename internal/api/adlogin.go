// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/ad"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

// ADLogin liga a entrada no painel com as contas do Active Directory. O papel
// vem dos grupos do AD (o primeiro que casar, de admin para viewer).
type ADLogin struct {
	Enabled        bool
	AdminGroups    []string
	OperatorGroups []string
	ViewerGroups   []string
	RequireMFA     bool // a conta do AD cadastra o MFA no primeiro acesso
}

func (a *api) adLoginOn() bool { return a.AD != nil && a.ADLogin.Enabled }

// adRole escolhe o papel pelos grupos (sem diferenciar maiúsculas).
func (a *api) adRole(groups []string) string {
	in := func(list []string) bool {
		return slices.ContainsFunc(list, func(g string) bool {
			return slices.ContainsFunc(groups, func(have string) bool { return strings.EqualFold(have, g) })
		})
	}
	switch {
	case in(a.ADLogin.AdminGroups):
		return store.RoleAdmin
	case in(a.ADLogin.OperatorGroups):
		return store.RoleOperator
	case in(a.ADLogin.ViewerGroups):
		return store.RoleViewer
	}
	return ""
}

// adAuthenticate confere no AD e cria/atualiza a conta local espelho (que
// guarda o papel atual, o MFA e o último acesso; nunca a senha).
func (a *api) adAuthenticate(r *http.Request, name, password string) (*store.User, error) {
	if !a.adLoginOn() {
		return nil, errBadLogin
	}
	au, groups, err := a.AD.Login(r.Context(), name, password)
	if err != nil {
		if errors.Is(err, ad.ErrBadCredentials) {
			return nil, errBadLogin
		}
		return nil, err
	}
	role := a.adRole(groups)
	if role == "" {
		return nil, errors.New("a conta não está em nenhum grupo do AD liberado para o painel")
	}
	u, err := a.Store.UserByName(au.SAM)
	switch {
	case errors.Is(err, store.ErrNotFound):
		u = store.User{Username: au.SAM, Source: sourceAD, Created: time.Now()}
	case err != nil:
		return nil, err
	case u.Source != sourceAD:
		// Uma conta local com o mesmo nome nunca é tomada pelo AD.
		return nil, errBadLogin
	}
	if u.ID != 0 && u.Role != role {
		a.auditAs(r, au.SAM, "auth.ad_role", au.SAM, map[string]any{"from": u.Role, "to": role}, nil)
	}
	u.Role, u.Display = role, au.DisplayName
	if err := a.Store.SaveUser(&u); err != nil {
		return nil, err
	}
	return &u, nil
}
