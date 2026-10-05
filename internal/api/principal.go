// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

// principal é quem fez a requisição: um usuário do painel (sessão), um token
// de API com escopo, ou o token raiz do servidor (api.token, usado pela CLI,
// pelo console de MSP e pela alta disponibilidade).
type principal struct {
	Kind  string // session, token ou root
	Role  string
	User  *store.User
	Token *store.APIToken
}

const (
	kindSession = "session"
	kindToken   = "token"
	kindRoot    = "root"
)

// Actor é o nome que vai para a auditoria.
func (p *principal) Actor() string {
	switch p.Kind {
	case kindSession:
		return p.User.Username
	case kindToken:
		return "token:" + p.Token.Name
	}
	return "cli"
}

// StrongAuth diz se a identidade passou por um segundo fator: sessão com
// MFA ligado, ou um token (que já é um segredo forte e revogável).
func (p *principal) StrongAuth() bool {
	if p.Kind == kindSession {
		return p.User.MFA.Enabled
	}
	return true
}

type ctxKey int

const (
	principalKey ctxKey = iota
	auditedKey
)

func withPrincipal(r *http.Request, p *principal) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), principalKey, p))
}

// who devolve quem fez a requisição (nil = não autenticado).
func (a *api) who(r *http.Request) *principal {
	if p, ok := r.Context().Value(principalKey).(*principal); ok {
		return p
	}
	return a.authenticate(r)
}

// authenticate aceita um token (cabeçalho, ou na URL nas rotas /live) ou o
// cookie de sessão do painel.
func (a *api) authenticate(r *http.Request) *principal {
	tok, bearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !bearer && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/live") {
		tok = r.URL.Query().Get("token")
		bearer = tok != ""
	}
	if bearer {
		if a.Token != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(a.Token)) == 1 {
			return &principal{Kind: kindRoot, Role: store.RoleAdmin}
		}
		if a.Store == nil || !strings.HasPrefix(tok, tokenPrefix) {
			return nil
		}
		t, err := a.Store.TokenByHash(hashToken(tok))
		if err != nil || (!t.Expires.IsZero() && timeNow().After(t.Expires)) {
			return nil
		}
		_ = a.Store.TouchToken(t.ID, timeNow())
		return &principal{Kind: kindToken, Role: t.Role, Token: &t}
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" || a.Store == nil {
		return nil
	}
	uid, ok, err := a.Store.Session(hashToken(c.Value))
	if err != nil || !ok {
		return nil
	}
	u, err := a.Store.UserByID(uid)
	if err != nil || u.Disabled {
		return nil
	}
	return &principal{Kind: kindSession, Role: u.Role, User: &u}
}

// Rotas que só o administrador acessa, até para leitura.
var adminOnly = []string{"/api/users", "/api/tokens", "/api/backup", "/api/backups", "/api/restore", "/api/restart",
	"/api/audit", "/api/import/", "/api/wizard/", "/api/console/", "/api/notify", "/api/certs"}

// Alterações liberadas ao operador: operar aparelhos, alertas e reservas.
var operatorWrites = []string{"/api/clients/", "/api/security/events/", "/api/security/ignore", "/api/rules/quick",
	"/api/lists/refresh", "/api/dhcp/reservations"}

func hasPrefix(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if path == strings.TrimSuffix(p, "/") || strings.HasPrefix(path, p) || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// permitted aplica os papéis: admin faz tudo; operator lê e opera; viewer só lê.
// A própria conta (/api/auth/) é sempre liberada.
func permitted(role, method, path string) bool {
	if role == store.RoleAdmin || strings.HasPrefix(path, "/api/auth/") {
		return true
	}
	if hasPrefix(path, adminOnly) {
		return false
	}
	if method == http.MethodGet || method == http.MethodHead {
		return true
	}
	return role == store.RoleOperator && hasPrefix(path, operatorWrites)
}

var errNoPermission = errors.New("sem permissão para esta ação (fale com um administrador)")

func (a *api) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := a.authenticate(r)
		if p == nil {
			writeErr(w, http.StatusUnauthorized, errors.New("não autenticado"))
			return
		}
		if p.Kind == kindSession && r.Method != http.MethodGet && r.Method != http.MethodHead && !sameOrigin(r) {
			writeErr(w, http.StatusForbidden, errors.New("origem não permitida"))
			return
		}
		if p.Kind == kindSession && a.mustEnrollMFA(p.User) && !strings.HasPrefix(r.URL.Path, "/api/auth/") {
			writeErr(w, http.StatusForbidden, errors.New("cadastre a verificação em duas etapas para continuar"))
			return
		}
		if !permitted(p.Role, r.Method, r.URL.Path) {
			// Tentativa barrada pelo papel: interessa ao SIEM (conta comprometida
			// tentando subir de nível, token usado fora do escopo).
			a.auditAs(r, p.Actor(), "auth.denied", r.Method+" "+r.URL.Path, map[string]any{"role": p.Role}, errNoPermission)
			writeErr(w, http.StatusForbidden, errNoPermission)
			return
		}
		next.ServeHTTP(w, withPrincipal(r, p))
	})
}

// mustEnrollMFA: contas do AD precisam de MFA (ad.login.require_mfa).
func (a *api) mustEnrollMFA(u *store.User) bool {
	return u.Source == sourceAD && a.ADLogin.RequireMFA && !u.MFA.Strong()
}

// statusWriter guarda o código da resposta para a auditoria genérica.
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) WriteHeader(c int) {
	s.code = c
	s.ResponseWriter.WriteHeader(c)
}

func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// auditWrites registra toda alteração que o próprio handler não registrou.
func (a *api) auditWrites(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || a.Store == nil {
			next.ServeHTTP(w, r)
			return
		}
		done := new(bool)
		r = r.WithContext(context.WithValue(r.Context(), auditedKey, done))
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(sw, r)
		if *done {
			return
		}
		action := r.Method + " " + r.URL.Path
		if r.Pattern != "" {
			action = r.Pattern
		}
		var err error
		if sw.code >= 400 {
			err = errors.New(http.StatusText(sw.code))
		}
		a.audit(r, action, r.URL.Path, map[string]any{"status": sw.code, "ms": time.Since(start).Milliseconds()}, err)
	})
}
