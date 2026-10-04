// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

const (
	totpStep   = 30 * time.Second
	totpDigits = 6
	totpSkew   = 1 // aceita o código do passo anterior e do seguinte (relógio torto)
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func totpAt(secret string, step int64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	h := hmac.New(sha1.New, key)
	h.Write(msg[:])
	sum := h.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, v%1_000_000), nil
}

// totpCheck devolve o passo do código válido (0 = inválido).
func totpCheck(secret, code string, now time.Time, after int64) int64 {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0
	}
	cur := now.Unix() / int64(totpStep/time.Second)
	for d := -totpSkew; d <= totpSkew; d++ {
		step := cur + int64(d)
		if step <= after {
			continue
		}
		want, err := totpAt(secret, step)
		if err == nil && subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step
		}
	}
	return 0
}

// verifyUserMFA confere o código e grava o passo usado (sem reuso). Relê a
// conta para não perder um passo gravado por outra requisição.
func (a *api) verifyUserMFA(u *store.User, code string) error {
	a.setupMu.Lock()
	defer a.setupMu.Unlock()
	cur, err := a.Store.UserByID(u.ID)
	if err != nil {
		return err
	}
	if !cur.MFA.Enabled {
		return nil
	}
	step := totpCheck(cur.MFA.Secret, code, timeNow(), cur.MFA.LastStep)
	if step == 0 {
		return errors.New("código de verificação inválido")
	}
	cur.MFA.LastStep = step
	if err := a.Store.SaveUser(&cur); err != nil {
		return err
	}
	u.MFA = cur.MFA
	return nil
}

// sessionUser exige uma sessão do painel (MFA é de uma pessoa, não de token).
func (a *api) sessionUser(w http.ResponseWriter, r *http.Request) *store.User {
	p := a.who(r)
	if p == nil || p.Kind != kindSession {
		writeErr(w, http.StatusForbidden, errors.New("a verificação em duas etapas é configurada por quem entra no painel"))
		return nil
	}
	return p.User
}

// mfaSetup gera um segredo novo (ainda não ligado) e devolve a URI para o app.
func (a *api) mfaSetup(w http.ResponseWriter, r *http.Request) {
	u := a.sessionUser(w, r)
	if u == nil {
		return
	}
	raw := make([]byte, 20)
	_, _ = rand.Read(raw)
	u.MFA.Pending = b32.EncodeToString(raw)
	if err := a.Store.SaveUser(u); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	label := url.PathEscape("HeimdallDNS:" + u.Username)
	uri := fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=HeimdallDNS&digits=6&period=30", label, u.MFA.Pending)
	writeJSON(w, http.StatusOK, map[string]string{"secret": u.MFA.Pending, "uri": uri})
}

// mfaEnable liga o MFA depois do primeiro código válido do segredo pendente.
func (a *api) mfaEnable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	u := a.sessionUser(w, r)
	if u == nil {
		return
	}
	if u.MFA.Pending == "" {
		writeErr(w, http.StatusConflict, errors.New("gere o segredo primeiro"))
		return
	}
	step := totpCheck(u.MFA.Pending, body.Code, timeNow(), 0)
	if step == 0 {
		a.guard.fail(remoteIP(r))
		writeErr(w, http.StatusBadRequest, errors.New("código inválido: confira a hora do celular e tente o código atual"))
		return
	}
	u.MFA = store.MFA{Secret: u.MFA.Pending, Enabled: true, LastStep: step}
	if err := a.Store.SaveUser(u); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	a.audit(r, "auth.mfa_enable", u.Username, nil, nil)
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": true})
}

// mfaDisable desliga. Pela sessão exige a senha (contas locais) e um código;
// com o token raiz ("heimdalldns mfa-off -user x") não exige, para recuperar
// o acesso de quem perdeu o celular.
func (a *api) mfaDisable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	u, p, err := a.targetUser(r, body.Username)
	if err != nil {
		writeErr(w, http.StatusForbidden, err)
		return
	}
	if p.Kind == kindSession {
		if a.mustEnrollMFA(u) || (u.Source == sourceAD && a.ADLogin.RequireMFA) {
			writeErr(w, http.StatusForbidden, errors.New("contas do Active Directory precisam da verificação em duas etapas"))
			return
		}
		if u.Source == sourceLocal && bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(body.Password)) != nil {
			a.guard.fail(remoteIP(r))
			writeErr(w, http.StatusForbidden, errors.New("senha incorreta"))
			return
		}
		if err := a.verifyUserMFA(u, body.Code); err != nil {
			a.guard.fail(remoteIP(r))
			writeErr(w, http.StatusForbidden, err)
			return
		}
	}
	u.MFA = store.MFA{}
	if err := a.Store.SaveUser(u); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	a.audit(r, "auth.mfa_disable", u.Username, nil, nil)
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": false})
}
