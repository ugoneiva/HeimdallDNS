// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

// Segurança da conta: códigos de recuperação do MFA, sessões ativas e
// passkeys (WebAuthn).

func (a *api) accountRoutes(api, root *http.ServeMux) {
	api.HandleFunc("POST /api/auth/mfa/recovery", a.mfaRecovery)
	api.HandleFunc("GET /api/auth/sessions", a.mySessions)
	api.HandleFunc("DELETE /api/auth/sessions/{id}", a.endMySession)
	api.HandleFunc("DELETE /api/auth/sessions", a.endOtherSessions)
	api.HandleFunc("GET /api/users/sessions", a.allSessions)
	api.HandleFunc("DELETE /api/users/sessions/{id}", a.endAnySession)
	api.HandleFunc("GET /api/auth/passkeys", a.listPasskeys)
	api.HandleFunc("POST /api/auth/passkeys/begin", a.passkeyRegisterBegin)
	api.HandleFunc("POST /api/auth/passkeys/finish", a.passkeyRegisterFinish)
	api.HandleFunc("DELETE /api/auth/passkeys/{id}", a.deletePasskey)
	api.HandleFunc("POST /api/auth/passkeys/verify", a.passkeyStepUp)
	root.HandleFunc("POST /api/auth/passkey/begin", a.passkeyLoginBegin)
	root.HandleFunc("POST /api/auth/passkey/login", a.passkeyLogin)
}

// ---------------------------------------------------------------------------
// Códigos de recuperação

const (
	recoveryCount    = 10
	recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789" // sem 0/o, 1/l/i
)

func normalizeRecovery(code string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '-' || r == ' ':
			return -1
		case r >= 'A' && r <= 'Z':
			return r + 32
		}
		return r
	}, code)
}

func hashRecovery(code string) string {
	h := sha256.Sum256([]byte("heimdalldns-recovery:" + normalizeRecovery(code)))
	return hex.EncodeToString(h[:])
}

// newRecoveryCodes gera os códigos (mostrados uma vez) e os hashes (guardados).
func newRecoveryCodes() (codes, hashes []string) {
	for range recoveryCount {
		var b [10]byte
		_, _ = rand.Read(b[:])
		var sb strings.Builder
		for i, v := range b {
			if i == 5 {
				sb.WriteByte('-')
			}
			sb.WriteByte(recoveryAlphabet[int(v)%len(recoveryAlphabet)])
		}
		codes = append(codes, sb.String())
		hashes = append(hashes, hashRecovery(sb.String()))
	}
	return codes, hashes
}

// looksLikeTOTP: seis dígitos. Qualquer outra coisa é tentada como código de
// recuperação.
func looksLikeTOTP(code string) bool {
	code = strings.TrimSpace(code)
	return len(code) == totpDigits && strings.Trim(code, "0123456789") == ""
}

// verifySecond confere a segunda etapa digitada: código do app autenticador
// ou de recuperação (que é gasto). Devolve o método usado.
func (a *api) verifySecond(r *http.Request, u *store.User, code string) (string, error) {
	if looksLikeTOTP(code) {
		if !u.MFA.Enabled {
			return "", errors.New("esta conta não usa aplicativo autenticador: use a passkey ou um código de recuperação")
		}
		return "totp", a.verifyUserMFA(u, code)
	}
	a.setupMu.Lock()
	defer a.setupMu.Unlock()
	cur, err := a.Store.UserByID(u.ID)
	if err != nil {
		return "", err
	}
	want := hashRecovery(code)
	i := slices.IndexFunc(cur.MFA.Recovery, func(h string) bool { return subtle.ConstantTimeCompare([]byte(h), []byte(want)) == 1 })
	if normalizeRecovery(code) == "" || i < 0 {
		return "", errors.New("código de verificação inválido")
	}
	cur.MFA.Recovery = slices.Delete(cur.MFA.Recovery, i, i+1)
	if err := a.Store.SaveUser(&cur); err != nil {
		return "", err
	}
	u.MFA = cur.MFA
	a.auditAs(r, u.Username, "auth.recovery_code", u.Username, map[string]any{"left": len(cur.MFA.Recovery)}, nil)
	return "recuperação", nil
}

// mfaRecovery gera códigos novos (os antigos deixam de valer). Exige a
// segunda etapa de novo (código ou passkey): quem roubou a sessão não leva
// os códigos.
func (a *api) mfaRecovery(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code    string            `json:"code"`
		Passkey *passkeyAssertion `json:"passkey"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	u := a.sessionUser(w, r)
	if u == nil {
		return
	}
	if !u.MFA.Strong() {
		writeErr(w, http.StatusConflict, errors.New("ligue a verificação em duas etapas ou cadastre uma passkey primeiro"))
		return
	}
	var err error
	if body.Passkey != nil {
		err = a.verifyPasskey(r, u, *body.Passkey, "login")
	} else {
		_, err = a.verifySecond(r, u, body.Code)
	}
	if err != nil {
		a.guard.fail(remoteIP(r))
		a.audit(r, "auth.recovery_codes", u.Username, nil, err)
		writeErr(w, http.StatusForbidden, err)
		return
	}
	codes, hashes := newRecoveryCodes()
	u.MFA.Recovery = hashes
	if err := a.Store.SaveUser(u); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	a.audit(r, "auth.recovery_codes", u.Username, nil, nil)
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// passkeyStepUp prepara o desafio para confirmar uma ação com a passkey.
func (a *api) passkeyStepUp(w http.ResponseWriter, r *http.Request) {
	u := a.sessionUser(w, r)
	if u == nil {
		return
	}
	if _, err := a.relyingParty(r); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	ch := a.beginSecondFactor(r, u)
	if ch == nil {
		writeErr(w, http.StatusConflict, errors.New("nenhuma passkey nesta conta"))
		return
	}
	writeJSON(w, http.StatusOK, ch)
}

// ensureRecovery cria os códigos na primeira segunda etapa da conta.
func ensureRecovery(u *store.User) []string {
	if len(u.MFA.Recovery) > 0 {
		return nil
	}
	codes, hashes := newRecoveryCodes()
	u.MFA.Recovery = hashes
	return codes
}

// ---------------------------------------------------------------------------
// Sessões

type sessionView struct {
	store.SessionRow
	Username string `json:"username,omitempty"`
	Current  bool   `json:"current"`
}

func currentSessionID(r *http.Request) string {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		return store.SessionID(hashToken(c.Value))
	}
	return ""
}

func (a *api) sessionViews(r *http.Request, userID int64) ([]sessionView, error) {
	rows, err := a.Store.Sessions(userID)
	if err != nil {
		return nil, err
	}
	names := map[int64]string{}
	if userID == 0 {
		us, err := a.Store.Users()
		if err != nil {
			return nil, err
		}
		for _, u := range us {
			names[u.ID] = u.Username
		}
	}
	cur := currentSessionID(r)
	out := make([]sessionView, 0, len(rows))
	for _, s := range rows {
		out = append(out, sessionView{SessionRow: s, Username: names[s.UserID], Current: s.ID == cur})
	}
	return out, nil
}

func (a *api) mySessions(w http.ResponseWriter, r *http.Request) {
	u := a.sessionUser(w, r)
	if u == nil {
		return
	}
	out, err := a.sessionViews(r, u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) endMySession(w http.ResponseWriter, r *http.Request) {
	u := a.sessionUser(w, r)
	if u == nil {
		return
	}
	a.endSession(w, r, u.ID)
}

func (a *api) endAnySession(w http.ResponseWriter, r *http.Request) { a.endSession(w, r, 0) }

func (a *api) endSession(w http.ResponseWriter, r *http.Request, userID int64) {
	id := r.PathValue("id")
	ok, err := a.Store.DeleteSessionByID(id, userID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, errors.New("sessão não encontrada"))
		return
	}
	a.audit(r, "auth.session_end", id, nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

// endOtherSessions encerra as outras sessões da conta (ex.: esqueceu logado
// em outro computador).
func (a *api) endOtherSessions(w http.ResponseWriter, r *http.Request) {
	u := a.sessionUser(w, r)
	if u == nil {
		return
	}
	c, _ := r.Cookie(sessionCookie)
	n, err := a.Store.DeleteOtherSessions(u.ID, hashToken(c.Value))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	a.audit(r, "auth.session_end_others", u.Username, map[string]any{"ended": n}, nil)
	writeJSON(w, http.StatusOK, map[string]int64{"ended": n})
}

func (a *api) allSessions(w http.ResponseWriter, r *http.Request) {
	out, err := a.sessionViews(r, 0)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// Passkeys (WebAuthn)

var errPasskeyHost = errors.New("passkeys precisam do painel aberto por um nome (ex.: heimdall.empresa.local) com HTTPS, ou por localhost; endereço IP não serve")

// relyingParty monta o WebAuthn para o endereço por onde o painel foi aberto.
// O navegador assina a origem verdadeira, então um Origin falso não ajuda
// ninguém: a credencial só vale para o nome em que foi criada.
func (a *api) relyingParty(r *http.Request) (*webauthn.WebAuthn, error) {
	origin := r.Header.Get("Origin")
	o, err := url.Parse(origin)
	if err != nil || o.Host == "" || !strings.EqualFold(o.Host, r.Host) {
		return nil, errors.New("origem não permitida")
	}
	host := o.Hostname()
	if _, err := netip.ParseAddr(host); err == nil {
		return nil, errPasskeyHost
	}
	local := host == "localhost" || strings.HasSuffix(host, ".localhost")
	if o.Scheme != "https" && !local {
		return nil, errPasskeyHost
	}
	return webauthn.New(&webauthn.Config{
		RPID: host, RPDisplayName: "HeimdallDNS", RPOrigins: []string{o.Scheme + "://" + o.Host},
	})
}

// waUser adapta a conta para a biblioteca.
type waUser struct {
	u     *store.User
	creds []webauthn.Credential
}

func newWAUser(u *store.User) (*waUser, error) {
	wu := &waUser{u: u}
	for _, p := range u.MFA.Passkeys {
		var c webauthn.Credential
		if err := json.Unmarshal(p.Credential, &c); err != nil {
			return nil, fmt.Errorf("passkey %q ilegível: %w", p.Name, err)
		}
		wu.creds = append(wu.creds, c)
	}
	return wu, nil
}

func (w *waUser) WebAuthnID() []byte {
	b, _ := base64.RawURLEncoding.DecodeString(w.u.MFA.Handle)
	return b
}
func (w *waUser) WebAuthnName() string { return w.u.Username }
func (w *waUser) WebAuthnDisplayName() string {
	if w.u.Display != "" {
		return w.u.Display
	}
	return w.u.Username
}
func (w *waUser) WebAuthnCredentials() []webauthn.Credential { return w.creds }

// ceremonies guarda o desafio entre o começo e o fim (5 minutos, uso único).
type ceremonies struct {
	mu sync.Mutex
	m  map[string]ceremony
}

type ceremony struct {
	kind    string // register, login (segunda etapa) ou passwordless
	userID  int64
	session webauthn.SessionData
	expires time.Time
}

const ceremonyTTL = 5 * time.Minute

func (c *ceremonies) put(cr ceremony) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]ceremony{}
	}
	now := timeNow()
	for k, v := range c.m {
		if now.After(v.expires) {
			delete(c.m, k)
		}
	}
	if len(c.m) >= 1000 { // ninguém lota a memória pedindo desafios
		for k := range c.m {
			delete(c.m, k)
			break
		}
	}
	id := randomToken(16)
	cr.expires = now.Add(ceremonyTTL)
	c.m[id] = cr
	return id
}

func (c *ceremonies) take(id, kind string) (ceremony, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cr, ok := c.m[id]
	delete(c.m, id)
	if !ok || cr.kind != kind || timeNow().After(cr.expires) {
		return ceremony{}, false
	}
	return cr, true
}

// passkeyAssertion é o que o navegador manda no fim do login com passkey.
type passkeyAssertion struct {
	ChallengeID string          `json:"challenge_id"`
	Credential  json.RawMessage `json:"credential"`
}

func (a *api) listPasskeys(w http.ResponseWriter, r *http.Request) {
	u := a.sessionUser(w, r)
	if u == nil {
		return
	}
	writeJSON(w, http.StatusOK, passkeyList(u))
}

type passkeyView struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"last_used,omitzero"`
}

func passkeyList(u *store.User) []passkeyView {
	out := []passkeyView{}
	for _, p := range u.MFA.Passkeys {
		out = append(out, passkeyView{ID: p.ID, Name: p.Name, Created: p.Created, LastUsed: p.LastUsed})
	}
	return out
}

func (a *api) passkeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	u := a.sessionUser(w, r)
	if u == nil {
		return
	}
	wa, err := a.relyingParty(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if u.MFA.Handle == "" {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		u.MFA.Handle = base64.RawURLEncoding.EncodeToString(b)
		if err := a.Store.SaveUser(u); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
	}
	wu, err := newWAUser(u)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	var exclude []protocol.CredentialDescriptor
	for _, c := range wu.creds {
		exclude = append(exclude, c.Descriptor())
	}
	creation, sess, err := wa.BeginRegistration(wu,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithExclusions(exclude))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	id := a.ceremonies.put(ceremony{kind: "register", userID: u.ID, session: *sess})
	writeJSON(w, http.StatusOK, map[string]any{"challenge_id": id, "options": creation.Response})
}

func (a *api) passkeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ChallengeID string          `json:"challenge_id"`
		Name        string          `json:"name"`
		Credential  json.RawMessage `json:"credential"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	u := a.sessionUser(w, r)
	if u == nil {
		return
	}
	cr, ok := a.ceremonies.take(body.ChallengeID, "register")
	if !ok || cr.userID != u.ID {
		writeErr(w, http.StatusBadRequest, errors.New("o pedido venceu; tente de novo"))
		return
	}
	wa, err := a.relyingParty(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body.Credential)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("resposta da passkey inválida: %w", err))
		return
	}
	a.setupMu.Lock()
	defer a.setupMu.Unlock()
	cur, err := a.Store.UserByID(u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	wu, err := newWAUser(&cur)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	cred, err := wa.CreateCredential(wu, cr.session, parsed)
	if err != nil {
		a.audit(r, "auth.passkey_add", u.Username, nil, err)
		writeErr(w, http.StatusBadRequest, fmt.Errorf("a passkey não foi aceita: %w", err))
		return
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = fmt.Sprintf("Passkey %d", len(cur.MFA.Passkeys)+1)
	}
	if len(name) > 60 {
		name = name[:60]
	}
	pk := store.Passkey{ID: base64.RawURLEncoding.EncodeToString(cred.ID), Name: name, Created: timeNow(), Credential: raw}
	cur.MFA.Passkeys = append(cur.MFA.Passkeys, pk)
	codes := ensureRecovery(&cur)
	if err := a.Store.SaveUser(&cur); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	a.audit(r, "auth.passkey_add", u.Username, map[string]any{"name": name}, nil)
	out := map[string]any{"passkeys": passkeyList(&cur)}
	if codes != nil {
		out["recovery_codes"] = codes
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) deletePasskey(w http.ResponseWriter, r *http.Request) {
	u := a.sessionUser(w, r)
	if u == nil {
		return
	}
	a.setupMu.Lock()
	defer a.setupMu.Unlock()
	cur, err := a.Store.UserByID(u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	id := r.PathValue("id")
	i := slices.IndexFunc(cur.MFA.Passkeys, func(p store.Passkey) bool { return p.ID == id })
	if i < 0 {
		writeErr(w, http.StatusNotFound, errors.New("passkey não encontrada"))
		return
	}
	if len(cur.MFA.Passkeys) == 1 && !cur.MFA.Enabled && cur.Source == sourceAD && a.ADLogin.RequireMFA {
		writeErr(w, http.StatusForbidden, errors.New("contas do Active Directory precisam da verificação em duas etapas: ligue o aplicativo autenticador antes de apagar a última passkey"))
		return
	}
	name := cur.MFA.Passkeys[i].Name
	cur.MFA.Passkeys = slices.Delete(cur.MFA.Passkeys, i, i+1)
	if !cur.MFA.Strong() {
		cur.MFA.Recovery = nil // sem segunda etapa, os códigos não servem para nada
	}
	if err := a.Store.SaveUser(&cur); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	a.audit(r, "auth.passkey_remove", u.Username, map[string]any{"name": name}, nil)
	writeJSON(w, http.StatusOK, passkeyList(&cur))
}

// beginSecondFactor prepara o desafio da passkey depois da senha certa.
func (a *api) beginSecondFactor(r *http.Request, u *store.User) map[string]any {
	if len(u.MFA.Passkeys) == 0 {
		return nil
	}
	wa, err := a.relyingParty(r)
	if err != nil {
		return nil // aberto por IP: sobra o app autenticador ou o código de recuperação
	}
	wu, err := newWAUser(u)
	if err != nil {
		return nil
	}
	assertion, sess, err := wa.BeginLogin(wu, webauthn.WithUserVerification(protocol.VerificationPreferred))
	if err != nil {
		return nil
	}
	id := a.ceremonies.put(ceremony{kind: "login", userID: u.ID, session: *sess})
	return map[string]any{"challenge_id": id, "options": assertion.Response}
}

// verifyPasskey confere a passkey da segunda etapa (ou do login sem senha) e
// atualiza o contador e o último uso.
func (a *api) verifyPasskey(r *http.Request, u *store.User, pa passkeyAssertion, kind string) error {
	cr, ok := a.ceremonies.take(pa.ChallengeID, kind)
	if !ok || (kind == "login" && cr.userID != u.ID) {
		return errors.New("o pedido da passkey venceu; tente de novo")
	}
	wa, err := a.relyingParty(r)
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(pa.Credential)
	if err != nil {
		return fmt.Errorf("resposta da passkey inválida: %w", err)
	}
	a.setupMu.Lock()
	defer a.setupMu.Unlock()
	cur, err := a.Store.UserByID(u.ID)
	if err != nil {
		return err
	}
	wu, err := newWAUser(&cur)
	if err != nil {
		return err
	}
	var cred *webauthn.Credential
	if kind == "login" {
		cred, err = wa.ValidateLogin(wu, cr.session, parsed)
	} else {
		cred, err = wa.ValidateDiscoverableLogin(func(_, _ []byte) (webauthn.User, error) { return wu, nil }, cr.session, parsed)
	}
	if err != nil {
		return errors.New("passkey não reconhecida")
	}
	for i, p := range cur.MFA.Passkeys {
		if p.ID == base64.RawURLEncoding.EncodeToString(cred.ID) {
			raw, _ := json.Marshal(cred)
			cur.MFA.Passkeys[i].Credential, cur.MFA.Passkeys[i].LastUsed = raw, timeNow()
		}
	}
	if err := a.Store.SaveUser(&cur); err != nil {
		return err
	}
	u.MFA = cur.MFA
	return nil
}

// passkeyLoginBegin começa o login sem senha (o navegador mostra as passkeys
// salvas para este endereço).
func (a *api) passkeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	if d := a.guard.blocked(remoteIP(r)); d > 0 {
		writeErr(w, http.StatusTooManyRequests, errors.New("muitas tentativas; aguarde "+d.Round(time.Second).String()))
		return
	}
	wa, err := a.relyingParty(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	assertion, sess, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	id := a.ceremonies.put(ceremony{kind: "passwordless", session: *sess})
	writeJSON(w, http.StatusOK, map[string]any{"challenge_id": id, "options": assertion.Response})
}

// passkeyLogin termina o login sem senha. Vale para contas locais: as do AD
// entram com a senha do domínio (que pode ter sido bloqueada lá) e usam a
// passkey como segunda etapa.
func (a *api) passkeyLogin(w http.ResponseWriter, r *http.Request) {
	ip := remoteIP(r)
	if d := a.guard.blocked(ip); d > 0 {
		writeErr(w, http.StatusTooManyRequests, errors.New("muitas tentativas; aguarde "+d.Round(time.Second).String()))
		return
	}
	var body passkeyAssertion
	if !readJSON(w, r, &body) {
		return
	}
	fail := func(name string, err error) {
		a.guard.fail(ip)
		a.Logger.Warn("login com passkey recusado", "usuario", name, "origem", ip, "motivo", err)
		a.auditAs(r, name, "auth.login", name, map[string]any{"method": "passkey"}, err)
		writeErr(w, http.StatusUnauthorized, err)
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body.Credential)
	if err != nil {
		fail("", errors.New("resposta da passkey inválida"))
		return
	}
	u, err := a.userByHandle(parsed.Response.UserHandle)
	if err != nil {
		fail("", errors.New("passkey não reconhecida"))
		return
	}
	if u.Disabled {
		fail(u.Username, errors.New("conta desativada"))
		return
	}
	if u.Source != sourceLocal {
		fail(u.Username, errors.New("contas do Active Directory entram com a senha do domínio; a passkey vale como segunda etapa"))
		return
	}
	if err := a.verifyPasskey(r, u, body, "passwordless"); err != nil {
		fail(u.Username, err)
		return
	}
	a.finishLogin(w, r, u, "passkey")
}

func (a *api) userByHandle(handle []byte) (*store.User, error) {
	if len(handle) == 0 {
		return nil, store.ErrNotFound
	}
	us, err := a.Store.Users()
	if err != nil {
		return nil, err
	}
	for i := range us {
		h, _ := base64.RawURLEncoding.DecodeString(us[i].MFA.Handle)
		if len(h) > 0 && bytes.Equal(h, handle) {
			return &us[i], nil
		}
	}
	return nil, store.ErrNotFound
}

// finishLogin abre a sessão depois de todas as etapas.
func (a *api) finishLogin(w http.ResponseWriter, r *http.Request, u *store.User, method string) {
	a.guard.ok(remoteIP(r))
	u.LastLogin = time.Now()
	if err := a.Store.SaveUser(u); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if err := a.startSession(w, r, u.ID, method); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	a.auditAs(r, u.Username, "auth.login", u.Username, map[string]any{"source": u.Source, "role": u.Role, "method": method}, nil)
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
}

// clientInfo resume de onde veio a sessão.
func clientInfo(r *http.Request, method string) store.SessionInfo {
	ip := remoteIP(r)
	if h, _, err := net.SplitHostPort(ip); err == nil {
		ip = h
	}
	return store.SessionInfo{IP: ip, UserAgent: r.UserAgent(), Method: method}
}
