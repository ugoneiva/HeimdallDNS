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
)

// MFAKey guarda a verificação em duas etapas (TOTP, RFC 6238) do painel.
const MFAKey = "admin.mfa"

const (
	totpStep   = 30 * time.Second
	totpDigits = 6
	totpSkew   = 1 // aceita o código do passo anterior e do seguinte (relógio torto)
)

// MFA é o estado salvo. Pending fica com o segredo até o primeiro código válido.
type MFA struct {
	Secret   string `json:"secret,omitempty"`
	Enabled  bool   `json:"enabled"`
	Pending  string `json:"pending,omitempty"`
	LastStep int64  `json:"last_step,omitempty"` // impede reusar o mesmo código
}

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

func (a *api) mfa() (MFA, error) {
	var m MFA
	_, err := a.Store.GetJSON(MFAKey, &m)
	return m, err
}

// verifyMFA confere o código e grava o passo usado (sem reuso).
func (a *api) verifyMFA(code string) error {
	a.setupMu.Lock()
	defer a.setupMu.Unlock()
	m, err := a.mfa()
	if err != nil {
		return err
	}
	if !m.Enabled {
		return nil
	}
	step := totpCheck(m.Secret, code, timeNow(), m.LastStep)
	if step == 0 {
		return errors.New("código de verificação inválido")
	}
	m.LastStep = step
	return a.Store.SetJSON(MFAKey, m)
}

// mfaSetup gera um segredo novo (ainda não ligado) e devolve a URI para o app.
func (a *api) mfaSetup(w http.ResponseWriter, _ *http.Request) {
	a.setupMu.Lock()
	defer a.setupMu.Unlock()
	m, err := a.mfa()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	raw := make([]byte, 20)
	_, _ = rand.Read(raw)
	m.Pending = b32.EncodeToString(raw)
	if err := a.Store.SetJSON(MFAKey, m); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	label := url.PathEscape("HeimdallDNS:admin")
	uri := fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=HeimdallDNS&digits=6&period=30", label, m.Pending)
	writeJSON(w, http.StatusOK, map[string]string{"secret": m.Pending, "uri": uri})
}

// mfaEnable liga o MFA depois do primeiro código válido do segredo pendente.
func (a *api) mfaEnable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	a.setupMu.Lock()
	defer a.setupMu.Unlock()
	m, err := a.mfa()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if m.Pending == "" {
		writeErr(w, http.StatusConflict, errors.New("gere o segredo primeiro"))
		return
	}
	step := totpCheck(m.Pending, body.Code, timeNow(), 0)
	if step == 0 {
		a.guard.fail(remoteIP(r))
		writeErr(w, http.StatusBadRequest, errors.New("código inválido: confira a hora do celular e tente o código atual"))
		return
	}
	m = MFA{Secret: m.Pending, Enabled: true, LastStep: step}
	if err := a.Store.SetJSON(MFAKey, m); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	a.Logger.Info("verificação em duas etapas ligada", "origem", remoteIP(r))
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": true})
}

// mfaDisable desliga. Pelo painel exige senha e código; com o token da API
// (comando "heimdalldns mfa-off") não exige, para recuperar o acesso.
func (a *api) mfaDisable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if _, cookie := a.authenticate(r); cookie {
		h, err := a.passwordHash()
		if err != nil || bcrypt.CompareHashAndPassword([]byte(h), []byte(body.Password)) != nil {
			a.guard.fail(remoteIP(r))
			writeErr(w, http.StatusForbidden, errors.New("senha incorreta"))
			return
		}
		if err := a.verifyMFA(body.Code); err != nil {
			a.guard.fail(remoteIP(r))
			writeErr(w, http.StatusForbidden, err)
			return
		}
	}
	if err := a.Store.SetJSON(MFAKey, MFA{}); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	a.Logger.Warn("verificação em duas etapas desligada", "origem", remoteIP(r))
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": false})
}

// mfaEnabled diz se o MFA está ligado (para o estado do login e as escritas no AD).
func (a *api) mfaEnabled() bool {
	if a.Store == nil {
		return false
	}
	m, err := a.mfa()
	return err == nil && m.Enabled
}
