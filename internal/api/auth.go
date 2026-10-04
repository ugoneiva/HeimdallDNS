package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// PasswordKey guarda o hash bcrypt da senha do painel nas configurações.
const PasswordKey = "admin.password"

const (
	sessionCookie  = "heimdall_session"
	sessionTTL     = 7 * 24 * time.Hour
	passwordKey    = PasswordKey
	minPasswordLen = 8
	maxFailures    = 5
	maxLockout     = 15 * time.Minute
)

// bcryptCost é o custo do hash da senha (os testes baixam para o mínimo).
var bcryptCost = 12

// guard limita tentativas de senha por IP: depois de 5 erros, espera 30 s,
// dobrando a cada novo erro até 15 min.
type guard struct {
	mu    sync.Mutex
	fails map[string]*failure
}

type failure struct {
	n     int
	until time.Time
}

func (g *guard) blocked(ip string) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	if f := g.fails[ip]; f != nil {
		return time.Until(f.until)
	}
	return 0
}

func (g *guard) fail(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	f := g.fails[ip]
	if f == nil {
		f = &failure{}
		g.fails[ip] = f
	}
	f.n++
	if f.n >= maxFailures {
		f.until = time.Now().Add(min(30*time.Second<<(f.n-maxFailures), maxLockout))
	}
}

func (g *guard) ok(ip string) {
	g.mu.Lock()
	delete(g.fails, ip)
	g.mu.Unlock()
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// newSetupCode gera um código legível, como "K7Q2-MX9P".
func newSetupCode() string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	s := base32.StdEncoding.EncodeToString(b)
	return s[:4] + "-" + s[4:8]
}

func (a *api) passwordHash() (string, error) {
	var h string
	ok, err := a.Store.GetJSON(passwordKey, &h)
	if err != nil || !ok {
		return "", err
	}
	return h, nil
}

// authenticate aceita o token da API (cabeçalho, ou na URL nas rotas /live) ou
// o cookie de sessão do painel.
func (a *api) authenticate(r *http.Request) (ok, viaCookie bool) {
	tok, bearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !bearer && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/live") {
		tok = r.URL.Query().Get("token")
		bearer = tok != ""
	}
	if bearer {
		return a.Token != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(a.Token)) == 1, false
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" || a.Store == nil {
		return false, false
	}
	valid, err := a.Store.SessionValid(hashToken(c.Value))
	return err == nil && valid, true
}

// sameOrigin barra alterações vindas de outro site usando o cookie do painel.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return r.Header.Get("Sec-Fetch-Site") != "cross-site"
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host == r.Host
}

func (a *api) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok, cookie := a.authenticate(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, errors.New("não autenticado"))
			return
		}
		if cookie && r.Method != http.MethodGet && r.Method != http.MethodHead && !sameOrigin(r) {
			writeErr(w, http.StatusForbidden, errors.New("origem não permitida"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *api) startSession(w http.ResponseWriter) error {
	tok := randomToken(32)
	exp := time.Now().Add(sessionTTL)
	if err := a.Store.CreateSession(hashToken(tok), exp); err != nil {
		return err
	}
	_ = a.Store.DeleteSessions(false) // limpa as vencidas
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/", Expires: exp,
		HttpOnly: true, Secure: a.Secure, SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func (a *api) authState(w http.ResponseWriter, r *http.Request) {
	h, err := a.passwordHash()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	ok, _ := a.authenticate(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"setup_required": h == "",
		"authenticated":  ok,
		"version":        a.Version,
		"mode":           map[bool]string{true: "console", false: "dns"}[a.Console != nil],
		"mfa":            a.mfaEnabled(),
		"wizard":         ok && a.wizardPending(),
	})
}

// setup define a senha na primeira abertura. Exige o código impresso no log
// do serviço, para que ninguém da rede defina a senha antes do dono.
func (a *api) setup(w http.ResponseWriter, r *http.Request) {
	ip := remoteIP(r)
	if d := a.guard.blocked(ip); d > 0 {
		writeErr(w, http.StatusTooManyRequests, errors.New("muitas tentativas; aguarde "+d.Round(time.Second).String()))
		return
	}
	var body struct {
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	a.setupMu.Lock()
	defer a.setupMu.Unlock()
	if h, err := a.passwordHash(); err != nil || h != "" {
		writeErr(w, http.StatusConflict, errors.New("a senha já foi definida"))
		return
	}
	code := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(body.Code), " ", ""))
	if a.setupCode == "" || subtle.ConstantTimeCompare([]byte(code), []byte(a.setupCode)) != 1 {
		a.guard.fail(ip)
		writeErr(w, http.StatusForbidden, errors.New("código de configuração inválido (veja o log do serviço)"))
		return
	}
	if err := a.savePassword(body.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	a.guard.ok(ip)
	a.setupCode = ""
	a.Logger.Info("senha do painel definida", "origem", ip)
	if a.Console == nil {
		_ = a.Store.SetJSON(WizardKey, true) // instalação nova: o painel abre o assistente
	}
	if err := a.startSession(w); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
}

func (a *api) savePassword(pw string) error {
	if len([]rune(pw)) < minPasswordLen {
		return errors.New("a senha precisa de pelo menos 8 caracteres")
	}
	if len(pw) > 72 {
		return errors.New("a senha pode ter no máximo 72 bytes")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	if err != nil {
		return err
	}
	return a.Store.SetJSON(passwordKey, string(h))
}

func (a *api) login(w http.ResponseWriter, r *http.Request) {
	ip := remoteIP(r)
	if d := a.guard.blocked(ip); d > 0 {
		writeErr(w, http.StatusTooManyRequests, errors.New("muitas tentativas; aguarde "+d.Round(time.Second).String()))
		return
	}
	var body struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	h, err := a.passwordHash()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if h == "" {
		writeErr(w, http.StatusConflict, errors.New("defina a senha primeiro"))
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(h), []byte(body.Password)) != nil {
		a.guard.fail(ip)
		a.Logger.Warn("senha errada no painel", "origem", ip)
		writeErr(w, http.StatusUnauthorized, errors.New("senha incorreta"))
		return
	}
	if err := a.verifyMFA(body.Code); err != nil {
		a.guard.fail(ip)
		a.Logger.Warn("código de verificação errado no painel", "origem", ip)
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	a.guard.ok(ip)
	if err := a.startSession(w); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
}

func (a *api) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_ = a.Store.DeleteSession(hashToken(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: a.Secure, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

// changePassword troca a senha. Pelo painel exige a senha atual; com o token
// da API (comando "heimdalldns passwd") não exige, para recuperar o acesso.
func (a *api) changePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Current  string `json:"current"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	_, cookie := a.authenticate(r)
	if cookie {
		h, err := a.passwordHash()
		if err != nil || h == "" || bcrypt.CompareHashAndPassword([]byte(h), []byte(body.Current)) != nil {
			a.guard.fail(remoteIP(r))
			writeErr(w, http.StatusForbidden, errors.New("senha atual incorreta"))
			return
		}
	}
	if err := a.savePassword(body.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	// Derruba todas as sessões; quem trocou pelo painel ganha uma nova.
	if err := a.Store.DeleteSessions(true); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	a.setupMu.Lock()
	a.setupCode = ""
	a.setupMu.Unlock()
	if cookie {
		if err := a.startSession(w); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
	}
	a.Logger.Info("senha do painel alterada", "origem", remoteIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// WizardKey marca que o assistente de primeiro acesso ainda não foi concluído.
const WizardKey = "ui.wizard_pending"

func (a *api) wizardPending() bool {
	var pending bool
	_, _ = a.Store.GetJSON(WizardKey, &pending)
	return pending
}

func (a *api) wizardDone(w http.ResponseWriter, _ *http.Request) {
	if err := a.Store.SetJSON(WizardKey, false); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
