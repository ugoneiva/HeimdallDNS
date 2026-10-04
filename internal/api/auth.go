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
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

// Chaves antigas (antes dos usuários): a senha única e o MFA do painel. São
// migradas para o usuário "admin" na primeira partida da versão nova.
const (
	PasswordKey = "admin.password"
	MFAKey      = "admin.mfa"
)

const (
	sessionCookie  = "heimdall_session"
	sessionTTL     = 7 * 24 * time.Hour
	minPasswordLen = 8
	maxFailures    = 5
	maxLockout     = 15 * time.Minute
	tokenPrefix    = "hdns_"
	sourceLocal    = "local"
	sourceAD       = "ad"
	defaultAdmin   = "admin"
)

// bcryptCost é o custo do hash da senha (os testes baixam para o mínimo).
var bcryptCost = 12

// dummyHash iguala o tempo de resposta quando o usuário não existe (não
// revela quais nomes existem).
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("heimdall-sem-usuario"), bcrypt.MinCost)

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

// sameOrigin barra alterações vindas de outro site usando o cookie do painel.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return r.Header.Get("Sec-Fetch-Site") != "cross-site"
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host == r.Host
}

func hashPassword(pw string) (string, error) {
	if len([]rune(pw)) < minPasswordLen {
		return "", errors.New("a senha precisa de pelo menos 8 caracteres")
	}
	if len(pw) > 72 {
		return "", errors.New("a senha pode ter no máximo 72 bytes")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	return string(h), err
}

var validUsername = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,63}$`)

func cleanUsername(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !validUsername.MatchString(s) {
		return "", errors.New("nome de usuário inválido: use letras, números, ponto, hífen, _ ou @ (até 64)")
	}
	return s, nil
}

// migrateLegacy transforma a senha única antiga no usuário "admin".
func (a *api) migrateLegacy() {
	if a.Store == nil {
		return
	}
	if n, err := a.Store.CountUsers(); err != nil || n > 0 {
		return
	}
	var hash string
	if ok, err := a.Store.GetJSON(PasswordKey, &hash); err != nil || !ok || hash == "" {
		return
	}
	var m store.MFA
	_, _ = a.Store.GetJSON(MFAKey, &m)
	u := store.User{Username: defaultAdmin, Role: store.RoleAdmin, Source: sourceLocal, PasswordHash: hash, MFA: m}
	if err := a.Store.SaveUser(&u); err != nil {
		a.Logger.Error("falha ao migrar a senha do painel para o usuário admin", "erro", err)
		return
	}
	_ = a.Store.SetJSON(PasswordKey, "")
	_ = a.Store.SetJSON(MFAKey, store.MFA{})
	a.Logger.Info("senha do painel migrada para o usuário admin")
}

func (a *api) setupRequired() bool {
	n, err := a.Store.CountUsers()
	return err == nil && n == 0
}

func (a *api) startSession(w http.ResponseWriter, userID int64) error {
	tok := randomToken(32)
	exp := time.Now().Add(sessionTTL)
	if err := a.Store.CreateSession(hashToken(tok), userID, exp); err != nil {
		return err
	}
	_ = a.Store.DeleteSessions(false) // limpa as vencidas
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/", Expires: exp,
		HttpOnly: true, Secure: a.Secure, SameSite: http.SameSiteStrictMode,
	})
	return nil
}

// userView é o que o painel sabe da conta logada (nunca hash nem segredo).
type userView struct {
	ID          int64     `json:"id"`
	Username    string    `json:"username"`
	Display     string    `json:"display"`
	Role        string    `json:"role"`
	Source      string    `json:"source"`
	MFA         bool      `json:"mfa"`
	MFARequired bool      `json:"mfa_required"`
	Disabled    bool      `json:"disabled"`
	Created     time.Time `json:"created"`
	LastLogin   time.Time `json:"last_login"`
}

func (a *api) view(u *store.User) userView {
	return userView{ID: u.ID, Username: u.Username, Display: u.Display, Role: u.Role, Source: u.Source, MFA: u.MFA.Enabled,
		MFARequired: a.mustEnrollMFA(u), Disabled: u.Disabled, Created: u.Created, LastLogin: u.LastLogin}
}

func (a *api) authState(w http.ResponseWriter, r *http.Request) {
	p := a.authenticate(r)
	out := map[string]any{
		"setup_required": a.setupRequired(),
		"authenticated":  p != nil,
		"version":        a.Version,
		"mode":           map[bool]string{true: "console", false: "dns"}[a.Console != nil],
		"ad_login":       a.AD != nil && a.ADLogin.Enabled,
	}
	if p != nil {
		out["role"] = p.Role
		if p.User != nil {
			out["user"] = a.view(p.User)
		}
		out["wizard"] = p.Role == store.RoleAdmin && a.wizardPending()
	}
	writeJSON(w, http.StatusOK, out)
}

// setup cria o primeiro administrador. Exige o código impresso no log do
// serviço, para que ninguém da rede tome o painel antes do dono.
func (a *api) setup(w http.ResponseWriter, r *http.Request) {
	ip := remoteIP(r)
	if d := a.guard.blocked(ip); d > 0 {
		writeErr(w, http.StatusTooManyRequests, errors.New("muitas tentativas; aguarde "+d.Round(time.Second).String()))
		return
	}
	var body struct {
		Code     string `json:"code"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	a.setupMu.Lock()
	defer a.setupMu.Unlock()
	if !a.setupRequired() {
		writeErr(w, http.StatusConflict, errors.New("o painel já foi configurado"))
		return
	}
	code := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(body.Code), " ", ""))
	if a.setupCode == "" || subtle.ConstantTimeCompare([]byte(code), []byte(a.setupCode)) != 1 {
		a.guard.fail(ip)
		writeErr(w, http.StatusForbidden, errors.New("código de configuração inválido (veja o log do serviço)"))
		return
	}
	if body.Username == "" {
		body.Username = defaultAdmin
	}
	name, err := cleanUsername(body.Username)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	hash, err := hashPassword(body.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	u := store.User{Username: name, Role: store.RoleAdmin, Source: sourceLocal, PasswordHash: hash, LastLogin: time.Now()}
	if err := a.Store.SaveUser(&u); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	a.guard.ok(ip)
	a.setupCode = ""
	a.Logger.Info("administrador do painel criado", "usuario", name, "origem", ip)
	if a.Console == nil {
		_ = a.Store.SetJSON(WizardKey, true) // instalação nova: o painel abre o assistente
	}
	if err := a.startSession(w, u.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	a.auditAs(r, name, "auth.setup", name, nil, nil)
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
}

var errBadLogin = errors.New("usuário ou senha incorretos")

func (a *api) login(w http.ResponseWriter, r *http.Request) {
	ip := remoteIP(r)
	if d := a.guard.blocked(ip); d > 0 {
		writeErr(w, http.StatusTooManyRequests, errors.New("muitas tentativas; aguarde "+d.Round(time.Second).String()))
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if a.setupRequired() {
		writeErr(w, http.StatusConflict, errors.New("defina o administrador primeiro"))
		return
	}
	name := strings.TrimSpace(body.Username)
	if name == "" {
		name = defaultAdmin
	}
	fail := func(err error) {
		a.guard.fail(ip)
		a.Logger.Warn("login recusado no painel", "usuario", name, "origem", ip, "motivo", err)
		a.auditAs(r, name, "auth.login", name, nil, err)
		writeErr(w, http.StatusUnauthorized, err)
	}

	u, err := a.Store.UserByName(name)
	switch {
	case err == nil && u.Source == sourceLocal:
		if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(body.Password)) != nil {
			fail(errBadLogin)
			return
		}
	case (err == nil && u.Source == sourceAD) || (errors.Is(err, store.ErrNotFound) && a.adLoginOn()):
		au, aerr := a.adAuthenticate(r, name, body.Password)
		if aerr != nil {
			fail(aerr)
			return
		}
		u = *au
	case errors.Is(err, store.ErrNotFound):
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(body.Password))
		fail(errBadLogin)
		return
	default:
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if u.Disabled {
		fail(errors.New("conta desativada"))
		return
	}
	if u.MFA.Enabled {
		if strings.TrimSpace(body.Code) == "" {
			// Senha certa: o painel pede o código (não conta como erro).
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "informe o código do aplicativo autenticador", "mfa_required": true})
			return
		}
		if err := a.verifyUserMFA(&u, body.Code); err != nil {
			fail(err)
			return
		}
	}
	a.guard.ok(ip)
	u.LastLogin = time.Now()
	if err := a.Store.SaveUser(&u); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if err := a.startSession(w, u.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	a.auditAs(r, u.Username, "auth.login", u.Username, map[string]any{"source": u.Source, "role": u.Role}, nil)
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

// targetUser escolhe a conta das rotas /api/auth/: a da sessão, ou (só com o
// token raiz, usado por "heimdalldns passwd" e "mfa-off") a informada.
func (a *api) targetUser(r *http.Request, username string) (*store.User, *principal, error) {
	p := a.who(r)
	switch {
	case p == nil:
		return nil, nil, errors.New("não autenticado")
	case p.Kind == kindSession:
		return p.User, p, nil
	case p.Kind == kindRoot:
		if username == "" {
			username = defaultAdmin
		}
		u, err := a.Store.UserByName(username)
		if err != nil {
			return nil, p, errors.New("usuário " + username + " não encontrado")
		}
		return &u, p, nil
	}
	return nil, p, errors.New("tokens de API não alteram contas")
}

// changePassword troca a senha da própria conta (exige a atual). Com o token
// raiz ("heimdalldns passwd"), redefine sem a atual para recuperar o acesso.
func (a *api) changePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Current  string `json:"current"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	u, p, err := a.targetUser(r, body.Username)
	if err != nil {
		writeErr(w, http.StatusForbidden, err)
		return
	}
	if u.Source != sourceLocal {
		writeErr(w, http.StatusBadRequest, errors.New("a senha desta conta é a do Active Directory"))
		return
	}
	if p.Kind == kindSession && bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(body.Current)) != nil {
		a.guard.fail(remoteIP(r))
		a.audit(r, "auth.password", u.Username, nil, errors.New("senha atual incorreta"))
		writeErr(w, http.StatusForbidden, errors.New("senha atual incorreta"))
		return
	}
	hash, err := hashPassword(body.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	u.PasswordHash = hash
	if err := a.Store.SaveUser(u); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	// Derruba as sessões da conta; quem trocou pelo painel ganha uma nova.
	if err := a.Store.DeleteUserSessions(u.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if p.Kind == kindSession {
		if err := a.startSession(w, u.ID); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
	}
	a.audit(r, "auth.password", u.Username, nil, nil)
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
