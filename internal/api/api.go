// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

// Package api expõe o controle do HeimdallDNS por HTTP/JSON e serve o painel.
// As rotas /api exigem o token (cabeçalho "Authorization: Bearer <token>") ou
// a sessão do painel; só as de login e o próprio painel são públicos.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/ad"
	"github.com/ugoneiva/HeimdallDNS/internal/cache"
	"github.com/ugoneiva/HeimdallDNS/internal/certs"
	"github.com/ugoneiva/HeimdallDNS/internal/clients"
	"github.com/ugoneiva/HeimdallDNS/internal/console"
	"github.com/ugoneiva/HeimdallDNS/internal/dhcp"
	"github.com/ugoneiva/HeimdallDNS/internal/filter"
	"github.com/ugoneiva/HeimdallDNS/internal/forward"
	"github.com/ugoneiva/HeimdallDNS/internal/notify"
	"github.com/ugoneiva/HeimdallDNS/internal/querylog"
	"github.com/ugoneiva/HeimdallDNS/internal/report"
	"github.com/ugoneiva/HeimdallDNS/internal/security"
	"github.com/ugoneiva/HeimdallDNS/internal/server"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
	"github.com/ugoneiva/HeimdallDNS/internal/topology"
	"github.com/ugoneiva/HeimdallDNS/internal/upstream"
	"github.com/ugoneiva/HeimdallDNS/internal/webfilter"
)

type Deps struct {
	Context   context.Context // vida do serviço (atualizações em segundo plano)
	Token     string
	Version   string
	Started   time.Time
	Server    *server.Server
	Cache     *cache.Cache
	Upstream  *upstream.Group
	Filter    *filter.Manager
	Clients   *clients.Registry
	Store     *store.Store
	Log       *querylog.Recorder
	Security  *security.Manager
	NRD       NRDInfo      // idade dos domínios (nil = sem checagem)
	DHCP      *dhcp.Server // nil = DHCP desligado
	HA        HA
	Console   *console.Console   // modo console (MSP): só as rotas do console
	AD        *ad.Client         // nil = sem integração com o Active Directory
	ADLogin   ADLogin            // entrada no painel com as contas do AD
	WebFilter *webfilter.Manager // nil = sem filtro web
	Forward   *forward.Manager   // encaminhamento condicional (nil = indisponível)
	Notify    *notify.Manager    // notificações (Telegram, Teams, e-mail, webhook)
	Reports   *report.Scheduler  // relatório periódico em PDF
	Certs     *certs.Manager     // certificado HTTPS pelo Let's Encrypt
	DNSTLS    bool               // DoT ou DoH configurados
	Audit     AuditExporter      // operações administrativas para o SIEM (opcional)
	Encrypted Encrypted
	// Backup e restauração (DataDir vazio = sem as rotas).
	DataDir    string
	ConfigPath string
	BackupDir  string
	BackupKeep int
	BackupAuto bool
	Restart    func() // reinicia o serviço; nil = não suportado
	// Valores do arquivo de configuração (o painel pode sobrepor).
	LocalConfig    map[string][]netip.Addr
	UpstreamConfig upstream.Options
	UI             fs.FS // arquivos do painel; nil = sem painel
	Secure         bool  // HTTPS: o cookie de sessão leva a marca Secure
	Logger         *slog.Logger
}

// NRDInfo é o que a API usa do verificador de domínios recém-registrados.
type NRDInfo interface {
	Age(name string) (time.Duration, bool)
	Block(name string) (rule string, block bool)
}

type api struct {
	Deps
	guard   guard
	setupMu sync.Mutex
	// desafios das passkeys entre o começo e o fim
	ceremonies ceremonies
	setupCode  string // código para definir a senha na primeira abertura
	imports    importer
}

func New(d Deps) http.Handler {
	_, h := build(d)
	return h
}

func build(d Deps) (*api, http.Handler) {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Context == nil {
		d.Context = context.Background()
	}
	a := &api{Deps: d, guard: guard{fails: map[string]*failure{}}}
	if d.Store != nil {
		a.migrateLegacy()
		if a.setupRequired() {
			a.setupCode = newSetupCode()
			a.Logger.Warn("painel sem senha: abra o painel e informe este código para definir a senha",
				"codigo", a.setupCode)
		}
	}

	if d.Console != nil {
		return a, a.consoleRoutes()
	}

	api := http.NewServeMux()
	api.HandleFunc("GET /api/status", a.status)
	api.HandleFunc("GET /api/clients", a.listClients)
	api.HandleFunc("GET /api/clients/{ref}", a.getClient)
	api.HandleFunc("PATCH /api/clients/{ref}", a.patchClient)
	api.HandleFunc("DELETE /api/clients/{ref}", a.forgetClient)
	api.HandleFunc("POST /api/clients/{ref}/isolate", a.isolate)
	api.HandleFunc("POST /api/clients/{ref}/release", a.release)
	api.HandleFunc("GET /api/clients/{ref}/access", a.getAccess)
	api.HandleFunc("POST /api/clients/{ref}/token", a.newToken)
	api.HandleFunc("DELETE /api/clients/{ref}/token", a.revokeToken)
	api.HandleFunc("GET /api/clients/{ref}/mobileconfig", a.mobileconfig)
	api.HandleFunc("GET /api/encrypted", a.encryptedInfo)
	api.HandleFunc("GET /api/ha", a.haStatus)
	if d.AD != nil {
		a.adRoutes(api)
	}
	a.localRoutes(api)
	a.forwardRoutes(api)
	a.notifyRoutes(api)
	a.reportRoutes(api)
	a.certRoutes(api)
	a.userRoutes(api)
	api.HandleFunc("POST /api/wizard/done", a.wizardDone)
	api.HandleFunc("GET /api/groups", a.listGroups)
	api.HandleFunc("GET /api/topology", a.topology)
	if d.WebFilter != nil {
		api.HandleFunc("GET /api/webfilter", a.getWebFilter)
		api.HandleFunc("PUT /api/webfilter", a.putWebFilter)
		api.HandleFunc("POST /api/webfilter/refresh", a.refreshWebFilter)
	}
	api.HandleFunc("PUT /api/groups", a.putGroups)
	if d.DataDir != "" {
		a.backupRoutes(api)
		a.importRoutes(api)
	}
	api.HandleFunc("GET /api/dhcp", a.dhcpState)
	api.HandleFunc("POST /api/dhcp/reservations", a.dhcpReserve)
	api.HandleFunc("DELETE /api/dhcp/reservations/{mac}", a.dhcpUnreserve)
	api.HandleFunc("GET /api/services", a.services)
	api.HandleFunc("GET /api/lists", a.lists)
	api.HandleFunc("POST /api/lists", a.addList)
	api.HandleFunc("PATCH /api/lists/{id}", a.patchList)
	api.HandleFunc("DELETE /api/lists/{id}", a.deleteList)
	api.HandleFunc("POST /api/lists/refresh", a.refreshLists)
	api.HandleFunc("GET /api/rules", a.getRules)
	api.HandleFunc("PUT /api/rules", a.putRules)
	api.HandleFunc("POST /api/rules/quick", a.quickRule)
	api.HandleFunc("GET /api/filter/test", a.testDomain)
	api.HandleFunc("GET /api/queries", a.queries)
	api.HandleFunc("GET /api/queries/live", a.liveQueries)
	api.HandleFunc("GET /api/stats/summary", a.summary)
	api.HandleFunc("GET /api/stats/timeseries", a.timeseries)
	api.HandleFunc("GET /api/stats/top", a.top)
	api.HandleFunc("GET /api/stats/realtime", a.realtime)
	api.HandleFunc("GET /api/stats/live", a.liveStats)
	api.HandleFunc("POST /api/auth/password", a.changePassword)
	api.HandleFunc("POST /api/auth/mfa/setup", a.mfaSetup)
	api.HandleFunc("POST /api/auth/mfa/enable", a.mfaEnable)
	api.HandleFunc("POST /api/auth/mfa/disable", a.mfaDisable)
	if d.Security != nil {
		api.HandleFunc("GET /api/security/events", a.securityEvents)
		api.HandleFunc("GET /api/security/summary", a.securitySummary)
		api.HandleFunc("POST /api/security/events/{id}/ack", a.setEventStatus("ack"))
		api.HandleFunc("POST /api/security/events/{id}/reopen", a.setEventStatus("open"))
		api.HandleFunc("GET /api/security/settings", a.getSecuritySettings)
		api.HandleFunc("PUT /api/security/settings", a.putSecuritySettings)
		api.HandleFunc("POST /api/security/ignore", a.ignoreDomain)
	}

	root := http.NewServeMux()
	root.HandleFunc("GET /api/auth/state", a.authState)
	root.HandleFunc("POST /api/auth/setup", a.setup)
	root.HandleFunc("POST /api/auth/login", a.login)
	root.HandleFunc("POST /api/auth/logout", a.logout)
	a.accountRoutes(api, root)
	if d.HA.Source != nil {
		root.Handle("GET /api/sync/snapshot", d.HA.Source) // token próprio de sincronização
	}
	root.Handle("/api/", a.requireAuth(a.replicaGuard(a.auditWrites(api))))
	if d.UI != nil {
		root.Handle("/", uiHandler(d.UI))
	}
	return a, root
}

func (a *api) status(w http.ResponseWriter, _ *http.Request) {
	block, allow := a.Filter.Matcher().Rules()
	writeJSON(w, http.StatusOK, map[string]any{
		"version":   a.Version,
		"uptime_s":  int(time.Since(a.Started).Seconds()),
		"queries":   a.Server.Counters(),
		"cache":     a.Cache.Stats(),
		"upstreams": a.Upstream.Stats(),
		"rules":     map[string]int{"block": block, "allow": allow},
		"clients":   len(a.Clients.List()),
		"history":   historyStatus(a.Log),
	})
}

func (a *api) listClients(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.Clients.List())
}

func (a *api) find(w http.ResponseWriter, r *http.Request) *clients.Client {
	c, err := a.Clients.Find(r.PathValue("ref"))
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, clients.ErrNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, err)
		return nil
	}
	return c
}

func (a *api) getClient(w http.ResponseWriter, r *http.Request) {
	if c := a.find(w, r); c != nil {
		writeJSON(w, http.StatusOK, c.View())
	}
}

// patchClient altera só os campos enviados.
func (a *api) patchClient(w http.ResponseWriter, r *http.Request) {
	c := a.find(w, r)
	if c == nil {
		return
	}
	var body struct {
		Name            *string   `json:"name"`
		Allow           *[]string `json:"allow"`
		Deny            *[]string `json:"deny"`
		SkipGlobalLists *bool     `json:"skip_global_lists"`
		Group           *string   `json:"group"`
		Kind            *string   `json:"kind"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	err := a.Clients.Update(c, func(s *clients.Settings) error {
		if body.Name != nil {
			s.Name = strings.TrimSpace(*body.Name)
		}
		if body.Allow != nil {
			s.Allow = clean(*body.Allow)
		}
		if body.Deny != nil {
			s.Deny = clean(*body.Deny)
		}
		if body.SkipGlobalLists != nil {
			s.SkipGlobalLists = *body.SkipGlobalLists
		}
		if body.Group != nil {
			if *body.Group != "" && !slices.ContainsFunc(a.Clients.Groups(), func(g clients.Group) bool { return g.ID == *body.Group }) {
				return errors.New("grupo não encontrado")
			}
			s.Group = *body.Group
		}
		if body.Kind != nil {
			if !topology.ValidKind(*body.Kind) {
				return errors.New("tipo de aparelho inválido")
			}
			s.Kind = *body.Kind
		}
		return nil
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, c.View())
}

func (a *api) isolate(w http.ResponseWriter, r *http.Request) {
	c := a.find(w, r)
	if c == nil {
		return
	}
	var body struct {
		Mode       string   `json:"mode"`
		Reason     string   `json:"reason"`
		Exceptions []string `json:"exceptions"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if err := a.Clients.Isolate(c, body.Mode, strings.TrimSpace(body.Reason), clean(body.Exceptions)); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, c.View())
}

func (a *api) release(w http.ResponseWriter, r *http.Request) {
	c := a.find(w, r)
	if c == nil {
		return
	}
	if err := a.Clients.Release(c); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, c.View())
}

func (a *api) forgetClient(w http.ResponseWriter, r *http.Request) {
	c := a.find(w, r)
	if c == nil {
		return
	}
	if err := a.Clients.Forget(c); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) services(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"groups": filter.ServiceGroups(), "services": filter.Services})
}

func (a *api) lists(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.Filter.Status())
}

func (a *api) refreshLists(w http.ResponseWriter, _ *http.Request) {
	go a.Filter.Refresh(a.Context)
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "atualizando"})
}

func clean(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.ContentLength == 0 {
		return true // corpo vazio = nenhum campo
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func historyStatus(l *querylog.Recorder) map[string]uint64 {
	if l == nil {
		return nil
	}
	ev, rows := l.Dropped()
	return map[string]uint64{"dropped_events": ev, "dropped_rows": rows}
}

// timeNow existe para os testes poderem trocar o relógio.
var timeNow = time.Now

// consoleRoutes monta o servidor no modo console: login, rotas do console e painel.
func (a *api) consoleRoutes() http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("GET /api/console/tenants", a.consoleTenants)
	api.HandleFunc("POST /api/console/tenants", a.consoleAdd)
	api.HandleFunc("DELETE /api/console/tenants/{id}", a.consoleRemove)
	api.HandleFunc("GET /api/console/alerts", a.consoleAlerts)
	api.HandleFunc("POST /api/console/tenants/{id}/ack/{event}", a.consoleAck)
	api.HandleFunc("GET /api/console/templates", a.consoleTemplates)
	api.HandleFunc("PUT /api/console/templates", a.consolePutTemplates)
	api.HandleFunc("POST /api/console/templates/{id}/apply", a.consoleApply)
	api.HandleFunc("POST /api/auth/password", a.changePassword)
	api.HandleFunc("POST /api/auth/mfa/setup", a.mfaSetup)
	api.HandleFunc("POST /api/auth/mfa/enable", a.mfaEnable)
	api.HandleFunc("POST /api/auth/mfa/disable", a.mfaDisable)
	a.userRoutes(api)
	root := http.NewServeMux()
	root.HandleFunc("GET /api/auth/state", a.authState)
	root.HandleFunc("POST /api/auth/setup", a.setup)
	root.HandleFunc("POST /api/auth/login", a.login)
	root.HandleFunc("POST /api/auth/logout", a.logout)
	a.accountRoutes(api, root)
	root.Handle("/api/", a.requireAuth(a.auditWrites(api)))
	if a.UI != nil {
		root.Handle("/", uiHandler(a.UI))
	}
	return root
}

// jsonDecode lê o corpo JSON recusando campos desconhecidos.
func jsonDecode(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
