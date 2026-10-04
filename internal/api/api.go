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
	"strings"
	"sync"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/cache"
	"github.com/ugoneiva/HeimdallDNS/internal/clients"
	"github.com/ugoneiva/HeimdallDNS/internal/filter"
	"github.com/ugoneiva/HeimdallDNS/internal/querylog"
	"github.com/ugoneiva/HeimdallDNS/internal/server"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
	"github.com/ugoneiva/HeimdallDNS/internal/upstream"
)

type Deps struct {
	Context  context.Context // vida do serviço (atualizações em segundo plano)
	Token    string
	Version  string
	Started  time.Time
	Server   *server.Server
	Cache    *cache.Cache
	Upstream *upstream.Group
	Filter   *filter.Manager
	Clients  *clients.Registry
	Store    *store.Store
	Log      *querylog.Recorder
	UI       fs.FS // arquivos do painel; nil = sem painel
	Secure   bool  // HTTPS: o cookie de sessão leva a marca Secure
	Logger   *slog.Logger
}

type api struct {
	Deps
	guard     guard
	setupMu   sync.Mutex
	setupCode string // código para definir a senha na primeira abertura
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
		if h, err := a.passwordHash(); err == nil && h == "" {
			a.setupCode = newSetupCode()
			a.Logger.Warn("painel sem senha: abra o painel e informe este código para definir a senha",
				"codigo", a.setupCode)
		}
	}

	api := http.NewServeMux()
	api.HandleFunc("GET /api/status", a.status)
	api.HandleFunc("GET /api/clients", a.listClients)
	api.HandleFunc("GET /api/clients/{ref}", a.getClient)
	api.HandleFunc("PATCH /api/clients/{ref}", a.patchClient)
	api.HandleFunc("DELETE /api/clients/{ref}", a.forgetClient)
	api.HandleFunc("POST /api/clients/{ref}/isolate", a.isolate)
	api.HandleFunc("POST /api/clients/{ref}/release", a.release)
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

	root := http.NewServeMux()
	root.HandleFunc("GET /api/auth/state", a.authState)
	root.HandleFunc("POST /api/auth/setup", a.setup)
	root.HandleFunc("POST /api/auth/login", a.login)
	root.HandleFunc("POST /api/auth/logout", a.logout)
	root.Handle("/api/", a.requireAuth(api))
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
