// Package api expõe o controle do HeimdallDNS por HTTP/JSON. Toda rota exige
// o token (cabeçalho "Authorization: Bearer <token>").
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/cache"
	"github.com/ugoneiva/HeimdallDNS/internal/clients"
	"github.com/ugoneiva/HeimdallDNS/internal/filter"
	"github.com/ugoneiva/HeimdallDNS/internal/server"
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
	Logger   *slog.Logger
}

type api struct{ Deps }

func New(d Deps) http.Handler {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Context == nil {
		d.Context = context.Background()
	}
	a := &api{d}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", a.status)
	mux.HandleFunc("GET /api/clients", a.listClients)
	mux.HandleFunc("GET /api/clients/{ref}", a.getClient)
	mux.HandleFunc("PATCH /api/clients/{ref}", a.patchClient)
	mux.HandleFunc("DELETE /api/clients/{ref}", a.forgetClient)
	mux.HandleFunc("POST /api/clients/{ref}/isolate", a.isolate)
	mux.HandleFunc("POST /api/clients/{ref}/release", a.release)
	mux.HandleFunc("GET /api/services", a.services)
	mux.HandleFunc("GET /api/lists", a.lists)
	mux.HandleFunc("POST /api/lists/refresh", a.refreshLists)
	return a.auth(mux)
}

func (a *api) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || a.Token == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(a.Token)) != 1 {
			writeErr(w, http.StatusUnauthorized, errors.New("token ausente ou inválido"))
			return
		}
		next.ServeHTTP(w, r)
	})
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
