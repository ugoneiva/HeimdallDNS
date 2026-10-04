package api

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/dnsname"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

func (a *api) securityEvents(w http.ResponseWriter, r *http.Request) {
	from, _, err := period(r, 7*24*time.Hour)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	q := store.EventQuery{Since: from, Status: r.URL.Query().Get("status"), Limit: intParam(r, "limit", 200)}
	for _, k := range splitParam(r.URL.Query().Get("kind")) {
		q.Kinds = append(q.Kinds, k)
	}
	if ref := r.URL.Query().Get("client"); ref != "" {
		c, err := a.Clients.Find(ref)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		q.ClientID = c.ID()
	}
	evs, err := a.Store.Events(q)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	type out struct {
		store.SecurityEvent
		ClientName string `json:"client_name,omitempty"`
	}
	res := make([]out, len(evs))
	for i, e := range evs {
		res[i] = out{SecurityEvent: e, ClientName: a.clientName(e.ClientID)}
	}
	writeJSON(w, http.StatusOK, res)
}

func (a *api) securitySummary(w http.ResponseWriter, _ *http.Request) {
	open, byKind, err := a.Store.EventCounts(time.Now().Add(-24 * time.Hour))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	total := 0
	for _, n := range open {
		total += n
	}
	writeJSON(w, http.StatusOK, map[string]any{"open": open, "open_total": total, "last_24h": byKind})
}

// setEventStatus: POST /api/security/events/{id}/ack|reopen; id "all" reconhece todos.
func (a *api) setEventStatus(status string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var id int64
		if v := r.PathValue("id"); v != "all" {
			var err error
			if id, err = strconv.ParseInt(v, 10, 64); err != nil || id <= 0 {
				writeErr(w, http.StatusBadRequest, errors.New("id inválido"))
				return
			}
		}
		n, err := a.Store.SetEventStatus(id, status)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if id > 0 && n == 0 {
			writeErr(w, http.StatusNotFound, errors.New("alerta não encontrado"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]int64{"updated": n})
	}
}

func (a *api) getSecuritySettings(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.Security.Settings())
}

func (a *api) putSecuritySettings(w http.ResponseWriter, r *http.Request) {
	s := a.Security.Settings()
	if !readJSON(w, r, &s) {
		return
	}
	if s.AutoIsolate == nil {
		s.AutoIsolate = []string{}
	}
	if s.Ignore == nil {
		s.Ignore = []string{}
	}
	if err := a.Security.SetSettings(s); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, a.Security.Settings())
}

// ignoreDomain acrescenta o domínio registrável à lista que as detecções ignoram.
func (a *api) ignoreDomain(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain string `json:"domain"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(body.Domain), "."))
	if reg, ok := dnsname.Registrable(d); ok {
		d = reg
	}
	if d == "" || !strings.Contains(d, ".") {
		writeErr(w, http.StatusBadRequest, errors.New("domínio inválido"))
		return
	}
	s := a.Security.Settings()
	if !slices.Contains(s.Ignore, d) {
		s.Ignore = append(s.Ignore, d)
	}
	if err := a.Security.SetSettings(s); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, a.Security.Settings())
}
