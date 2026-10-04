// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/ugoneiva/HeimdallDNS/internal/ha"
)

// HA descreve o papel deste nó na alta disponibilidade.
type HA struct {
	Role    string // "", primary ou replica
	Source  *ha.Source
	Replica *ha.Replica
}

func (a *api) haStatus(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{"role": a.HA.Role}
	switch {
	case a.HA.Source != nil:
		out["version"] = a.HA.Source.Version()
		out["replicas"] = a.HA.Source.Replicas()
	case a.HA.Replica != nil:
		out["replica"] = a.HA.Replica.Status()
	}
	writeJSON(w, http.StatusOK, out)
}

// localOnly são operações do próprio nó, liberadas também na réplica.
var localOnly = map[string]bool{"/api/backup": true, "/api/backups": true, "/api/restore": true, "/api/restart": true}

// replicaGuard deixa a réplica só leitura: a configuração vem do principal.
// Reconhecer os alertas do próprio nó e atualizar as listas continuam livres.
func (a *api) replicaGuard(next http.Handler) http.Handler {
	if a.HA.Role != ha.RoleReplica {
		return next
	}
	primary := ""
	if a.HA.Replica != nil {
		primary = a.HA.Replica.Status().PrimaryURL
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead ||
			strings.HasPrefix(r.URL.Path, "/api/security/events/") || r.URL.Path == "/api/lists/refresh" ||
			localOnly[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		writeErr(w, http.StatusConflict, fmt.Errorf("este nó é réplica: altere a configuração no principal (%s)", primary))
	})
}
