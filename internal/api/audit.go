// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"net/http"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

// audit registra uma operação administrativa (com sucesso ou erro) no banco
// e, com a exportação ligada, no SIEM.
func (a *api) audit(r *http.Request, action, target string, details map[string]any, opErr error) {
	if done, ok := r.Context().Value(auditedKey).(*bool); ok {
		*done = true // o handler registrou: a auditoria genérica não repete
	}
	actor := "anônimo"
	if p := a.who(r); p != nil {
		actor = p.Actor()
	}
	a.auditAs(r, actor, action, target, details, opErr)
}

// auditAs registra com um autor explícito (ex.: tentativa de login).
func (a *api) auditAs(r *http.Request, actor, action, target string, details map[string]any, opErr error) {
	if a.Store == nil {
		return
	}
	entry := store.AuditEntry{Time: time.Now(), Actor: actor, IP: remoteIP(r), Action: action, Target: target,
		Details: details, OK: opErr == nil}
	if opErr != nil {
		entry.Error = opErr.Error()
	}
	if err := a.Store.InsertAudit(&entry); err != nil {
		a.Logger.Error("falha ao gravar auditoria", "acao", action, "erro", err)
	}
	if a.Audit != nil {
		a.Audit.Audit(entry)
	}
	a.Logger.Info("operação administrativa", "acao", action, "alvo", target, "autor", actor, "ok", entry.OK, "origem", entry.IP, "erro", entry.Error)
}
