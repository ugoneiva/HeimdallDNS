package api

import (
	"net/http"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

// audit registra uma operação administrativa (com sucesso ou erro) no banco
// e, com a exportação ligada, no SIEM.
func (a *api) audit(r *http.Request, action, target string, details map[string]any, opErr error) {
	_, cookie := a.authenticate(r)
	actor := "api"
	if cookie {
		actor = "painel"
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
	a.Logger.Info("operação administrativa", "acao", action, "alvo", target, "ok", entry.OK, "origem", entry.IP, "erro", entry.Error)
}
