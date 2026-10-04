package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/ad"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

// AuditExporter manda as operações administrativas para o SIEM.
type AuditExporter interface {
	Audit(store.AuditEntry)
}

func (a *api) adRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/ad/info", a.adInfo)
	mux.HandleFunc("GET /api/ad/users", a.adUsers)
	mux.HandleFunc("GET /api/ad/users/{sam}", a.adUser)
	mux.HandleFunc("GET /api/ad/groups", a.adGroups)
	mux.HandleFunc("GET /api/ad/groups/{name}", a.adGroup)
	mux.HandleFunc("GET /api/ad/computer", a.adComputer)
	mux.HandleFunc("GET /api/ad/zones", a.adZones)
	mux.HandleFunc("GET /api/ad/zones/{zone}/records", a.adRecords)
	mux.HandleFunc("GET /api/audit", a.auditList)

	mux.HandleFunc("POST /api/ad/users", a.adWrite("ad.user.create", a.adCreateUser))
	mux.HandleFunc("POST /api/ad/users/{sam}/enable", a.adWrite("ad.user.enable", a.adSetEnabled(true)))
	mux.HandleFunc("POST /api/ad/users/{sam}/disable", a.adWrite("ad.user.disable", a.adSetEnabled(false)))
	mux.HandleFunc("POST /api/ad/users/{sam}/unlock", a.adWrite("ad.user.unlock", a.adUnlock))
	mux.HandleFunc("POST /api/ad/users/{sam}/password", a.adWrite("ad.user.password", a.adPassword))
	mux.HandleFunc("DELETE /api/ad/users/{sam}", a.adWrite("ad.user.delete", a.adDeleteUser))
	mux.HandleFunc("POST /api/ad/groups/{name}/members", a.adWrite("ad.group.add_member", a.adMember(true)))
	mux.HandleFunc("DELETE /api/ad/groups/{name}/members/{sam}", a.adWrite("ad.group.remove_member", a.adMember(false)))
	mux.HandleFunc("POST /api/ad/zones/{zone}/records", a.adWrite("ad.dns.add", a.adRecordChange(true)))
	mux.HandleFunc("DELETE /api/ad/zones/{zone}/records", a.adWrite("ad.dns.delete", a.adRecordChange(false)))
}

func (a *api) adInfo(w http.ResponseWriter, r *http.Request) {
	info, err := a.AD.Check(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"info": info, "mfa": a.mfaEnabled(), "can_write": info.Write && a.mfaEnabled(),
		"policy": a.AD.Policy()})
}

func (a *api) adUsers(w http.ResponseWriter, r *http.Request) {
	us, err := a.AD.Users(r.Context(), r.URL.Query().Get("q"), intParam(r, "limit", 200))
	reply502(w, us, err)
}

func (a *api) adUser(w http.ResponseWriter, r *http.Request) {
	u, err := a.AD.User(r.Context(), r.PathValue("sam"))
	reply502(w, u, err)
}

func (a *api) adGroups(w http.ResponseWriter, r *http.Request) {
	gs, err := a.AD.Groups(r.Context(), r.URL.Query().Get("q"), intParam(r, "limit", 200))
	reply502(w, gs, err)
}

func (a *api) adGroup(w http.ResponseWriter, r *http.Request) {
	g, members, err := a.AD.GroupMembers(r.Context(), r.PathValue("name"))
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"group": g, "members": members})
}

func (a *api) adComputer(w http.ResponseWriter, r *http.Request) {
	c, err := a.AD.ComputerByHost(r.Context(), r.URL.Query().Get("host"))
	reply502(w, map[string]any{"computer": c}, err)
}

func (a *api) adZones(w http.ResponseWriter, r *http.Request) {
	zs, err := a.AD.Zones(r.Context())
	reply502(w, zs, err)
}

func (a *api) adRecords(w http.ResponseWriter, r *http.Request) {
	rs, err := a.AD.Records(r.Context(), r.PathValue("zone"))
	reply502(w, rs, err)
}

func reply502(w http.ResponseWriter, v any, err error) {
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (a *api) auditList(w http.ResponseWriter, r *http.Request) {
	from, _, err := period(r, 30*24*time.Hour)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	es, err := a.Store.Audit(from, intParam(r, "limit", 300))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, es)
}

// adOp executa uma alteração e devolve o alvo e detalhes para a auditoria.
type adOp func(r *http.Request) (target string, details map[string]any, result any, err error)

// adWrite aplica as travas (escrita liberada + MFA ligado) e registra tudo
// na auditoria, com sucesso ou erro.
func (a *api) adWrite(action string, op adOp) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, err := a.AD.Check(r.Context())
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		if !info.Write {
			writeErr(w, http.StatusForbidden, ad.ErrWriteDisabled)
			return
		}
		if !a.mfaEnabled() {
			writeErr(w, http.StatusForbidden, errors.New("ligue a verificação em duas etapas do painel antes de alterar o AD"))
			return
		}
		target, details, result, opErr := op(r)
		a.audit(r, action, target, details, opErr)
		if opErr != nil {
			writeErr(w, http.StatusBadRequest, opErr)
			return
		}
		if result == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func decode[T any](r *http.Request) (T, error) {
	var v T
	if r.ContentLength == 0 {
		return v, nil
	}
	err := jsonDecode(r, &v)
	return v, err
}

func (a *api) adCreateUser(r *http.Request) (string, map[string]any, any, error) {
	n, err := decode[ad.NewUser](r)
	if err != nil {
		return "", nil, nil, err
	}
	details := map[string]any{"ou": n.OU, "display_name": n.DisplayName, "enabled": n.Enabled, "must_change": n.MustChange}
	u, err := a.AD.CreateUser(r.Context(), n)
	return n.SAM, details, u, err
}

func (a *api) adSetEnabled(on bool) adOp {
	return func(r *http.Request) (string, map[string]any, any, error) {
		sam := r.PathValue("sam")
		u, err := a.AD.SetEnabled(r.Context(), sam, on)
		return sam, nil, u, err
	}
}

func (a *api) adUnlock(r *http.Request) (string, map[string]any, any, error) {
	sam := r.PathValue("sam")
	u, err := a.AD.Unlock(r.Context(), sam)
	return sam, nil, u, err
}

func (a *api) adPassword(r *http.Request) (string, map[string]any, any, error) {
	sam := r.PathValue("sam")
	body, err := decode[struct {
		Password   string `json:"password"`
		MustChange bool   `json:"must_change"`
	}](r)
	if err != nil {
		return sam, nil, nil, err
	}
	u, err := a.AD.ResetPassword(r.Context(), sam, body.Password, body.MustChange)
	return sam, map[string]any{"must_change": body.MustChange}, u, err // a senha nunca vai para a auditoria
}

func (a *api) adDeleteUser(r *http.Request) (string, map[string]any, any, error) {
	sam := r.PathValue("sam")
	return sam, nil, nil, a.AD.DeleteUser(r.Context(), sam)
}

func (a *api) adMember(add bool) adOp {
	return func(r *http.Request) (string, map[string]any, any, error) {
		group, sam := r.PathValue("name"), r.PathValue("sam")
		if add {
			body, err := decode[struct {
				SAM string `json:"sam"`
			}](r)
			if err != nil {
				return group, nil, nil, err
			}
			sam = strings.TrimSpace(body.SAM)
		}
		g, err := a.AD.SetMembership(r.Context(), group, sam, add)
		return group, map[string]any{"user": sam}, g, err
	}
}

func (a *api) adRecordChange(add bool) adOp {
	return func(r *http.Request) (string, map[string]any, any, error) {
		rc, err := decode[ad.RecordChange](r)
		if err != nil {
			return "", nil, nil, err
		}
		rc.Zone = r.PathValue("zone")
		target := rc.Name + "." + rc.Zone
		details := map[string]any{"type": rc.Type, "data": rc.Data, "ttl": rc.TTL}
		if add {
			err = a.AD.AddRecord(r.Context(), rc)
		} else {
			err = a.AD.DeleteRecord(r.Context(), rc)
		}
		return target, details, nil, err
	}
}
