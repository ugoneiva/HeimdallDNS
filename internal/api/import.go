// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/clients"
	"github.com/ugoneiva/HeimdallDNS/internal/dhcp"
	"github.com/ugoneiva/HeimdallDNS/internal/filter"
	"github.com/ugoneiva/HeimdallDNS/internal/pihole"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
	"github.com/ugoneiva/HeimdallDNS/internal/upstream"
)

// importTTL é quanto tempo uma prévia fica guardada esperando a confirmação.
const importTTL = 15 * time.Minute

type pendingImport struct {
	export  *pihole.Export
	created time.Time
}

type importer struct {
	mu      sync.Mutex
	pending map[string]pendingImport
}

func (a *api) importRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/import/pihole", a.importPreview)
	mux.HandleFunc("POST /api/import/pihole/{id}/apply", a.importApply)
}

// importPreview lê o arquivo do Teleporter e mostra o que entraria.
func (a *api) importPreview(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 512<<20)
	mr, err := r.MultipartReader()
	if err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("envie o arquivo como multipart/form-data (campo file)"))
		return
	}
	var e *pihole.Export
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if p.FormName() == "file" {
			if e, err = pihole.Parse(p, a.DataDir); err != nil {
				writeErr(w, http.StatusBadRequest, err)
				return
			}
		}
		p.Close()
	}
	if e == nil {
		writeErr(w, http.StatusBadRequest, errors.New("nenhum arquivo enviado"))
		return
	}
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	a.imports.mu.Lock()
	if a.imports.pending == nil {
		a.imports.pending = map[string]pendingImport{}
	}
	for k, v := range a.imports.pending {
		if time.Since(v.created) > importTTL {
			delete(a.imports.pending, k)
		}
	}
	a.imports.pending[id] = pendingImport{export: e, created: time.Now()}
	a.imports.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "export": e, "plan": a.importPlan(e)})
}

// importPlan conta o que é novo em relação ao que já existe aqui.
func (a *api) importPlan(e *pihole.Export) map[string]int {
	have := map[string]bool{}
	for _, l := range a.Filter.Status() {
		have[l.URL] = true
	}
	newLists, allowLists := 0, 0
	for _, l := range e.Lists {
		switch {
		case l.Allow:
			allowLists++
		case !have[l.URL]:
			newLists++
		}
	}
	_, _, allow, deny := a.Filter.UserRules()
	countNew := func(in, cur []string) int {
		n := 0
		for _, r := range in {
			if !slices.Contains(cur, r) {
				n++
			}
		}
		return n
	}
	var recs []store.LocalRecord
	_, _ = a.Store.GetJSON(LocalKey, &recs)
	newHosts := 0
	for _, h := range e.Hosts {
		if !slices.Contains(recs, store.LocalRecord{Name: h.Name, Type: h.Type, Value: h.Value}) {
			newHosts++
		}
	}
	found := 0
	for _, c := range e.Clients {
		if _, err := a.Clients.Find(c.Ref); err == nil {
			found++
		}
	}
	return map[string]int{
		"lists": newLists, "allow_lists": allowLists, "deny": countNew(e.Deny, deny), "allow": countNew(e.Allow, allow),
		"hosts": newHosts, "reservations": len(e.Reservations), "upstreams": len(e.Upstreams),
		"clients": len(e.Clients), "clients_found": found, "groups": e.Groups, "skipped": len(e.Skipped),
	}
}

// importApply aplica as partes escolhidas da prévia.
func (a *api) importApply(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Lists        bool `json:"lists"`
		Rules        bool `json:"rules"`
		Hosts        bool `json:"hosts"`
		Reservations bool `json:"reservations"`
		Upstreams    bool `json:"upstreams"`
		Clients      bool `json:"clients"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	a.imports.mu.Lock()
	p, ok := a.imports.pending[id]
	delete(a.imports.pending, id)
	a.imports.mu.Unlock()
	if !ok || time.Since(p.created) > importTTL {
		writeErr(w, http.StatusNotFound, errors.New("prévia expirada: envie o arquivo de novo"))
		return
	}
	e := p.export
	res := map[string]int{}
	var notes []string
	fail := func(err error) {
		a.audit(r, "import.pihole", e.Version, map[string]any{"result": res}, err)
		writeErr(w, http.StatusInternalServerError, err)
	}

	if body.Lists {
		have := map[string]bool{}
		for _, l := range a.Filter.Status() {
			have[l.URL] = true
		}
		for _, l := range e.Lists {
			if l.Allow || have[l.URL] {
				continue
			}
			if err := validListURL(l.URL); err != nil {
				notes = append(notes, "lista ignorada ("+err.Error()+"): "+l.URL)
				continue
			}
			name := strings.TrimSpace(l.Name)
			if name == "" {
				name = l.URL
			}
			id, err := a.Store.AddList(name, l.URL, "")
			if err != nil {
				fail(err)
				return
			}
			if !l.Enabled {
				off := false
				if _, err := a.Store.UpdateList(id, nil, &off, nil); err != nil {
					fail(err)
					return
				}
			}
			have[l.URL] = true
			res["lists"]++
		}
	}
	if body.Rules {
		_, _, allow, deny := a.Filter.UserRules()
		merge := func(cur, add []string, isAllow bool) []string {
			out := slices.Clone(cur)
			for _, rule := range add {
				if slices.Contains(out, rule) {
					continue
				}
				var bad []string
				if isAllow {
					_, bad = filter.CompileUserRules([]string{rule}, nil)
				} else {
					_, bad = filter.CompileUserRules(nil, []string{rule})
				}
				if len(bad) > 0 {
					notes = append(notes, "regra não entendida: "+rule)
					continue
				}
				out = append(out, rule)
				res["rules"]++
			}
			return out
		}
		allow, deny = merge(allow, e.Allow, true), merge(deny, e.Deny, false)
		if err := a.Store.SetJSON(allowKey, allow); err != nil {
			fail(err)
			return
		}
		if err := a.Store.SetJSON(denyKey, deny); err != nil {
			fail(err)
			return
		}
	}
	if body.Lists || body.Rules {
		if err := a.reloadFilter(); err != nil {
			fail(err)
			return
		}
	}
	if body.Hosts {
		var recs []store.LocalRecord
		if _, err := a.Store.GetJSON(LocalKey, &recs); err != nil {
			fail(err)
			return
		}
		for _, h := range e.Hosts {
			rec := store.LocalRecord{Name: h.Name, Type: h.Type, Value: h.Value}
			if slices.Contains(recs, rec) {
				continue
			}
			// Um por vez: um conflito (ex.: CNAME num nome com IP) só pula aquele.
			if _, err := BuildLocal(a.LocalConfig, append(slices.Clone(recs), rec)); err != nil {
				notes = append(notes, "registro local ignorado: "+err.Error())
				continue
			}
			recs = append(recs, rec)
			res["hosts"]++
		}
		if err := a.saveLocal(recs); err != nil {
			fail(err)
			return
		}
	}
	if body.Reservations {
		for _, rv := range e.Reservations {
			ip, _ := netip.ParseAddr(rv.IP)
			r := dhcp.Reservation{MAC: rv.MAC, IP: ip, Name: rv.Name}
			var err error
			if a.DHCP != nil {
				err = a.DHCP.Reserve(r)
			} else {
				err = a.Store.SaveDHCPReservation(r)
			}
			if err != nil {
				notes = append(notes, "reserva ignorada ("+rv.MAC+"): "+err.Error())
				continue
			}
			res["reservations"]++
		}
	}
	if body.Upstreams && len(e.Upstreams) > 0 {
		u := store.UpstreamSettings{Servers: e.Upstreams, Mode: upstream.ModeFastest}
		if err := upstream.Validate(u.Servers, u.Mode); err != nil {
			notes = append(notes, "upstreams do Pi-hole não aplicados: "+err.Error())
		} else if err := a.Upstream.Reconfigure(upstream.Options{Servers: u.Servers, Mode: u.Mode}); err != nil {
			notes = append(notes, "upstreams do Pi-hole não aplicados: "+err.Error())
		} else {
			if err := a.Store.SetJSON(UpstreamKey, u); err != nil {
				fail(err)
				return
			}
			a.Cache.Flush()
			res["upstreams"] = len(u.Servers)
		}
	}
	if body.Clients {
		for _, c := range e.Clients {
			cl, err := a.Clients.Find(c.Ref)
			if err != nil {
				continue // ainda não visto aqui
			}
			name := strings.TrimSpace(c.Name)
			if err := a.Clients.Update(cl, func(s *clients.Settings) error {
				if s.Name == "" {
					s.Name = name
				}
				return nil
			}); err == nil {
				res["clients"]++
			}
		}
	}
	notes = append(notes, e.Skipped...)
	if e.Groups > 0 {
		notes = append(notes, "grupos do Pi-hole não foram migrados (regras por dispositivo são configuradas em Dispositivos)")
	}
	a.audit(r, "import.pihole", e.Version, map[string]any{"result": res}, nil)
	writeJSON(w, http.StatusOK, map[string]any{"result": res, "notes": nonNil(notes)})
}
