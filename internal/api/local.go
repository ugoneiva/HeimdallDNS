// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/miekg/dns"

	"github.com/ugoneiva/HeimdallDNS/internal/server"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
	"github.com/ugoneiva/HeimdallDNS/internal/upstream"
)

// Chaves dos registros locais e dos upstreams definidos pelo painel.
const (
	LocalKey    = "dns.local"
	UpstreamKey = "dns.upstream"
)

// BuildLocal junta os registros do arquivo com os do painel e confere tudo.
func BuildLocal(cfg map[string][]netip.Addr, recs []store.LocalRecord) (*server.Local, error) {
	l := &server.Local{Hosts: map[string][]netip.Addr{}, CNAME: map[string]string{}}
	for name, ips := range cfg {
		l.Hosts[name] = slices.Clone(ips)
	}
	for _, r := range recs {
		name, err := fqdn(r.Name)
		if err != nil {
			return nil, err
		}
		switch strings.ToUpper(r.Type) {
		case "A", "AAAA":
			ip, err := netip.ParseAddr(strings.TrimSpace(r.Value))
			if err != nil || (r.Type == "A") != ip.Unmap().Is4() {
				return nil, fmt.Errorf("%s: IP %q inválido para %s", r.Name, r.Value, r.Type)
			}
			if !slices.Contains(l.Hosts[name], ip.Unmap()) {
				l.Hosts[name] = append(l.Hosts[name], ip.Unmap())
			}
		case "CNAME":
			target, err := fqdn(r.Value)
			if err != nil {
				return nil, err
			}
			if target == name {
				return nil, fmt.Errorf("%s: apelido para ele mesmo", r.Name)
			}
			if old, ok := l.CNAME[name]; ok && old != target {
				return nil, fmt.Errorf("%s: dois apelidos para o mesmo nome", r.Name)
			}
			l.CNAME[name] = target
		default:
			return nil, fmt.Errorf("%s: tipo %q (use A, AAAA ou CNAME)", r.Name, r.Type)
		}
	}
	for name := range l.CNAME {
		if _, ok := l.Hosts[name]; ok {
			return nil, fmt.Errorf("%s: um nome com apelido (CNAME) não pode ter IP", strings.TrimSuffix(name, "."))
		}
		seen := map[string]bool{}
		for n := name; ; {
			if seen[n] {
				return nil, fmt.Errorf("%s: apelidos em círculo", strings.TrimSuffix(name, "."))
			}
			seen[n] = true
			next, ok := l.CNAME[n]
			if !ok {
				break
			}
			n = next
		}
	}
	return l, nil
}

func fqdn(name string) (string, error) {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if n == "" || strings.Contains(n, "*") || strings.Contains(n, " ") {
		return "", fmt.Errorf("nome %q inválido", name)
	}
	if _, ok := dns.IsDomainName(n); !ok {
		return "", fmt.Errorf("nome %q inválido", name)
	}
	return n + ".", nil
}

// LoadLocal aplica no servidor os registros do arquivo + os do painel.
func LoadLocal(st *store.Store, cfg map[string][]netip.Addr, srv *server.Server) error {
	var recs []store.LocalRecord
	if _, err := st.GetJSON(LocalKey, &recs); err != nil {
		return err
	}
	l, err := BuildLocal(cfg, recs)
	if err != nil {
		return err
	}
	srv.SetLocal(l)
	return nil
}

// LoadUpstream aplica os upstreams do painel, se houver.
func LoadUpstream(st *store.Store, ups *upstream.Group) error {
	var u store.UpstreamSettings
	ok, err := st.GetJSON(UpstreamKey, &u)
	if err != nil || !ok || len(u.Servers) == 0 {
		return err
	}
	return ups.Reconfigure(upstream.Options{Servers: u.Servers, Mode: u.Mode})
}

func (a *api) localRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/dns/local", a.getLocal)
	mux.HandleFunc("PUT /api/dns/local", a.putLocal)
	mux.HandleFunc("GET /api/dns/upstream", a.getUpstream)
	mux.HandleFunc("PUT /api/dns/upstream", a.putUpstream)
	mux.HandleFunc("DELETE /api/dns/upstream", a.resetUpstream)
}

func (a *api) getLocal(w http.ResponseWriter, _ *http.Request) {
	var recs []store.LocalRecord
	if _, err := a.Store.GetJSON(LocalKey, &recs); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	cfg := []store.LocalRecord{}
	for name, ips := range a.LocalConfig {
		for _, ip := range ips {
			t := "A"
			if ip.Is6() {
				t = "AAAA"
			}
			cfg = append(cfg, store.LocalRecord{Name: strings.TrimSuffix(name, "."), Type: t, Value: ip.String()})
		}
	}
	slices.SortFunc(cfg, func(x, y store.LocalRecord) int { return strings.Compare(x.Name, y.Name) })
	if recs == nil {
		recs = []store.LocalRecord{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": cfg, "records": recs})
}

func (a *api) putLocal(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Records []store.LocalRecord `json:"records"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if err := a.saveLocal(body.Records); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	a.audit(r, "dns.local.update", "", map[string]any{"records": len(body.Records)}, nil)
	a.getLocal(w, r)
}

// saveLocal normaliza, confere, grava e aplica.
func (a *api) saveLocal(recs []store.LocalRecord) error {
	for i := range recs {
		recs[i].Name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(recs[i].Name), "."))
		recs[i].Type = strings.ToUpper(strings.TrimSpace(recs[i].Type))
		recs[i].Value = strings.TrimSuffix(strings.TrimSpace(recs[i].Value), ".")
	}
	l, err := BuildLocal(a.LocalConfig, recs)
	if err != nil {
		return err
	}
	if err := a.Store.SetJSON(LocalKey, recs); err != nil {
		return err
	}
	a.Server.SetLocal(l)
	return nil
}

func (a *api) getUpstream(w http.ResponseWriter, _ *http.Request) {
	servers, mode := a.Upstream.Config()
	var u store.UpstreamSettings
	custom, err := a.Store.GetJSON(UpstreamKey, &u)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"servers": servers, "mode": mode, "custom": custom && len(u.Servers) > 0,
		"config_servers": nonNil(a.UpstreamConfig.Servers), "config_mode": a.UpstreamConfig.Mode,
		"stats": a.Upstream.Stats(),
	})
}

func (a *api) putUpstream(w http.ResponseWriter, r *http.Request) {
	var body store.UpstreamSettings
	if !readJSON(w, r, &body) {
		return
	}
	body.Servers = clean(body.Servers)
	if body.Mode == "" {
		body.Mode = upstream.ModeFastest
	}
	if err := upstream.Validate(body.Servers, body.Mode); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := a.Upstream.Reconfigure(upstream.Options{Servers: body.Servers, Mode: body.Mode}); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := a.Store.SetJSON(UpstreamKey, body); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	a.Cache.Flush()
	a.audit(r, "dns.upstream.update", strings.Join(body.Servers, " "), map[string]any{"mode": body.Mode}, nil)
	a.getUpstream(w, r)
}

// resetUpstream volta aos upstreams do arquivo de configuração.
func (a *api) resetUpstream(w http.ResponseWriter, r *http.Request) {
	if len(a.UpstreamConfig.Servers) == 0 {
		writeErr(w, http.StatusConflict, errors.New("sem upstreams no arquivo de configuração"))
		return
	}
	if err := a.Upstream.Reconfigure(a.UpstreamConfig); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if err := a.Store.SetJSON(UpstreamKey, store.UpstreamSettings{}); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	a.Cache.Flush()
	a.audit(r, "dns.upstream.reset", "", nil, nil)
	a.getUpstream(w, r)
}
