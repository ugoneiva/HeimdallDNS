// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"errors"
	"net/http"

	"github.com/ugoneiva/HeimdallDNS/internal/certs"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

// CertsKey guarda a configuração do certificado HTTPS (Let's Encrypt).
const CertsKey = "certs"

// LoadCerts aplica a configuração salva.
func LoadCerts(st *store.Store, cm *certs.Manager) error {
	var s certs.Settings
	ok, err := st.GetJSON(CertsKey, &s)
	if err != nil || !ok {
		return err
	}
	return cm.SetSettings(s)
}

func (a *api) certRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/certs", a.getCerts)
	mux.HandleFunc("PUT /api/certs", a.putCerts)
	mux.HandleFunc("POST /api/certs/issue", a.issueCert)
	mux.HandleFunc("POST /api/certs/disable", a.disableCert)
}

func (a *api) certsOn(w http.ResponseWriter) bool {
	if a.Certs == nil {
		writeErr(w, http.StatusNotFound, errors.New("certificados indisponíveis"))
		return false
	}
	return true
}

func (a *api) getCerts(w http.ResponseWriter, _ *http.Request) {
	if !a.certsOn(w) {
		return
	}
	s := a.Certs.Settings()
	s.CloudflareToken = mask(s.CloudflareToken)
	if s.Domains == nil {
		s.Domains = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"settings": s,
		"status":   a.Certs.Status(),
		"running":  a.Certs.Running(),
		// O painel está em HTTPS agora? Se não, ligar o certificado nele pede
		// reiniciar (o serviço abre a porta já com TLS).
		"panel_https": a.Secure,
		"dns_tls":     a.DNSTLS,
	})
}

func (a *api) saveCerts(r *http.Request, s certs.Settings) error {
	if s.CloudflareToken == secretMask {
		s.CloudflareToken = a.Certs.Settings().CloudflareToken
	}
	if s.Challenge != certs.ChallengeCloudflare {
		s.CloudflareToken = ""
	}
	if err := a.Certs.SetSettings(s); err != nil {
		return err
	}
	if err := a.Store.SetJSON(CertsKey, a.Certs.Settings()); err != nil {
		return err
	}
	a.audit(r, "certs.settings", "", map[string]any{"domains": s.Domains, "challenge": s.Challenge, "enabled": s.Enabled,
		"auto_renew": s.AutoRenew, "panel": s.UsePanel, "dns": s.UseDNS, "staging": s.Staging}, nil)
	return nil
}

func (a *api) putCerts(w http.ResponseWriter, r *http.Request) {
	if !a.certsOn(w) {
		return
	}
	var s certs.Settings
	if !readJSON(w, r, &s) {
		return
	}
	if err := a.saveCerts(r, s); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	a.getCerts(w, r)
}

// issueCert grava a configuração enviada (se houver), liga e emite em
// segundo plano; o painel acompanha pelo GET.
func (a *api) issueCert(w http.ResponseWriter, r *http.Request) {
	if !a.certsOn(w) {
		return
	}
	var s certs.Settings
	if r.ContentLength > 0 {
		if !readJSON(w, r, &s) {
			return
		}
	} else {
		s = a.Certs.Settings()
	}
	s.Enabled = true
	if err := a.saveCerts(r, s); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := a.Certs.IssueAsync(); err != nil {
		writeErr(w, http.StatusConflict, err)
		return
	}
	a.audit(r, "certs.issue", "", map[string]any{"domains": s.Domains}, nil)
	a.getCerts(w, r)
}

// disableCert volta ao certificado do arquivo (ou autoassinado); os arquivos
// emitidos ficam guardados.
func (a *api) disableCert(w http.ResponseWriter, r *http.Request) {
	if !a.certsOn(w) {
		return
	}
	a.Certs.Disable()
	if err := a.Store.SetJSON(CertsKey, a.Certs.Settings()); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	a.audit(r, "certs.disable", "", nil, nil)
	a.getCerts(w, r)
}
