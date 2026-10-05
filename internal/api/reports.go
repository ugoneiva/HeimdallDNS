// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/report"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

// Chaves do relatório periódico.
const (
	ReportKey     = "report"
	ReportLastKey = "report.last" // fim do último período enviado
)

// LoadReport aplica a configuração salva.
func LoadReport(st *store.Store, rs *report.Scheduler) error {
	var s report.Settings
	ok, err := st.GetJSON(ReportKey, &s)
	if err != nil || !ok {
		return err
	}
	return rs.SetSettings(s)
}

func (a *api) reportRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/reports", a.getReports)
	mux.HandleFunc("PUT /api/reports/settings", a.putReportSettings)
	mux.HandleFunc("GET /api/reports/generate", a.generateReport)
	mux.HandleFunc("POST /api/reports/send", a.sendReport)
	mux.HandleFunc("GET /api/reports/file/{name}", a.reportFile)
}

func (a *api) reportsOn(w http.ResponseWriter) bool {
	if a.Reports == nil {
		writeErr(w, http.StatusNotFound, errors.New("relatórios indisponíveis"))
		return false
	}
	return true
}

func (a *api) getReports(w http.ResponseWriter, _ *http.Request) {
	if !a.reportsOn(w) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": a.Reports.Settings(), "reports": a.Reports.List()})
}

func (a *api) putReportSettings(w http.ResponseWriter, r *http.Request) {
	if !a.reportsOn(w) {
		return
	}
	var s report.Settings
	if !readJSON(w, r, &s) {
		return
	}
	if err := s.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := a.Store.SetJSON(ReportKey, s); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	_ = a.Reports.SetSettings(s)
	a.audit(r, "report.settings", "", map[string]any{"enabled": s.Enabled, "frequency": s.Frequency, "hour": s.Hour}, nil)
	a.getReports(w, r)
}

// generateReport monta o PDF dos últimos N dias (até hoje 00:00) e baixa.
func (a *api) generateReport(w http.ResponseWriter, r *http.Request) {
	if !a.reportsOn(w) {
		return
	}
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 {
		days = 7
	}
	days = min(days, 90)
	now := timeNow()
	y, m, d := now.Date()
	to := time.Date(y, m, d, 0, 0, 0, 0, now.Location())
	if r.URL.Query().Get("today") == "1" {
		to = to.AddDate(0, 0, 1) // inclui o dia de hoje
	}
	from := to.AddDate(0, 0, -days)
	title := "Relatório de " + strconv.Itoa(days) + " dias"
	_, pdf, name, err := a.Reports.Generate(from, to, title)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Write(pdf)
}

// sendReport manda já o relatório do último período pelos canais.
func (a *api) sendReport(w http.ResponseWriter, r *http.Request) {
	if !a.reportsOn(w) {
		return
	}
	name, err := a.Reports.SendNow()
	a.audit(r, "report.send", name, nil, err)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": name})
}

func (a *api) reportFile(w http.ResponseWriter, r *http.Request) {
	if !a.reportsOn(w) {
		return
	}
	p, ok := a.Reports.Path(r.PathValue("name"))
	if !ok {
		writeErr(w, http.StatusNotFound, errors.New("relatório não encontrado"))
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+r.PathValue("name")+`"`)
	http.ServeFile(w, r, p)
}
