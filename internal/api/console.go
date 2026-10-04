package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/ugoneiva/HeimdallDNS/internal/console"
)

func (a *api) consoleTenants(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.Console.States())
}

func (a *api) consoleAlerts(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.Console.Alerts())
}

func (a *api) consoleAdd(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string `json:"name"`
		URL         string `json:"url"`
		Token       string `json:"token"`
		InsecureTLS bool   `json:"insecure_tls"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	t, err := a.Console.Add(r.Context(), console.Tenant{Name: body.Name, URL: body.URL, Token: body.Token, InsecureTLS: body.InsecureTLS})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func (a *api) consoleRemove(w http.ResponseWriter, r *http.Request) {
	if err := a.Console.Remove(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) consoleAck(w http.ResponseWriter, r *http.Request) {
	ev, err := strconv.ParseInt(r.PathValue("event"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("alerta inválido"))
		return
	}
	if err := a.Console.Ack(r.Context(), r.PathValue("id"), ev); err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, a.Console.Alerts())
}
