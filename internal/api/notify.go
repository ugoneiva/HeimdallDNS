// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"errors"
	"net/http"

	"github.com/ugoneiva/HeimdallDNS/internal/notify"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

// NotifyKey guarda os canais de notificação e o SMTP.
const NotifyKey = "notify"

// secretMask volta no lugar dos segredos; mandado de volta, mantém o atual.
const secretMask = "••••••••"

// LoadNotify aplica a configuração salva.
func LoadNotify(st *store.Store, nt *notify.Manager) error {
	var s notify.Settings
	ok, err := st.GetJSON(NotifyKey, &s)
	if err != nil || !ok {
		return err
	}
	return nt.SetSettings(s)
}

func (a *api) notifyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/notify", a.getNotify)
	mux.HandleFunc("PUT /api/notify", a.putNotify)
	mux.HandleFunc("POST /api/notify/test/{id}", a.testNotify)
}

func mask(v string) string {
	if v == "" {
		return ""
	}
	return secretMask
}

// masked tira os segredos (token do bot, segredo do webhook, URL do Teams,
// que leva a assinatura, e a senha do SMTP).
func masked(s notify.Settings) notify.Settings {
	for i := range s.Channels {
		c := &s.Channels[i]
		c.BotToken, c.Secret = mask(c.BotToken), mask(c.Secret)
		if c.Type == notify.TypeTeams {
			c.URL = mask(c.URL)
		}
		if c.Events == nil {
			c.Events = []string{}
		}
	}
	s.SMTP.Password = mask(s.SMTP.Password)
	return s
}

// unmask devolve os segredos que o painel mandou mascarados.
func unmask(s *notify.Settings, cur notify.Settings) {
	old := map[string]notify.Channel{}
	for _, c := range cur.Channels {
		old[c.ID] = c
	}
	for i := range s.Channels {
		c := &s.Channels[i]
		o := old[c.ID]
		if c.BotToken == secretMask {
			c.BotToken = o.BotToken
		}
		if c.Secret == secretMask {
			c.Secret = o.Secret
		}
		if c.URL == secretMask {
			c.URL = o.URL
		}
	}
	if s.SMTP.Password == secretMask {
		s.SMTP.Password = cur.SMTP.Password
	}
}

func (a *api) getNotify(w http.ResponseWriter, _ *http.Request) {
	if a.Notify == nil {
		writeErr(w, http.StatusNotFound, errors.New("notificações indisponíveis"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"settings": masked(a.Notify.Settings()), "history": a.Notify.History(), "events": notify.Events,
	})
}

func (a *api) putNotify(w http.ResponseWriter, r *http.Request) {
	if a.Notify == nil {
		writeErr(w, http.StatusNotFound, errors.New("notificações indisponíveis"))
		return
	}
	var s notify.Settings
	if !readJSON(w, r, &s) {
		return
	}
	unmask(&s, a.Notify.Settings())
	if err := s.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := a.Store.SetJSON(NotifyKey, s); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if err := a.Notify.SetSettings(s); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	names := []string{}
	for _, c := range s.Channels {
		names = append(names, c.Type+":"+c.Name)
	}
	a.audit(r, "notify.update", "", map[string]any{"channels": names}, nil)
	a.getNotify(w, r)
}

// testNotify manda um aviso de teste pelo canal salvo.
func (a *api) testNotify(w http.ResponseWriter, r *http.Request) {
	if a.Notify == nil {
		writeErr(w, http.StatusNotFound, errors.New("notificações indisponíveis"))
		return
	}
	err := a.Notify.Test(r.Context(), r.PathValue("id"))
	a.audit(r, "notify.test", r.PathValue("id"), nil, err)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"sent": true})
}
