// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package main

import (
	"fmt"
	"strings"

	"github.com/ugoneiva/HeimdallDNS/internal/clients"
	"github.com/ugoneiva/HeimdallDNS/internal/notify"
	"github.com/ugoneiva/HeimdallDNS/internal/security"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

// Títulos dos alertas de segurança nos avisos.
var alertTitle = map[string]string{
	security.KindThreat:    "Ameaça bloqueada",
	security.KindDGA:       "Possível malware (nomes aleatórios, DGA)",
	security.KindTunnel:    "Possível túnel/exfiltração por DNS",
	security.KindNRD:       "Domínio recém-registrado",
	security.KindNewDevice: "Dispositivo novo na rede",
	security.KindFlood:     "Excesso de consultas",
}

func securityNotice(ev store.SecurityEvent, client, response string) notify.Event {
	title := alertTitle[ev.Kind]
	if title == "" {
		title = ev.Kind
	}
	if response == "isolated" {
		title += " — dispositivo isolado"
	}
	who := client
	if who == "" {
		who = ev.ClientIP
	} else if ev.ClientIP != "" && who != ev.ClientIP {
		who += " (" + ev.ClientIP + ")"
	}
	fields := [][2]string{{"Dispositivo", who}}
	if ev.Domain != "" {
		fields = append(fields, [2]string{"Domínio", ev.Domain})
	}
	fields = append(fields, [2]string{"Tipo", ev.Kind})
	return notify.Event{Type: notify.EventSecurity, Severity: ev.Severity, Title: title, Text: ev.Summary,
		Fields: fields, Time: ev.FirstSeen, Key: ev.Kind + "|" + ev.ClientID + "|" + ev.Domain}
}

func isolationNotice(c *clients.Client, isolated bool, reason string) notify.Event {
	p := c.Policy()
	name := p.Display
	if isolated {
		fields := [][2]string{{"Dispositivo", name}}
		if reason != "" {
			fields = append(fields, [2]string{"Motivo", reason})
		}
		return notify.Event{Type: notify.EventIsolation, Severity: notify.SevHigh, Title: "Dispositivo isolado: " + name,
			Text: "O DNS do dispositivo foi cortado (só as exceções respondem).", Fields: fields, Key: "isolated|" + c.ID()}
	}
	return notify.Event{Type: notify.EventIsolation, Severity: notify.SevLow, Title: "Dispositivo liberado: " + name,
		Text: "O dispositivo voltou a navegar normalmente.", Fields: [][2]string{{"Dispositivo", name}}, Key: "released|" + c.ID()}
}

func upstreamNotice(up bool, servers []string) notify.Event {
	if up {
		return notify.Event{Type: notify.EventUpstream, Severity: notify.SevLow, Title: "Upstreams de volta",
			Text: "O HeimdallDNS voltou a resolver nomes da internet.", Fields: [][2]string{{"Upstreams", strings.Join(servers, ", ")}}, Key: "upstream-up"}
	}
	return notify.Event{Type: notify.EventUpstream, Severity: notify.SevCritical, Title: "Nenhum upstream responde",
		Text:   "As consultas para a internet estão falhando. Confira a conexão do servidor ou troque os upstreams no painel (DNS).",
		Fields: [][2]string{{"Upstreams", strings.Join(servers, ", ")}}, Key: "upstream-down"}
}

func systemNotice(title string, err error, fields ...[2]string) notify.Event {
	return notify.Event{Type: notify.EventSystem, Severity: notify.SevHigh, Title: title,
		Text: fmt.Sprint(err), Fields: fields, Key: "system|" + title}
}
