// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Encrypted descreve o DNS criptografado deste servidor, para o painel montar
// os endereços de cada aparelho.
type Encrypted struct {
	PublicHost string `json:"public_host"`
	DoH        bool   `json:"doh"`
	DoT        bool   `json:"dot"`
	DoHPort    string `json:"doh_port,omitempty"`
	DoTPort    string `json:"dot_port,omitempty"`
}

func (e Encrypted) dohURL(token string) string {
	host := e.PublicHost
	if e.DoHPort != "" && e.DoHPort != "443" {
		host += ":" + e.DoHPort
	}
	u := "https://" + host + "/dns-query"
	if token != "" {
		u += "/" + token
	}
	return u
}

type deviceAccess struct {
	Encrypted
	Token   string `json:"token,omitempty"`
	DoHURL  string `json:"doh_url,omitempty"`
	DoTHost string `json:"dot_host,omitempty"`
}

func (a *api) accessInfo(token string) deviceAccess {
	d := deviceAccess{Encrypted: a.Encrypted, Token: token}
	if a.Encrypted.PublicHost != "" && token != "" {
		if a.Encrypted.DoH {
			d.DoHURL = a.Encrypted.dohURL(token)
		}
		if a.Encrypted.DoT {
			d.DoTHost = token + "." + a.Encrypted.PublicHost
		}
	}
	return d
}

func (a *api) encryptedInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.Encrypted)
}

func (a *api) getAccess(w http.ResponseWriter, r *http.Request) {
	if c := a.find(w, r); c != nil {
		writeJSON(w, http.StatusOK, a.accessInfo(c.View().Settings.AccessToken))
	}
}

// newToken cria ou troca o token do aparelho (o antigo para de valer na hora).
func (a *api) newToken(w http.ResponseWriter, r *http.Request) {
	c := a.find(w, r)
	if c == nil {
		return
	}
	tok, err := a.Clients.SetToken(c, false)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, a.accessInfo(tok))
}

func (a *api) revokeToken(w http.ResponseWriter, r *http.Request) {
	c := a.find(w, r)
	if c == nil {
		return
	}
	if _, err := a.Clients.SetToken(c, true); err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, a.accessInfo(""))
}

// mobileconfig gera o perfil da Apple (iPhone, iPad, Mac) que liga o DoH do
// aparelho com um toque. O perfil não é assinado: o sistema mostra o aviso
// "não verificado" ao instalar.
func (a *api) mobileconfig(w http.ResponseWriter, r *http.Request) {
	c := a.find(w, r)
	if c == nil {
		return
	}
	v := c.View()
	if !a.Encrypted.DoH || a.Encrypted.PublicHost == "" {
		writeErr(w, http.StatusConflict, errors.New("configure dns.doh_listen e dns.public_host para gerar o perfil"))
		return
	}
	if v.Settings.AccessToken == "" {
		writeErr(w, http.StatusConflict, errors.New("gere o token do aparelho antes"))
		return
	}
	esc := func(s string) string {
		var b strings.Builder
		_ = xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	name := esc("HeimdallDNS — " + v.Display)
	profile := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>DNSSettings</key>
			<dict>
				<key>DNSProtocol</key>
				<string>HTTPS</string>
				<key>ServerURL</key>
				<string>%s</string>
			</dict>
			<key>PayloadDescription</key>
			<string>Envia o DNS deste aparelho para o HeimdallDNS, com as regras dele, dentro e fora da rede.</string>
			<key>PayloadDisplayName</key>
			<string>%s</string>
			<key>PayloadIdentifier</key>
			<string>com.apple.dnsSettings.managed.%s</string>
			<key>PayloadType</key>
			<string>com.apple.dnsSettings.managed</string>
			<key>PayloadUUID</key>
			<string>%s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDisplayName</key>
	<string>%s</string>
	<key>PayloadIdentifier</key>
	<string>br.heimdalldns.%s</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>%s</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`, esc(a.Encrypted.dohURL(v.Settings.AccessToken)), name, v.ID, newUUID(), name, v.ID, newUUID())
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="heimdalldns-%s.mobileconfig"`, v.ID))
	_, _ = w.Write([]byte(profile))
}

// newUUID gera um UUID v4 (os perfis da Apple exigem).
func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := strings.ToUpper(hex.EncodeToString(b))
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
