// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package topology

import (
	"regexp"
	"strings"
)

// Tipos de aparelho (o painel escolhe o ícone por eles).
const (
	KindPhone    = "phone"
	KindTablet   = "tablet"
	KindComputer = "computer"
	KindTV       = "tv"
	KindPrinter  = "printer"
	KindCamera   = "camera"
	KindConsole  = "console"
	KindSpeaker  = "speaker"
	KindServer   = "server"
	KindRouter   = "router"
	KindIoT      = "iot"
	KindUnknown  = "unknown"
)

// Kinds são os tipos que dá para escolher à mão.
var Kinds = []string{KindPhone, KindTablet, KindComputer, KindTV, KindPrinter, KindCamera, KindConsole, KindSpeaker, KindServer, KindRouter, KindIoT, KindUnknown}

// ValidKind diz se o tipo existe ("" = deduzir).
func ValidKind(k string) bool {
	if k == "" {
		return true
	}
	for _, x := range Kinds {
		if x == k {
			return true
		}
	}
	return false
}

// Padrões no nome do aparelho (nome dado, reverso ou do DHCP).
var namePatterns = []struct {
	re   *regexp.Regexp
	kind string
}{
	{regexp.MustCompile(`ipad|tablet|\btab\b|galaxy-?tab`), KindTablet},
	{regexp.MustCompile(`iphone|android|galaxy|pixel|redmi|poco|moto[- ]?[a-z0-9]|celular|smartphone|phone|oneplus|huawei`), KindPhone},
	{regexp.MustCompile(`macbook|imac|laptop|notebook|desktop|thinkpad|\bpc\b|-pc\b|^pc-|workstation|ultrabook|chromebook`), KindComputer},
	{regexp.MustCompile(`\btv\b|smart-?tv|bravia|roku|chromecast|fire-?tv|apple-?tv|webos|tizen|android-?tv|mibox|tvbox`), KindTV},
	{regexp.MustCompile(`printer|impressora|epson|brother|canon|laserjet|deskjet|officejet|\bhp[a-z0-9]{4,}`), KindPrinter},
	{regexp.MustCompile(`\bcam\b|camera|câmera|ipcam|hikvision|dahua|intelbras|ezviz|\bdvr\b|\bnvr\b|wyze|ring-`), KindCamera},
	{regexp.MustCompile(`playstation|\bps[345]\b|xbox|nintendo|switch`), KindConsole},
	{regexp.MustCompile(`echo|alexa|homepod|google-?home|nest-?(mini|audio|hub)|sonos|speaker`), KindSpeaker},
	{regexp.MustCompile(`\bnas\b|server|servidor|\bsrv|proxmox|synology|qnap|truenas|raspberry|\brpi\b|pihole|esxi`), KindServer},
	{regexp.MustCompile(`router|roteador|gateway|\bap\b|access-?point|mikrotik|ubiquiti|unifi|openwrt|archer`), KindRouter},
	{regexp.MustCompile(`esp[-_]?[0-9a-f]{4,}|tasmota|shelly|sonoff|tuya|smart-?(plug|lamp|bulb)|lampada|tomada|wled|zigbee`), KindIoT},
}

// Fabricante (da base OUI) → tipo, quando o nome não diz nada.
var vendorPatterns = []struct {
	re   *regexp.Regexp
	kind string
}{
	{regexp.MustCompile(`espressif|tuya|shelly|sonoff|itead|lifx|signify|philips lighting`), KindIoT},
	{regexp.MustCompile(`hikvision|dahua|intelbras|ezviz|wyze|axis comm`), KindCamera},
	{regexp.MustCompile(`seiko epson|brother|canon|lexmark|xerox|kyocera|ricoh`), KindPrinter},
	{regexp.MustCompile(`sony interactive|nintendo`), KindConsole},
	{regexp.MustCompile(`roku|lg electronics|tcl|hisense|vizio`), KindTV},
	{regexp.MustCompile(`sonos|amazon technologies`), KindSpeaker},
	{regexp.MustCompile(`raspberry pi|synology|qnap|supermicro|super micro`), KindServer},
	{regexp.MustCompile(`tp-link|mikrotik|ubiquiti|routerboard|huawei technologies|zte|arris|technicolor|sagemcom|intelbras|d-link|netgear|tenda|mercusys`), KindRouter},
	{regexp.MustCompile(`samsung|xiaomi|motorola|oneplus|oppo|vivo mobile|realme|huawei device|google`), KindPhone},
	{regexp.MustCompile(`apple`), KindPhone},
	{regexp.MustCompile(`intel corp|realtek|liteon|lite-on|azurewave|cloud network technology|hon hai|foxconn|dell|lenovo|hewlett|asustek|micro-star|gigabyte|chicony|quanta`), KindComputer},
}

// Destinos que denunciam o tipo (consultas típicas de cada sistema).
var domainHints = []struct {
	suffix string
	kind   string
}{
	{"xboxlive.com", KindConsole},
	{"playstation.net", KindConsole},
	{"nintendo.net", KindConsole},
	{"windowsupdate.com", KindComputer},
	{"msftconnecttest.com", KindComputer},
	// Repositórios de distribuições Linux: só computador consulta.
	{"manjaro.org", KindComputer},
	{"archlinux.org", KindComputer},
	{"ubuntu.com", KindComputer},
	{"debian.org", KindComputer},
	{"fedoraproject.org", KindComputer},
	// connectivitycheck.gstatic.com NÃO serve: o Chrome e o NetworkManager
	// também consultam, em qualquer sistema.
	{"android.clients.google.com", KindPhone},
	{"roku.com", KindTV},
	{"samsungcloudsolution.com", KindTV},
	{"lgtvsdp.com", KindTV},
	{"epson.net", KindPrinter},
	{"hpeprint.com", KindPrinter},
	{"tuyaus.com", KindIoT},
	{"tuyacn.com", KindIoT},
	{"shelly.cloud", KindIoT},
}

// Guess deduz o tipo pelo nome, pelo fabricante e pelos nomes consultados.
// O nome vence o fabricante (um "notebook" com placa Intel continua notebook),
// e as consultas vencem o fabricante (um Samsung que fala com a loja de TV é TV).
func Guess(name, hostname, vendor string, queried []string) string {
	text := strings.ToLower(name + " " + hostname)
	for _, p := range namePatterns {
		if p.re.MatchString(text) {
			return p.kind
		}
	}
	for _, q := range queried {
		q = strings.TrimSuffix(strings.ToLower(q), ".")
		for _, h := range domainHints {
			if q == h.suffix || strings.HasSuffix(q, "."+h.suffix) {
				return h.kind
			}
		}
	}
	v := strings.ToLower(vendor)
	for _, p := range vendorPatterns {
		if v != "" && p.re.MatchString(v) {
			return p.kind
		}
	}
	return KindUnknown
}
