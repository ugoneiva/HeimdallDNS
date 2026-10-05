// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package webfilter

import (
	"regexp"
	"strings"
)

// Endereços oficiais da busca segura, documentados por cada serviço para
// escolas e empresas: o DNS responde o nome do buscador com um CNAME para eles.
const (
	googleSafe     = "forcesafesearch.google.com."
	bingSafe       = "strict.bing.com."
	duckSafe       = "safe.duckduckgo.com."
	youtubeStrict  = "restrict.youtube.com."
	youtubeModerat = "restrictmoderate.youtube.com."
)

// Domínios do Google (google.com, google.com.br, google.co.uk…), com ou sem www.
var googleRe = regexp.MustCompile(`^(www\.)?google\.(com|[a-z]{2}|com?\.[a-z]{2})\.$`)

var youtubeNames = map[string]bool{
	"www.youtube.com.": true, "m.youtube.com.": true, "youtube.com.": true,
	"youtubei.googleapis.com.": true, "youtube.googleapis.com.": true, "www.youtube-nocookie.com.": true,
}

// SafeSearchTarget devolve o destino da busca segura para o nome consultado
// ("" se não for um buscador). youtube: strict ou moderate.
func SafeSearchTarget(name, youtube string) string {
	n := strings.ToLower(name)
	if !strings.HasSuffix(n, ".") {
		n += "."
	}
	switch {
	case googleRe.MatchString(n):
		return googleSafe
	case youtubeNames[n]:
		if youtube == "moderate" {
			return youtubeModerat
		}
		return youtubeStrict
	case n == "www.bing.com." || n == "bing.com.":
		return bingSafe
	case n == "duckduckgo.com." || n == "www.duckduckgo.com." || n == "start.duckduckgo.com.":
		return duckSafe
	}
	return ""
}

// SafeSearch decide a busca segura: vale se ligada para todos (global) ou
// para o grupo do aparelho.
func (m *Manager) SafeSearch(name string, global, group bool) string {
	s := m.settings.Load()
	if !(global && s.SafeSearch) && !group {
		return ""
	}
	return SafeSearchTarget(name, s.YouTube)
}
