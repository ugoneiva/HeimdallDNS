// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package filter

import (
	"fmt"
	"slices"
	"strings"
)

// Service é um serviço conhecido que pode ser bloqueado pelo nome nas regras
// próprias (por exemplo "service:tiktok" ou o grupo "service:social").
type Service struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Group   string   `json:"group"`
	Domains []string `json:"domains"` // valem para o domínio e os subdomínios
}

// Services é o catálogo embutido. Os domínios cobrem o site, os apps e as CDNs
// principais de cada serviço.
var Services = []Service{
	{"facebook", "Facebook", "social", []string{"facebook.com", "facebook.net", "fbcdn.net", "fb.com", "fb.me", "fbsbx.com", "messenger.com"}},
	{"instagram", "Instagram", "social", []string{"instagram.com", "cdninstagram.com", "ig.me"}},
	{"tiktok", "TikTok", "social", []string{"tiktok.com", "tiktokv.com", "tiktokcdn.com", "tiktokcdn-us.com", "byteoversea.com", "ibytedtos.com", "musical.ly"}},
	{"twitter", "X (Twitter)", "social", []string{"twitter.com", "x.com", "twimg.com", "t.co"}},
	{"snapchat", "Snapchat", "social", []string{"snapchat.com", "sc-cdn.net", "sc-static.net"}},
	{"reddit", "Reddit", "social", []string{"reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"}},
	{"linkedin", "LinkedIn", "social", []string{"linkedin.com", "licdn.com", "lnkd.in"}},
	{"pinterest", "Pinterest", "social", []string{"pinterest.com", "pinimg.com"}},
	{"whatsapp", "WhatsApp", "mensagens", []string{"whatsapp.com", "whatsapp.net", "wa.me"}},
	{"telegram", "Telegram", "mensagens", []string{"telegram.org", "telegram.me", "t.me", "telesco.pe"}},
	{"discord", "Discord", "mensagens", []string{"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"}},
	{"youtube", "YouTube", "streaming", []string{"youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "youtube-nocookie.com", "youtubei.googleapis.com"}},
	{"netflix", "Netflix", "streaming", []string{"netflix.com", "netflix.net", "nflxext.com", "nflximg.net", "nflximg.com", "nflxvideo.net", "nflxso.net"}},
	{"twitch", "Twitch", "streaming", []string{"twitch.tv", "ttvnw.net", "jtvnw.net"}},
	{"roblox", "Roblox", "jogos", []string{"roblox.com", "rbxcdn.com"}},
}

const servicePrefix = "service:"

// expandService troca "service:id" (ou "service:grupo") pelas regras dos
// domínios. Outras linhas voltam como estão.
func expandService(line string) ([]string, error) {
	line = strings.TrimSpace(line)
	allow := strings.HasPrefix(line, "@@")
	body := strings.TrimPrefix(line, "@@")
	if !strings.HasPrefix(body, servicePrefix) {
		return []string{line}, nil
	}
	id := strings.ToLower(strings.TrimPrefix(body, servicePrefix))
	var out []string
	for _, s := range Services {
		if s.ID != id && s.Group != id {
			continue
		}
		for _, d := range s.Domains {
			r := "||" + d + "^"
			if allow {
				r = "@@" + r
			}
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("serviço desconhecido: %s", id)
	}
	return out, nil
}

// ServiceGroups lista os grupos do catálogo.
func ServiceGroups() []string {
	var g []string
	for _, s := range Services {
		if !slices.Contains(g, s.Group) {
			g = append(g, s.Group)
		}
	}
	return g
}

// AddUserRules acrescenta regras escritas pelo usuário: domínio simples vale
// para os subdomínios, "service:x" expande para o serviço, e as de allow viram
// exceções. Devolve as regras que não puderam ser entendidas.
func (b *Builder) AddUserRules(allow, deny []string) (invalid []string) {
	add := func(line string, exception bool) {
		lines, err := expandService(line)
		if err != nil {
			invalid = append(invalid, line)
			return
		}
		for _, l := range lines {
			if exception && !strings.HasPrefix(l, "@@") {
				l = "@@" + l
			}
			if b.AddLine(l, true) == lineBad {
				invalid = append(invalid, line)
				return
			}
		}
	}
	for _, l := range deny {
		add(l, false)
	}
	for _, l := range allow {
		add(l, true)
	}
	return invalid
}

// CompileUserRules monta um Matcher só com regras do usuário. Devolve nil
// quando não há regra nenhuma.
func CompileUserRules(allow, deny []string) (*Matcher, []string) {
	if len(allow) == 0 && len(deny) == 0 {
		return nil, nil
	}
	b := NewBuilder()
	invalid := b.AddUserRules(allow, deny)
	return b.Build(), invalid
}
