// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

// Package topology monta o mapa da rede que o HeimdallDNS enxerga pelo DNS:
// aparelhos (com o tipo deduzido), o servidor, a internet e os destinos de
// cada aparelho agrupados por serviço.
package topology

import (
	"strings"

	"github.com/ugoneiva/HeimdallDNS/internal/dnsname"
	"github.com/ugoneiva/HeimdallDNS/internal/filter"
)

// Categorias de destino (o painel escolhe o ícone por elas).
const (
	CatSocial    = "social"
	CatMessaging = "mensagens"
	CatStreaming = "streaming"
	CatGames     = "jogos"
	CatSearch    = "busca"   // Google, Bing…
	CatSystem    = "sistema" // atualizações e serviços do sistema (Apple, Microsoft, Android)
	CatCloud     = "nuvem"   // nuvem e CDN (Amazon, Cloudflare, Akamai…)
	CatShopping  = "compras"
	CatWork      = "trabalho" // Office, Zoom, Slack…
	CatBlocked   = "bloqueado"
	CatOther     = "outros"
)

// Destination é um destino agrupado (um serviço ou um domínio).
type Destination struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
}

// Além do catálogo de serviços do filtro (redes sociais, streaming…), os
// destinos mais comuns de uma rede. Domínio vale com os subdomínios.
var extra = []struct {
	id, name, cat string
	domains       []string
}{
	{"google", "Google", CatSearch, []string{"google.com", "google.com.br", "googleapis.com", "gstatic.com", "gvt1.com", "gvt2.com", "googleusercontent.com", "ggpht.com", "1e100.net", "googletagmanager.com", "google-analytics.com", "googlesyndication.com", "doubleclick.net", "app-measurement.com", "firebaseio.com", "crashlytics.com"}},
	{"android", "Android", CatSystem, []string{"android.com", "googleplay.com", "play.google.com"}},
	{"apple", "Apple / iCloud", CatSystem, []string{"apple.com", "icloud.com", "icloud-content.com", "mzstatic.com", "aaplimg.com", "apple-dns.net", "cdn-apple.com", "itunes.apple.com", "apple.news"}},
	{"microsoft", "Microsoft / Windows", CatSystem, []string{"microsoft.com", "windows.com", "windowsupdate.com", "msftconnecttest.com", "msftncsi.com", "live.com", "msn.com", "bing.com", "msedge.net", "azureedge.net", "azure.com", "skype.com", "xbox.com", "xboxlive.com", "microsoftonline.com", "office.net", "sharepoint.com", "onedrive.com", "s-microsoft.com", "trafficmanager.net", "windows.net"}},
	{"office", "Microsoft 365", CatWork, []string{"office.com", "office365.com", "outlook.com", "teams.microsoft.com", "lync.com"}},
	{"amazon", "Amazon / AWS", CatCloud, []string{"amazon.com", "amazon.com.br", "amazonaws.com", "media-amazon.com", "ssl-images-amazon.com", "amazonvideo.com", "primevideo.com", "aiv-cdn.net", "a2z.com", "alexa.com"}},
	{"cloudflare", "Cloudflare", CatCloud, []string{"cloudflare.com", "cloudflare-dns.com", "cloudflareinsights.com", "workers.dev", "one.one.one.one"}},
	{"akamai", "Akamai (CDN)", CatCloud, []string{"akamai.net", "akamaiedge.net", "akamaized.net", "akamaihd.net", "edgekey.net", "edgesuite.net"}},
	{"fastly", "Fastly (CDN)", CatCloud, []string{"fastly.net", "fastlylb.net"}},
	{"meta", "Meta", CatSocial, []string{"meta.com", "oculus.com"}},
	{"spotify", "Spotify", CatStreaming, []string{"spotify.com", "scdn.co", "spotifycdn.com", "spotify.design"}},
	{"globo", "Globo", CatStreaming, []string{"globo.com", "globoplay.com", "glbimg.com"}},
	{"disney", "Disney+", CatStreaming, []string{"disneyplus.com", "disney-plus.net", "bamgrid.com", "dssott.com"}},
	{"hbo", "Max", CatStreaming, []string{"max.com", "hbomax.com", "hbo.com"}},
	{"steam", "Steam", CatGames, []string{"steampowered.com", "steamcommunity.com", "steamcontent.com", "steamstatic.com"}},
	{"playstation", "PlayStation", CatGames, []string{"playstation.com", "playstation.net", "sonyentertainmentnetwork.com"}},
	{"epic", "Epic Games", CatGames, []string{"epicgames.com", "unrealengine.com", "fortnite.com"}},
	{"nintendo", "Nintendo", CatGames, []string{"nintendo.com", "nintendo.net"}},
	{"zoom", "Zoom", CatWork, []string{"zoom.us", "zoom.com"}},
	{"slack", "Slack", CatWork, []string{"slack.com", "slack-edge.com", "slack-msgs.com"}},
	{"github", "GitHub", CatWork, []string{"github.com", "githubusercontent.com", "github.io", "githubassets.com"}},
	{"mercadolivre", "Mercado Livre", CatShopping, []string{"mercadolivre.com.br", "mercadolibre.com", "mlstatic.com"}},
	{"shopee", "Shopee", CatShopping, []string{"shopee.com.br", "shopee.com", "susercontent.com"}},
	{"aliexpress", "AliExpress", CatShopping, []string{"aliexpress.com", "alicdn.com", "aliexpress.us"}},
	{"samsung", "Samsung", CatSystem, []string{"samsung.com", "samsungcloud.com", "samsungapps.com", "samsungosp.com", "samsungqbe.com"}},
	{"xiaomi", "Xiaomi", CatSystem, []string{"xiaomi.com", "mi.com", "miui.com", "xiaomi.net"}},
	{"ubuntu", "Linux (atualizações)", CatSystem, []string{"ubuntu.com", "canonical.com", "snapcraft.io", "debian.org", "fedoraproject.org", "archlinux.org"}},
}

// byDomain liga cada domínio do catálogo ao destino dele.
var byDomain = func() map[string]Destination {
	m := map[string]Destination{}
	for _, s := range filter.Services {
		for _, d := range s.Domains {
			m[d] = Destination{ID: s.ID, Name: s.Name, Category: s.Group}
		}
	}
	for _, e := range extra {
		for _, d := range e.domains {
			if _, ok := m[d]; !ok {
				m[d] = Destination{ID: e.id, Name: e.name, Category: e.cat}
			}
		}
	}
	return m
}()

// Classify devolve o destino de um nome consultado: o serviço conhecido (pelo
// nome inteiro ou por qualquer domínio pai), ou o domínio registrável.
func Classify(name string) Destination {
	n := strings.TrimSuffix(strings.ToLower(name), ".")
	for d := n; d != ""; {
		if dest, ok := byDomain[d]; ok {
			return dest
		}
		_, rest, ok := strings.Cut(d, ".")
		if !ok {
			break
		}
		d = rest
	}
	reg, ok := dnsname.Registrable(n)
	if !ok {
		reg = n
	}
	return Destination{ID: "d:" + reg, Name: reg, Category: CatOther}
}
