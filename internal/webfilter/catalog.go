// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

// Package webfilter é o filtro web por categorias (adulto, apostas, redes
// sociais…): cada categoria junta listas públicas gratuitas e/ou serviços do
// catálogo interno, e pode valer para todos, para um grupo ou num horário.
// Também força a busca segura (SafeSearch) nos buscadores e no YouTube.
package webfilter

// Source é uma lista pública usada por uma categoria.
type Source struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	License  string `json:"license"`
	Homepage string `json:"homepage"`
	// Wildcard: domínio simples vale também para os subdomínios (listas no
	// formato do SquidGuard, como a UT1). Nas outras, o formato da própria
	// linha decide (||dominio^ = com subdomínios; dominio = só ele).
	Wildcard bool `json:"-"`
}

// Category é uma categoria do filtro web.
type Category struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Icon        string   `json:"icon"`
	Sources     []Source `json:"sources"`
	// Rules são regras do catálogo interno (ex.: service:social), sem download.
	Rules []string `json:"rules,omitempty"`
}

var (
	hagezi = func(name, file string) Source {
		return Source{Name: "HaGeZi " + name, URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/" + file,
			License: "GPL-3.0", Homepage: "https://github.com/hagezi/dns-blocklists"}
	}
	blp = func(name, file string) Source {
		return Source{Name: "Block List Project " + name, URL: "https://blocklistproject.github.io/Lists/alt-version/" + file,
			License: "Unlicense (domínio público)", Homepage: "https://blocklistproject.github.io/Lists/"}
	}
	ut1 = func(name, cat string) Source {
		return Source{Name: "UT1 " + name, URL: "https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/" + cat + "/domains",
			License: "CC BY-SA 4.0 (Université Toulouse Capitole)", Homepage: "https://dsi.ut-capitole.fr/blacklists/", Wildcard: true}
	}
)

// Catalog são as categorias disponíveis. As fontes foram escolhidas pela
// qualidade, pela atualização frequente e pelo tamanho (as versões "medium" e
// "mini" da HaGeZi cabem num Raspberry Pi).
var Catalog = []Category{
	{ID: "adulto", Name: "Adulto", Icon: "adult", Description: "Pornografia e conteúdo sexual explícito.",
		Sources: []Source{hagezi("NSFW", "nsfw.txt")}},
	{ID: "apostas", Name: "Apostas", Icon: "gambling", Description: "Cassinos, bets e apostas esportivas.",
		Sources: []Source{hagezi("Gambling (medium)", "gambling.medium.txt")}},
	{ID: "ameacas", Name: "Ameaças", Icon: "threat", Description: "Malware, phishing, C2 e golpes conhecidos (seleção essencial).",
		Sources: []Source{hagezi("Threat Intelligence (mini)", "tif.mini.txt")}},
	{ID: "golpes", Name: "Golpes e lojas falsas", Icon: "scam", Description: "Lojas falsas, fraudes e sites enganosos.",
		Sources: []Source{hagezi("Fake", "fake.txt")}},
	{ID: "pirataria", Name: "Pirataria e torrent", Icon: "piracy", Description: "Sites de pirataria, IPTV irregular e torrent.",
		Sources: []Source{hagezi("Anti-Piracy", "anti.piracy.txt"), blp("Torrent", "torrent-nl.txt")}},
	{ID: "bypass", Name: "VPN, proxy e DNS alternativo", Icon: "bypass",
		Description: "Serviços usados para contornar o filtro: DoH, VPNs, proxies e Tor.",
		Sources:     []Source{hagezi("DoH/VPN/Proxy bypass", "doh-vpn-proxy-bypass.txt")}},
	{ID: "redes-sociais", Name: "Redes sociais", Icon: "social", Description: "Facebook, Instagram, TikTok, X, Snapchat, Reddit e outras.",
		Rules: []string{"service:social"}, Sources: []Source{ut1("Social networks", "social_networks")}},
	{ID: "mensagens", Name: "Mensagens", Icon: "messaging", Description: "WhatsApp, Telegram e Discord.",
		Rules: []string{"service:mensagens"}},
	{ID: "streaming", Name: "Vídeo e streaming", Icon: "streaming", Description: "YouTube, Netflix, Twitch e outros.",
		Rules: []string{"service:streaming"}},
	{ID: "jogos", Name: "Jogos", Icon: "games", Description: "Jogos online, lojas e plataformas de jogos.",
		Rules: []string{"service:jogos"}, Sources: []Source{ut1("Games", "games")}},
	{ID: "namoro", Name: "Namoro", Icon: "dating", Description: "Sites e apps de relacionamento.",
		Sources: []Source{ut1("Dating", "dating")}},
	{ID: "drogas", Name: "Drogas", Icon: "drugs", Description: "Venda e apologia de drogas.",
		Sources: []Source{blp("Drugs", "drugs-nl.txt")}},
	{ID: "cripto", Name: "Cripto e mineração", Icon: "crypto", Description: "Mineração no navegador e golpes com criptomoedas.",
		Sources: []Source{blp("Crypto", "crypto-nl.txt")}},
	{ID: "encurtadores", Name: "Encurtadores de link", Icon: "shortener", Description: "bit.ly e afins (escondem o destino real do link).",
		Sources: []Source{ut1("Shortener", "shortener")}},
}

// Find devolve a categoria pelo id.
func Find(id string) (Category, bool) {
	for _, c := range Catalog {
		if c.ID == id {
			return c, true
		}
	}
	return Category{}, false
}

// Valid diz se todos os ids existem; devolve o primeiro inválido.
func Valid(ids []string) (string, bool) {
	for _, id := range ids {
		if _, ok := Find(id); !ok {
			return id, false
		}
	}
	return "", true
}
