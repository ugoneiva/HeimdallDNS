package detect

import "testing"

// Rótulos registrados de sites e serviços comuns (inclusive brasileiros e de
// CDNs/telemetria): nenhum pode parecer gerado.
var benign = []string{
	"google", "facebook", "youtube", "wikipedia", "instagram", "whatsapp", "microsoft", "windowsupdate",
	"googleusercontent", "googlesyndication", "doubleclick", "cloudflare", "cloudfront", "amazonaws",
	"akamaiedge", "akamaized", "mercadolivre", "mercadopago", "americanas", "magazineluiza", "bradesco",
	"itau", "santander", "caixa", "bancodobrasil", "nubank", "globo", "uol", "terra", "estadao",
	"folha", "netflix", "spotify", "steampowered", "steamcommunity", "office365", "microsoftonline",
	"live", "outlook", "linkedin", "twitter", "tiktokcdn", "tiktokv", "bytedance", "apple", "icloud",
	"mzstatic", "gstatic", "googleapis", "ggpht", "ytimg", "fbcdn", "githubusercontent", "github",
	"stackoverflow", "reddit", "redditstatic", "discordapp", "telegram", "whatsapp", "zoom", "slack",
	"salesforce", "hubspot", "segment", "mixpanel", "sentry", "newrelic", "datadoghq", "hotjar",
	"criteo", "taboola", "outbrain", "adnxs", "rubiconproject", "pubmatic", "openx", "smartadserver",
	"scorecardresearch", "quantserve", "chartbeat", "optimizely", "wazuh", "fortinet", "paloaltonetworks",
	"crowdstrike", "sentinelone", "bitdefender", "kaspersky", "malwarebytes", "trendmicro", "sophos",
	"e5", "avast", "mcafee", "symantec", "digicert", "letsencrypt", "sectigo", "globalsign",
	"xboxlive", "playstation", "nintendo", "epicgames", "riotgames", "roblox", "rbxcdn", "twitch",
	"jtvnw", "ttvnw", "duckduckgo", "bing", "yahoo", "baidu", "yandex", "naver", "1e100", "t-mobile",
	"vivo", "claro", "oi", "tim", "netflix", "nflxvideo", "nflxso", "primevideo", "disneyplus",
	"hbomax", "globoplay", "crunchyroll", "deezer", "soundcloud", "shopee", "aliexpress", "alicdn",
	"temu", "shein", "ifood", "rappi", "uber", "99app", "waze", "booking", "airbnb", "decolar",
	"receita", "gov", "serpro", "dataprev", "detran", "jusbrasil", "stf", "tse", "bradesco", "itau",
	"natura", "ambev", "embraer", "totvs", "localiza", "petrobras",
}

// Amostras no estilo de famílias de DGA conhecidas (Conficker, Cryptolocker,
// Necurs, Ramnit, Pykspa, Murofet, Bamital, Banjori…).
var generated = []string{
	"xjwqmzkdpqrv", "qmklcwprgtbn", "ydqtkptuwsa", "kdkbjtsdqxdn", "bvqvoxpfjeyhbn", "wbkwbxdmpgfdhq",
	"nmjskpgbujcrdb", "hhutvfscqvcke", "fxpvpgjrqvwq", "lzmqkyshfntwc", "tkfrqgjvtmybk", "cvyhbsnxwgqrt",
	"pzrbkwxqvnlj", "a3f9e2c7b1d8", "x9k2m7q4p8z1", "dbf7c2a91e6f4", "q7h3n9w2k5x8r", "k2j9x7q4m1z8",
	"rghxkpwnqtlz", "mkfjvbqyzxcw", "vgxqwkfjzhpy", "jxqzvbkwmfyp", "earnestnessbiophysicalohax", "ohxaeqgkkfwmhfvt",
}

func TestDGAScore(t *testing.T) {
	for _, l := range benign {
		if s := DGAScore(l); s >= dgaThreshold {
			t.Errorf("benigno %q pontuou %.2f", l, s)
		}
	}
	misses := 0
	for _, l := range generated {
		if s := DGAScore(l); s < dgaThreshold {
			misses++
			t.Logf("não pegou %q (%.2f)", l, s)
		}
	}
	// Heurística: aceita perder poucos (nomes de DGA baseada em dicionário,
	// como "earnestnessbiophysicalohax", parecem palavras de propósito).
	if misses > 1 {
		t.Errorf("%d de %d amostras de DGA não foram reconhecidas", misses, len(generated))
	}
}
