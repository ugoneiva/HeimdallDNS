package dnsname

import "testing"

func TestRegistrable(t *testing.T) {
	cases := map[string]string{
		"www.exemplo.com.br.":           "exemplo.com.br",
		"exemplo.com":                   "exemplo.com",
		"a.b.c.exemplo.co.uk":           "exemplo.co.uk",
		"d111111abcdef8.cloudfront.net": "cloudfront.net",
		"usuario.github.io":             "github.io",
		"x.s3.us-east-1.amazonaws.com":  "amazonaws.com",
		"WWW.Google.COM":                "google.com",
		"localhost":                     "",
		"kjhgfdsazx":                    "",
		"1.0.168.192.in-addr.arpa":      "",
		"com":                           "",
		"co.uk":                         "",
		"nas.casa":                      "nas.casa", // .casa é um gTLD de verdade
		"nas.home.arpa":                 "",
		"impressora.lan":                "",
	}
	for in, want := range cases {
		got, ok := Registrable(in)
		if got != want || ok != (want != "") {
			t.Errorf("Registrable(%q) = %q, %v; quero %q", in, got, ok, want)
		}
	}
}

func TestSplit(t *testing.T) {
	d, l, s, ok := Split("www.mail.exemplo.com.br.")
	if !ok || d != "exemplo.com.br" || l != "exemplo" || s != "www.mail" {
		t.Errorf("Split = %q %q %q %v", d, l, s, ok)
	}
	if _, _, s, _ := Split("exemplo.com"); s != "" {
		t.Errorf("sem subdomínio: %q", s)
	}
}
