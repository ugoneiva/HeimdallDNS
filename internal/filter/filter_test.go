// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package filter

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleList = `# lista de teste
! comentário Adblock
[Adblock Plus 2.0]
0.0.0.0 ads.example.com
127.0.0.1 tracker.example.net   # comentário no fim
0.0.0.0 localhost
0.0.0.0 multi1.test multi2.test
plain.example.org
*.wild.example
||adblock.example^
||important.example^$important
||thirdparty.example^$third-party
@@||ok.adblock.example^
/^ad[0-9]+\.regex\.test$/
isto não é domínio!
0.0.0.0 1.2.3.4
`

func build(t *testing.T) *Matcher {
	t.Helper()
	b := NewBuilder()
	st, err := b.AddList(strings.NewReader(sampleList))
	if err != nil {
		t.Fatal(err)
	}
	if st.Rules != 9 {
		t.Errorf("regras = %d, quero 9", st.Rules)
	}
	if st.Invalid != 2 { // $third-party e a frase
		t.Errorf("inválidas = %d, quero 2", st.Invalid)
	}
	b.AddLine("@@plain.example.org", false)
	return b.Build()
}

func TestMatch(t *testing.T) {
	m := build(t)
	cases := []struct {
		name string
		want Verdict
	}{
		{"ads.example.com.", Blocked},
		{"ADS.Example.COM", Blocked},  // caixa não importa
		{"sub.ads.example.com", Pass}, // hosts vale só para o nome exato
		{"tracker.example.net", Blocked},
		{"multi2.test", Blocked},
		{"localhost", Pass},
		{"wild.example", Blocked},
		{"a.b.wild.example", Blocked},
		{"adblock.example", Blocked},
		{"x.adblock.example", Blocked},
		{"ok.adblock.example", Allowed}, // exceção vence
		{"y.ok.adblock.example", Allowed},
		{"important.example", Blocked},
		{"thirdparty.example", Pass},
		{"ad42.regex.test", Blocked},
		{"adx.regex.test", Pass},
		{"plain.example.org", Allowed},
		{"example.com", Pass},
	}
	for _, c := range cases {
		if got := m.Match(c.name).Verdict; got != c.want {
			t.Errorf("Match(%q) = %v, quero %v", c.name, got, c.want)
		}
	}
	if r := m.Match("x.adblock.example"); r.Rule != "||adblock.example^" {
		t.Errorf("regra = %q", r.Rule)
	}
}

func TestUserRulesWildcard(t *testing.T) {
	b := NewBuilder()
	b.AddLine("facebook.com", true)
	m := b.Build()
	if m.Match("www.facebook.com").Verdict != Blocked {
		t.Error("regra própria simples deveria valer para subdomínios")
	}
	if m.Match("notfacebook.com").Verdict != Pass {
		t.Error("não pode casar por pedaço de rótulo")
	}
}

func TestDomainSet(t *testing.T) {
	s := newDomainSet([]string{"b.com", "a.com", "c.com", "a.com"})
	if s.Len() != 3 {
		t.Fatalf("Len = %d", s.Len())
	}
	for _, d := range []string{"a.com", "b.com", "c.com"} {
		if !s.has(d) {
			t.Errorf("faltou %s", d)
		}
	}
	if s.has("d.com") || s.has("") {
		t.Error("achou o que não existe")
	}
	if (domainSet{}).has("a.com") {
		t.Error("conjunto vazio")
	}
}

func TestNilMatcher(t *testing.T) {
	var m *Matcher
	if m.Match("a.com").Verdict != Pass {
		t.Error("Matcher nil deve deixar passar")
	}
}

func BenchmarkMatch(b *testing.B) {
	bl := NewBuilder()
	var sb strings.Builder
	for i := range 500_000 {
		sb.WriteString("0.0.0.0 host")
		sb.WriteString(strings.Repeat("x", i%7))
		sb.WriteString(".dominio")
		sb.WriteString(string(rune('a' + i%26)))
		sb.WriteString(".com\n")
	}
	if _, err := bl.AddList(strings.NewReader(sb.String())); err != nil {
		b.Fatal(err)
	}
	m := bl.Build()
	b.ResetTimer()
	for b.Loop() {
		m.Match("um.subdominio.qualquer.exemplo.com.br.")
	}
}

func TestStartRemovesStaleDownloads(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, ".baixando-123")
	os.WriteFile(stale, []byte("pela metade"), 0o600)
	m := NewManager(ManagerOptions{CacheDir: dir, Logger: slog.New(slog.DiscardHandler)})
	m.Start(t.Context())
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("o temporário de download interrompido deveria ter sido apagado")
	}
}

func TestThreatCategory(t *testing.T) {
	b := NewBuilder()
	b.AddList(strings.NewReader("0.0.0.0 ads.exemplo.com\n"))
	b.AddThreatList(strings.NewReader("||c2.malware.test^\n@@||ok.malware.test^\n"))
	b.AddLine("ads2.exemplo.com", false)
	m := b.Build()
	if r := m.Match("x.c2.malware.test"); r.Verdict != Blocked || r.Category != CategoryThreat {
		t.Errorf("ameaça = %+v", r)
	}
	if r := m.Match("ads.exemplo.com"); r.Verdict != Blocked || r.Category != "" {
		t.Errorf("anúncio = %+v", r)
	}
	if r := m.Match("ads2.exemplo.com"); r.Category != "" {
		t.Errorf("depois da lista de ameaças, o modo volta ao normal: %+v", r)
	}
	if r := m.Match("ok.malware.test"); r.Verdict != Allowed {
		t.Errorf("exceção em lista de ameaças vale: %+v", r)
	}
	if blk, _ := m.Rules(); blk != 3 {
		t.Errorf("regras = %d", blk)
	}
}
