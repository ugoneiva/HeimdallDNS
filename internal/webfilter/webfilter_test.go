// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package webfilter

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCatalogValid(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Catalog {
		if seen[c.ID] || c.Name == "" || (len(c.Sources) == 0 && len(c.Rules) == 0) {
			t.Errorf("categoria mal definida: %+v", c)
		}
		seen[c.ID] = true
		for _, s := range c.Sources {
			if !strings.HasPrefix(s.URL, "https://") || s.License == "" {
				t.Errorf("%s: fonte sem https ou sem licença: %+v", c.ID, s)
			}
		}
	}
	if id, ok := Valid([]string{"adulto", "nada"}); ok || id != "nada" {
		t.Error("Valid")
	}
}

func TestSafeSearch(t *testing.T) {
	for name, want := range map[string]string{
		"www.google.com":          googleSafe,
		"google.com.br.":          googleSafe,
		"www.google.co.uk":        googleSafe,
		"mail.google.com":         "",
		"www.youtube.com":         youtubeStrict,
		"youtubei.googleapis.com": youtubeStrict,
		"www.bing.com":            bingSafe,
		"duckduckgo.com":          duckSafe,
		"exemplo.com":             "",
	} {
		if got := SafeSearchTarget(name, "strict"); got != want {
			t.Errorf("%s = %q, quero %q", name, got, want)
		}
	}
	if SafeSearchTarget("m.youtube.com", "moderate") != youtubeModerat {
		t.Error("modo moderado do YouTube")
	}
	m := New(Options{CacheDir: t.TempDir()})
	if m.SafeSearch("www.google.com", true, false) != "" {
		t.Error("desligado: não deveria redirecionar")
	}
	if m.SafeSearch("www.google.com", false, true) != googleSafe {
		t.Error("ligado no grupo")
	}
	m.SetSettings(Settings{SafeSearch: true})
	if m.SafeSearch("www.google.com", true, false) != googleSafe || m.SafeSearch("www.google.com", false, false) != "" {
		t.Error("global (e aparelho fora das listas globais)")
	}
}

func TestCategoriesLoadOnlyUsed(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch {
		case strings.HasSuffix(r.URL.Path, "/ut1"):
			fmt.Fprintln(w, "jogo-ut1.com") // formato UT1: vale com os subdomínios
		default:
			fmt.Fprintln(w, "||aposta.com^\nexato.net")
		}
	}))
	defer srv.Close()
	old := Catalog
	defer func() { Catalog = old }()
	Catalog = []Category{
		{ID: "apostas", Name: "Apostas", Sources: []Source{{Name: "A", URL: srv.URL + "/a", License: "x"}}},
		{ID: "jogos", Name: "Jogos", Rules: []string{"service:jogos"}, Sources: []Source{{Name: "U", URL: srv.URL + "/ut1", License: "x", Wildcard: true}}},
		{ID: "adulto", Name: "Adulto", Sources: []Source{{Name: "B", URL: srv.URL + "/b", License: "x"}}},
	}
	m := New(Options{CacheDir: t.TempDir()})
	if err := m.SetSettings(Settings{Global: []string{"apostas"}}); err != nil {
		t.Fatal(err)
	}
	m.SetUsed([]string{"apostas", "jogos"})
	m.reload(context.Background(), false)
	if hits.Load() != 2 {
		t.Errorf("só as usadas devem baixar: %d downloads", hits.Load())
	}
	cases := []struct {
		name   string
		global bool
		extra  []string
		block  bool
		cat    string
	}{
		{"www.aposta.com", true, nil, true, "apostas"},
		{"www.aposta.com", false, nil, false, ""}, // aparelho fora das listas globais
		{"exato.net", true, nil, true, "apostas"},
		{"sub.exato.net", true, nil, false, ""},
		{"x.jogo-ut1.com", false, []string{"jogos"}, true, "jogos"}, // UT1: subdomínio vale
		{"www.roblox.com", false, []string{"jogos"}, true, "jogos"}, // catálogo interno
		{"www.roblox.com", true, nil, false, ""},
		{"porn.example", true, []string{"adulto"}, false, ""}, // categoria não carregada
	}
	for _, c := range cases {
		_, cat, block := m.Check(c.name, c.global, c.extra)
		if block != c.block || cat != c.cat {
			t.Errorf("%s (global=%v extra=%v) = %v %s", c.name, c.global, c.extra, block, cat)
		}
	}
	st := m.Status()
	if !st["apostas"].Loaded || st["apostas"].Rules != 2 || st["jogos"].Rules < 2 {
		t.Errorf("status = %+v", st)
	}
	// Tirar de uso libera a memória (e não baixa de novo o que já tinha).
	m.SetUsed([]string{"jogos"})
	m.reload(context.Background(), false)
	if _, ok := m.Status()["apostas"]; ok {
		t.Error("categoria fora de uso deveria sair")
	}
	if _, _, b := m.Check("www.aposta.com", true, nil); b {
		t.Error("descarregada não bloqueia")
	}
	if hits.Load() != 2 {
		t.Errorf("recarregar o que já estava na memória não baixa: %d", hits.Load())
	}
	if m.SetSettings(Settings{Global: []string{"inexistente"}}) == nil {
		t.Error("categoria inválida")
	}
}

func TestStaleCacheIsRefreshedOnStart(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		fmt.Fprintln(w, "||velho.test^")
	}))
	defer srv.Close()
	old := Catalog
	defer func() { Catalog = old }()
	Catalog = []Category{{ID: "x", Name: "X", Sources: []Source{{Name: "s", URL: srv.URL, License: "x"}}}}
	dir := t.TempDir()
	start := func() {
		m := New(Options{CacheDir: dir, Interval: time.Hour})
		m.SetUsed([]string{"x"})
		m.reload(context.Background(), false)
	}
	start() // sem cópia: baixa
	start() // cópia nova: não baixa
	if hits.Load() != 1 {
		t.Fatalf("downloads = %d, quero 1", hits.Load())
	}
	// Cópia com mais de 1 h (o intervalo): a partida seguinte baixa de novo.
	files, _ := filepath.Glob(filepath.Join(dir, "web-*.txt"))
	past := time.Now().Add(-2 * time.Hour)
	os.Chtimes(files[0], past, past)
	start()
	if hits.Load() != 2 {
		t.Errorf("cópia vencida deveria ser baixada de novo: %d downloads", hits.Load())
	}
}
