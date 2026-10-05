// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package webui

import (
	"io/fs"
	"regexp"
	"testing"
)

// O index.html embutido só serve se todo JS/CSS que ele chama também foi
// embutido. Sem isso o painel abre preto (a v0.1.0 saiu assim: os assets
// ficaram fora do git e o binário levou só o index.html).
func TestAssetsDoIndexEstaoEmbutidos(t *testing.T) {
	sub := FS()
	if sub == nil {
		t.Fatal("painel não embutido: rode 'make web'")
	}
	html, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	refs := regexp.MustCompile(`(?:src|href)="/([^"]+)"`).FindAllStringSubmatch(string(html), -1)
	if len(refs) == 0 {
		t.Fatal("index.html sem referências a assets")
	}
	for _, m := range refs {
		if _, err := fs.Stat(sub, m[1]); err != nil {
			t.Errorf("index.html chama /%s, que não está embutido", m[1])
		}
	}
}
