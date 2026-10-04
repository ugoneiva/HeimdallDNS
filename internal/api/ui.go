// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"errors"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// uiHandler serve o painel (SPA). Arquivos com hash no nome (assets/) ficam em
// cache para sempre; o index.html nunca, para pegar a versão nova.
func uiHandler(ui fs.FS) http.Handler {
	files := http.FileServerFS(ui)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeErr(w, http.StatusMethodNotAllowed, errors.New("método não permitido"))
			return
		}
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

		p := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if p == "" {
			p = "index.html"
		}
		if fi, err := fs.Stat(ui, p); err != nil || fi.IsDir() {
			p = "index.html" // rota do SPA
		}
		if strings.HasPrefix(p, "assets/") {
			h.Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			h.Set("Cache-Control", "no-cache")
		}
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/" + p
		if p == "index.html" {
			r2.URL.Path = "/" // FileServer redireciona /index.html para /
		}
		files.ServeHTTP(w, r2)
	})
}
