// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package tlsconf

import (
	"crypto/tls"
	"os"
	"testing"
)

func TestSelfSigned(t *testing.T) {
	dir := t.TempDir()
	c1, k1, err := SelfSigned(dir)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(c1, k1)
	if err != nil || pair.Leaf == nil || pair.Leaf.VerifyHostname("localhost") != nil {
		t.Fatalf("certificado: %v", err)
	}
	before, _ := os.ReadFile(c1)
	SelfSigned(dir)
	after, _ := os.ReadFile(c1)
	if string(before) != string(after) {
		t.Error("um certificado válido não deve ser trocado")
	}
	if fi, _ := os.Stat(k1); fi.Mode().Perm() != 0o600 {
		t.Error("a chave tem que ser 600")
	}
}
