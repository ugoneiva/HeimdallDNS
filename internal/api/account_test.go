// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

var b64u = base64.RawURLEncoding

// softKey é um autenticador de software: uma passkey ES256 que assina como
// o navegador assinaria.
type softKey struct {
	key    *ecdsa.PrivateKey
	id     []byte
	handle []byte
	count  uint32
	origin string
	rpID   string
}

func newSoftKey(t *testing.T, origin string) *softKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	rand.Read(id)
	u, _ := url.Parse(origin)
	return &softKey{key: k, id: id, origin: origin, rpID: u.Hostname()}
}

func (k *softKey) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": k.origin, "crossOrigin": false})
	return b
}

func (k *softKey) authData(flags byte, attested []byte) []byte {
	rp := sha256.Sum256([]byte(k.rpID))
	out := append(rp[:], flags)
	out = binary.BigEndian.AppendUint32(out, k.count)
	return append(out, attested...)
}

// create responde ao navigator.credentials.create().
func (k *softKey) create(t *testing.T, options map[string]any) json.RawMessage {
	pk := options
	k.handle, _ = b64u.DecodeString(pk["user"].(map[string]any)["id"].(string))
	x, y := k.key.PublicKey.X.FillBytes(make([]byte, 32)), k.key.PublicKey.Y.FillBytes(make([]byte, 32))
	cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	if err != nil {
		t.Fatal(err)
	}
	att := make([]byte, 16) // AAGUID zerado
	att = binary.BigEndian.AppendUint16(att, uint16(len(k.id)))
	att = append(append(att, k.id...), cose...)
	ao, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": k.authData(0x45, att)})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{
		"id": b64u.EncodeToString(k.id), "rawId": b64u.EncodeToString(k.id), "type": "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64u.EncodeToString(k.clientData("webauthn.create", pk["challenge"].(string))),
			"attestationObject": b64u.EncodeToString(ao),
			"transports":        []string{"internal"},
		},
	})
	return b
}

// get responde ao navigator.credentials.get().
func (k *softKey) get(t *testing.T, options map[string]any) json.RawMessage {
	pk := options
	k.count++
	ad := k.authData(0x05, nil)
	cd := k.clientData("webauthn.get", pk["challenge"].(string))
	h := sha256.Sum256(cd)
	sum := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{
		"id": b64u.EncodeToString(k.id), "rawId": b64u.EncodeToString(k.id), "type": "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON": b64u.EncodeToString(cd), "authenticatorData": b64u.EncodeToString(ad),
			"signature": b64u.EncodeToString(sig), "userHandle": b64u.EncodeToString(k.handle),
		},
	})
	return b
}

// named fala com o painel por um nome (localhost), como exige o WebAuthn.
type named struct {
	p      *panel
	host   string
	origin string
	client *http.Client
}

func asLocalhost(p *panel) *named {
	u, _ := url.Parse(p.ts.URL)
	host := "localhost:" + u.Port()
	jar, _ := cookiejar.New(nil)
	return &named{p: p, host: host, origin: "http://" + host, client: &http.Client{Jar: jar}}
}

func (n *named) do(t *testing.T, method, path string, body any) (*http.Response, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, n.p.ts.URL+path, rd)
	req.Host = n.host
	req.Header.Set("Origin", n.origin)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Navegador de teste")
	resp, err := n.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil && len(raw) > 0 {
		var list []any
		json.Unmarshal(raw, &list)
		out = map[string]any{"list": list}
	}
	return resp, out
}

func TestRecoveryCodes(t *testing.T) {
	p := newPanel(t)
	login(t, p)
	_, out := p.do(t, "POST", "/api/auth/mfa/setup", "")
	secret := out["secret"].(string)
	code, _ := totpAt(secret, time.Now().Unix()/30)
	_, out = p.do(t, "POST", "/api/auth/mfa/enable", `{"code":"`+code+`"}`)
	codes, _ := out["recovery_codes"].([]any)
	if len(codes) != recoveryCount || len(codes[0].(string)) != 11 {
		t.Fatalf("códigos = %v", out)
	}
	if u, _ := p.api.Store.UserByName("admin"); len(u.MFA.Recovery) != recoveryCount || strings.Contains(strings.Join(u.MFA.Recovery, ""), codes[0].(string)) {
		t.Fatal("o banco guarda só os hashes")
	}
	p.do(t, "POST", "/api/auth/logout", "")
	first := strings.ToUpper(codes[0].(string)) // maiúsculas e hífen não importam
	if r, out := p.do(t, "POST", "/api/auth/login", `{"password":"senha-forte-1","code":"`+first+`"}`); r.StatusCode != 200 {
		t.Fatalf("login com código de recuperação: %v", out)
	}
	if _, st := p.do(t, "GET", "/api/auth/state", ""); st["user"].(map[string]any)["recovery_left"] != float64(recoveryCount-1) {
		t.Errorf("restantes = %v", st["user"])
	}
	p.do(t, "POST", "/api/auth/logout", "")
	if r, _ := p.do(t, "POST", "/api/auth/login", `{"password":"senha-forte-1","code":"`+first+`"}`); r.StatusCode != http.StatusUnauthorized {
		t.Error("código de recuperação vale uma vez só")
	}
	second := codes[1].(string)
	if r, _ := p.do(t, "POST", "/api/auth/login", `{"password":"senha-forte-1","code":"`+second+`"}`); r.StatusCode != 200 {
		t.Fatal("segundo código")
	}
	// Gerar de novo exige a segunda etapa; os antigos deixam de valer.
	if r, _ := p.do(t, "POST", "/api/auth/mfa/recovery", `{"code":"000000"}`); r.StatusCode != http.StatusForbidden {
		t.Error("gerar sem código válido")
	}
	next, _ := totpAt(secret, time.Now().Unix()/30+1)
	r, out := p.do(t, "POST", "/api/auth/mfa/recovery", `{"code":"`+next+`"}`)
	if r.StatusCode != 200 || len(out["recovery_codes"].([]any)) != recoveryCount {
		t.Fatalf("gerar de novo: %v", out)
	}
	p.do(t, "POST", "/api/auth/logout", "")
	if r, _ := p.do(t, "POST", "/api/auth/login", `{"password":"senha-forte-1","code":"`+codes[2].(string)+`"}`); r.StatusCode != http.StatusUnauthorized {
		t.Error("código da lista antiga ainda vale")
	}
	es, _ := p.api.Store.Audit(time.Now().Add(-time.Minute), 100)
	used := 0
	for _, e := range es {
		if e.Action == "auth.recovery_code" {
			used++
		}
	}
	if used != 2 {
		t.Errorf("uso de código de recuperação auditado %d vezes, quero 2", used)
	}
}

func TestSessionsPage(t *testing.T) {
	p := newPanel(t)
	login(t, p)
	other := asLocalhost(p)
	if r, out := other.do(t, "POST", "/api/auth/login", map[string]string{"password": "senha-forte-1"}); r.StatusCode != 200 {
		t.Fatalf("segundo login: %v", out)
	}
	_, out := p.do(t, "GET", "/api/auth/sessions", "")
	list := out["raw"]
	var sessions []map[string]any
	if s, ok := list.(string); ok {
		json.Unmarshal([]byte(s), &sessions)
	}
	if len(sessions) != 2 {
		t.Fatalf("sessões = %v", out)
	}
	var mine, theirs map[string]any
	for _, s := range sessions {
		if s["current"] == true {
			mine = s
		} else {
			theirs = s
		}
	}
	if mine == nil || theirs == nil || theirs["user_agent"] != "Navegador de teste" || theirs["method"] != "senha" || theirs["ip"] != "127.0.0.1" {
		t.Fatalf("sessões = %v", sessions)
	}
	if r, _ := p.do(t, "DELETE", "/api/auth/sessions/"+theirs["id"].(string), ""); r.StatusCode != http.StatusNoContent {
		t.Fatal("encerrar a outra sessão")
	}
	if r, _ := other.do(t, "GET", "/api/auth/state", nil); r.StatusCode != 200 {
		t.Fatal("estado")
	}
	if _, st := other.do(t, "GET", "/api/auth/state", nil); st["authenticated"] != false {
		t.Error("a sessão encerrada continua valendo")
	}
	if r, _ := p.do(t, "DELETE", "/api/auth/sessions/0123456789abcdef", ""); r.StatusCode != http.StatusNotFound {
		t.Error("sessão inexistente")
	}
	// "Sair dos outros lugares" mantém a atual.
	other.do(t, "POST", "/api/auth/login", map[string]string{"password": "senha-forte-1"})
	if r, out := p.do(t, "DELETE", "/api/auth/sessions", ""); r.StatusCode != 200 || out["ended"] != float64(1) {
		t.Fatalf("encerrar as outras: %v", out)
	}
	if r, _ := p.do(t, "GET", "/api/users/sessions", ""); r.StatusCode != 200 {
		t.Error("o admin vê todas as sessões")
	}
	// Um leitor não vê as sessões dos outros.
	viewer := store.User{Username: "leitor", Role: store.RoleViewer, Source: sourceLocal}
	viewer.PasswordHash, _ = hashPassword("senha-forte-2")
	if err := p.api.Store.SaveUser(&viewer); err != nil {
		t.Fatal(err)
	}
	v := asLocalhost(p)
	v.do(t, "POST", "/api/auth/login", map[string]string{"username": "leitor", "password": "senha-forte-2"})
	if r, _ := v.do(t, "GET", "/api/users/sessions", nil); r.StatusCode != http.StatusForbidden {
		t.Error("leitor viu as sessões de todos")
	}
	if r, _ := v.do(t, "DELETE", "/api/auth/sessions/"+mine["id"].(string), nil); r.StatusCode != http.StatusNotFound {
		t.Error("leitor encerrou a sessão do admin")
	}
}

func TestPasskeys(t *testing.T) {
	p := newPanel(t)
	login(t, p)
	n := asLocalhost(p)
	if r, out := n.do(t, "POST", "/api/auth/login", map[string]string{"password": "senha-forte-1"}); r.StatusCode != 200 {
		t.Fatalf("login: %v", out)
	}
	// Pelo IP não dá: o WebAuthn exige um nome.
	if r, out := p.do(t, "POST", "/api/auth/passkeys/begin", ""); r.StatusCode != http.StatusBadRequest || !strings.Contains(out["error"].(string), "IP") {
		t.Errorf("begin pelo IP: %d %v", r.StatusCode, out)
	}
	key := newSoftKey(t, n.origin)
	_, begin := n.do(t, "POST", "/api/auth/passkeys/begin", map[string]any{})
	cred := key.create(t, begin["options"].(map[string]any))
	r, out := n.do(t, "POST", "/api/auth/passkeys/finish", map[string]any{"challenge_id": begin["challenge_id"], "name": "Notebook", "credential": cred})
	if r.StatusCode != 200 {
		t.Fatalf("cadastrar: %v", out)
	}
	if len(out["passkeys"].([]any)) != 1 || len(out["recovery_codes"].([]any)) != recoveryCount {
		t.Fatalf("primeira passkey gera os códigos: %v", out)
	}
	// O mesmo desafio não serve duas vezes.
	if r, _ := n.do(t, "POST", "/api/auth/passkeys/finish", map[string]any{"challenge_id": begin["challenge_id"], "credential": cred}); r.StatusCode != http.StatusBadRequest {
		t.Error("desafio reusado")
	}

	// Senha certa agora pede a segunda etapa, com o desafio da passkey.
	n.do(t, "POST", "/api/auth/logout", nil)
	r, out = n.do(t, "POST", "/api/auth/login", map[string]string{"password": "senha-forte-1"})
	if r.StatusCode != http.StatusUnauthorized || out["mfa_required"] != true || out["passkey"] == nil {
		t.Fatalf("segunda etapa: %v", out)
	}
	ch := out["passkey"].(map[string]any)
	assertion := key.get(t, ch["options"].(map[string]any))
	r, out = n.do(t, "POST", "/api/auth/login", map[string]any{"password": "senha-forte-1", "passkey": map[string]any{"challenge_id": ch["challenge_id"], "credential": assertion}})
	if r.StatusCode != 200 {
		t.Fatalf("senha + passkey: %v", out)
	}
	// Assinatura de outra chave é recusada.
	n.do(t, "POST", "/api/auth/logout", nil)
	_, out = n.do(t, "POST", "/api/auth/login", map[string]string{"password": "senha-forte-1"})
	ch = out["passkey"].(map[string]any)
	fake := newSoftKey(t, n.origin)
	fake.id, fake.handle = key.id, key.handle
	if r, _ := n.do(t, "POST", "/api/auth/login", map[string]any{"password": "senha-forte-1", "passkey": map[string]any{"challenge_id": ch["challenge_id"], "credential": fake.get(t, ch["options"].(map[string]any))}}); r.StatusCode != http.StatusUnauthorized {
		t.Error("chave falsa entrou")
	}

	// Sem senha: o navegador escolhe a passkey.
	_, begin = n.do(t, "POST", "/api/auth/passkey/begin", nil)
	r, out = n.do(t, "POST", "/api/auth/passkey/login", map[string]any{"challenge_id": begin["challenge_id"], "credential": key.get(t, begin["options"].(map[string]any))})
	if r.StatusCode != 200 {
		t.Fatalf("login sem senha: %v", out)
	}
	_, st := n.do(t, "GET", "/api/auth/state", nil)
	if st["user"].(map[string]any)["passkeys"] != float64(1) {
		t.Errorf("estado = %v", st["user"])
	}
	_, out = n.do(t, "GET", "/api/auth/sessions", nil)
	methods := []string{}
	for _, s := range out["list"].([]any) {
		methods = append(methods, s.(map[string]any)["method"].(string))
	}
	if !strings.Contains(strings.Join(methods, ","), "passkey") {
		t.Errorf("métodos das sessões = %v", methods)
	}
	u, _ := p.api.Store.UserByName("admin")
	if u.MFA.Passkeys[0].LastUsed.IsZero() {
		t.Error("último uso da passkey")
	}

	// Apagar a passkey.
	if r, _ := n.do(t, "DELETE", "/api/auth/passkeys/"+u.MFA.Passkeys[0].ID, nil); r.StatusCode != 200 {
		t.Fatal("apagar")
	}
	if u, _ := p.api.Store.UserByName("admin"); u.MFA.Strong() || len(u.MFA.Recovery) != 0 {
		t.Error("sem segunda etapa, os códigos de recuperação somem")
	}
}
