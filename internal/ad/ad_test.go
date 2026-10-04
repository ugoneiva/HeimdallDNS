// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package ad

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/miekg/dns"
)

// Bytes reais gravados pelo AD (Samba) no laboratório.
const (
	realA  = "0400010005f00000010000000000038400000000000000000a4d000a"                                             // dc01 A 10.77.0.10, TTL 900
	realNS = "1a00020005f000000100000000000384000000000000000018040464633031036c6162086865696d64616c6c047465737400" // NS dc01.lab.heimdall.test.
)

func TestRecordFormat(t *testing.T) {
	a, _ := hex.DecodeString(realA)
	rec, ok := decodeRecord(a)
	if !ok || rec.Type != "A" || rec.Data != "10.77.0.10" || rec.TTL != 900 || !rec.Static {
		t.Errorf("A real = %+v", rec)
	}
	if got := hex.EncodeToString(encodeRecord(typeA, []byte{10, 77, 0, 10}, 900, 1)); got != realA {
		t.Errorf("codificação A:\n%s\n%s", got, realA)
	}
	ns, _ := hex.DecodeString(realNS)
	rec, ok = decodeRecord(ns)
	if !ok || rec.Type != "NS" || rec.Data != "dc01.lab.heimdall.test." {
		t.Errorf("NS real = %+v", rec)
	}
	name, _ := encodeName("dc01.lab.heimdall.test")
	if got := hex.EncodeToString(encodeRecord(typeNS, name, 900, 1)); got != realNS {
		t.Errorf("codificação de nome:\n%s\n%s", got, realNS)
	}
	if hex.EncodeToString(encodePassword("Aé1")) != "22004100e90031002200" {
		t.Errorf("unicodePwd = %x", encodePassword("Aé1"))
	}
}

func TestFileTime(t *testing.T) {
	if got := fileTime("133000000000000000"); got.Year() != 2022 {
		t.Errorf("FILETIME = %v", got)
	}
	if !fileTime("0").IsZero() || !fileTime("9223372036854775807").IsZero() {
		t.Error("zero e 'nunca' devem virar data vazia")
	}
}

// --- integração com o AD de laboratório ---
// HEIMDALL_AD_TEST_URL=ldaps://127.0.0.1:2636 HEIMDALL_AD_TEST_PASS_FILE=… HEIMDALL_AD_TEST_DNS=127.0.0.1:2653

func lab(t *testing.T) (*Client, *ldap.Conn, string) {
	t.Helper()
	url, pf := os.Getenv("HEIMDALL_AD_TEST_URL"), os.Getenv("HEIMDALL_AD_TEST_PASS_FILE")
	if url == "" || pf == "" {
		t.Skip("AD de laboratório não configurado (HEIMDALL_AD_TEST_URL / HEIMDALL_AD_TEST_PASS_FILE)")
	}
	pw, err := os.ReadFile(pf)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := ldap.DialURL(url, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	if err := admin.Bind("Administrator@lab.heimdall.test", strings.TrimSpace(string(pw))); err != nil {
		t.Fatal(err)
	}
	base := "DC=lab,DC=heimdall,DC=test"
	// Fixtures: OU liberada, OU fora, grupo liberado e grupo não liberado.
	for _, dn := range []string{"OU=Heimdall," + base, "OU=Fora," + base} {
		add := ldap.NewAddRequest(dn, nil)
		add.Attribute("objectClass", []string{"top", "organizationalUnit"})
		if err := admin.Add(add); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
			t.Fatal(err)
		}
	}
	for _, g := range []string{"VPN-Usuarios", "Financeiro"} {
		add := ldap.NewAddRequest("CN="+g+",OU=Heimdall,"+base, nil)
		add.Attribute("objectClass", []string{"top", "group"})
		add.Attribute("sAMAccountName", []string{g})
		if err := admin.Add(add); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
			t.Fatal(err)
		}
	}
	c, err := New(Options{URL: url, BindUser: "Administrator@lab.heimdall.test", BindPassword: strings.TrimSpace(string(pw)),
		InsecureTLS: true, Write: true, UserOUs: []string{"OU=Heimdall," + base}, ManagedGroups: []string{"VPN-Usuarios", "Domain Admins"},
		DNSZones: []string{"lab.heimdall.test"}})
	if err != nil {
		t.Fatal(err)
	}
	return c, admin, base
}

func TestLabUsersAndGroups(t *testing.T) {
	c, admin, base := lab(t)
	ctx := context.Background()
	info, err := c.Check(ctx)
	if err != nil || info.Vendor != "Samba" || info.Domain != "lab.heimdall.test" {
		t.Fatalf("Check = %+v, %v", info, err)
	}
	ou := "OU=Heimdall," + base
	_ = c.DeleteUser(ctx, "teste.heimdall") // sobra de execução anterior

	// Senha fraca: recusada e sem deixar conta pela metade.
	if _, err := c.CreateUser(ctx, NewUser{OU: ou, SAM: "teste.heimdall", GivenName: "Teste", Surname: "Heimdall", Password: "123", Enabled: true}); err == nil {
		t.Fatal("senha fraca deveria ser recusada")
	}
	if _, err := c.User(ctx, "teste.heimdall"); err == nil {
		t.Fatal("a criação com senha recusada deveria ter sido desfeita")
	}
	// OU fora da lista.
	if _, err := c.CreateUser(ctx, NewUser{OU: "OU=Fora," + base, SAM: "fora.x", Password: "Senha-Forte-123!"}); err == nil {
		t.Error("OU não liberada deveria ser recusada")
	}
	u, err := c.CreateUser(ctx, NewUser{OU: ou, SAM: "teste.heimdall", GivenName: "Teste", Surname: "Heimdall",
		Mail: "teste@lab.heimdall.test", Password: "Senha-Forte-123!", MustChange: true, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if !u.Enabled || !u.Manageable || u.UPN != "teste.heimdall@lab.heimdall.test" || u.DisplayName != "Teste Heimdall" || !u.PwdLastSet.IsZero() {
		t.Errorf("criado = %+v", u)
	}
	// A senha funciona de verdade: o usuário consegue autenticar (deve trocar no 1º logon: o bind falha com 773).
	ul, _ := ldap.DialURL(os.Getenv("HEIMDALL_AD_TEST_URL"), ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	if err := ul.Bind("teste.heimdall@lab.heimdall.test", "Senha-Forte-123!"); err == nil || !strings.Contains(err.Error(), "773") && !strings.Contains(err.Error(), "data") {
		t.Logf("bind com troca obrigatória: %v", err)
	}
	ul.Close()

	if u, err = c.SetEnabled(ctx, "teste.heimdall", false); err != nil || u.Enabled {
		t.Errorf("desabilitar: %+v %v", u, err)
	}
	if u, err = c.SetEnabled(ctx, "teste.heimdall", true); err != nil || !u.Enabled {
		t.Errorf("habilitar: %+v %v", u, err)
	}
	if u, err = c.ResetPassword(ctx, "teste.heimdall", "Outra-Senha-456!", false); err != nil || u.PwdLastSet.IsZero() {
		t.Errorf("reset: %+v %v", u, err)
	}
	ul, _ = ldap.DialURL(os.Getenv("HEIMDALL_AD_TEST_URL"), ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	if err := ul.Bind("teste.heimdall@lab.heimdall.test", "Outra-Senha-456!"); err != nil {
		t.Errorf("a senha nova deveria autenticar: %v", err)
	}
	ul.Close()
	if _, err := c.Unlock(ctx, "teste.heimdall"); err != nil {
		t.Errorf("desbloquear: %v", err)
	}

	// Grupos: liberado sim; não liberado e privilegiado (mesmo na lista) não.
	g, err := c.SetMembership(ctx, "VPN-Usuarios", "teste.heimdall", true)
	if err != nil || g.Members != 1 {
		t.Errorf("entrar no grupo: %+v %v", g, err)
	}
	if u, _ := c.User(ctx, "teste.heimdall"); len(u.Groups) != 1 || u.Groups[0] != "VPN-Usuarios" {
		t.Errorf("memberOf = %v", u.Groups)
	}
	if _, err := c.SetMembership(ctx, "Financeiro", "teste.heimdall", true); err == nil {
		t.Error("grupo não liberado")
	}
	if _, err := c.SetMembership(ctx, "Domain Admins", "teste.heimdall", true); err == nil || !strings.Contains(err.Error(), "privilegiado") {
		t.Errorf("Domain Admins deveria ser bloqueado mesmo na lista: %v", err)
	}
	if g, err := c.SetMembership(ctx, "VPN-Usuarios", "teste.heimdall", false); err != nil || g.Members != 0 {
		t.Errorf("sair do grupo: %+v %v", g, err)
	}
	// Conta privilegiada e fora das OUs.
	if _, err := c.ResetPassword(ctx, "Administrator", "Qualquer-123!", false); err == nil {
		t.Error("Administrator nunca pode ser alterado")
	}
	us, err := c.Users(ctx, "teste", 10)
	if err != nil || len(us) != 1 {
		t.Errorf("busca: %d %v", len(us), err)
	}
	gs, _ := c.Groups(ctx, "admins", 50)
	for _, g := range gs {
		if g.Name == "Domain Admins" && (g.Managed || !g.Privileged) {
			t.Errorf("Domain Admins = %+v", g)
		}
	}
	if err := c.DeleteUser(ctx, "teste.heimdall"); err != nil {
		t.Errorf("excluir: %v", err)
	}
	_ = admin
}

func TestLabDNS(t *testing.T) {
	c, _, _ := lab(t)
	ctx := context.Background()
	zs, err := c.Zones(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, z := range zs {
		if z.Name == "lab.heimdall.test" {
			found = z.Editable
		}
		if strings.HasPrefix(z.Name, "_msdcs") && z.Editable {
			t.Error("_msdcs nunca é editável")
		}
	}
	if !found {
		t.Fatalf("zona do laboratório não editável: %+v", zs)
	}
	z := "lab.heimdall.test"
	for _, n := range []string{"dc01", "DomainDnsZones", "ForestDnsZones", "gc"} {
		if err := c.DeleteRecord(ctx, RecordChange{Zone: z, Name: n, Type: "A", Data: "10.77.0.10"}); err == nil || !strings.Contains(err.Error(), "infraestrutura") {
			t.Errorf("%s deveria ser protegido: %v", n, err)
		}
	}
	recs, err := c.Records(ctx, z)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if want := r.Name == "@" || r.Name == "dc01" || strings.HasPrefix(r.Name, "_") || strings.HasSuffix(r.Name, "DnsZones"); r.Protected != want {
			t.Errorf("%s %s: protected = %v", r.Name, r.Type, r.Protected)
		}
	}
	for _, rc := range []RecordChange{{Zone: z, Name: "intranet", Type: "A", Data: "10.77.0.50"}, {Zone: z, Name: "intranet", Type: "AAAA", Data: "fd00::50"},
		{Zone: z, Name: "portal", Type: "CNAME", Data: "intranet.lab.heimdall.test"}} {
		_ = c.DeleteRecord(ctx, rc) // sobra de execução anterior
		if err := c.AddRecord(ctx, rc); err != nil {
			t.Fatalf("criar %+v: %v", rc, err)
		}
	}
	if err := c.AddRecord(ctx, RecordChange{Zone: z, Name: "intranet", Type: "A", Data: "10.77.0.50"}); err == nil {
		t.Error("registro repetido")
	}
	if err := c.AddRecord(ctx, RecordChange{Zone: z, Name: "portal", Type: "A", Data: "10.77.0.51"}); err == nil {
		t.Error("CNAME não convive com A")
	}
	for _, bad := range []RecordChange{{Zone: z, Name: "_ldap._tcp", Type: "A", Data: "1.2.3.4"}, {Zone: z, Name: "@", Type: "A", Data: "1.2.3.4"},
		{Zone: z, Name: "x", Type: "TXT", Data: "oi"}, {Zone: "outra.zona", Name: "x", Type: "A", Data: "1.2.3.4"}} {
		if err := c.AddRecord(ctx, bad); err == nil {
			t.Errorf("deveria recusar %+v", bad)
		}
	}
	rs, _ := c.Records(ctx, z)
	got := map[string]string{}
	for _, r := range rs {
		got[r.Name+" "+r.Type] = r.Data
	}
	if got["intranet A"] != "10.77.0.50" || got["intranet AAAA"] != "fd00::50" || got["portal CNAME"] != "intranet.lab.heimdall.test." {
		t.Errorf("registros = %v", got)
	}
	// O próprio DNS do AD responde (prova de que o formato está certo para o servidor).
	if srv := os.Getenv("HEIMDALL_AD_TEST_DNS"); srv != "" {
		cl := &dns.Client{Net: "tcp", Timeout: 3 * time.Second}
		m := new(dns.Msg)
		m.SetQuestion("portal.lab.heimdall.test.", dns.TypeA)
		r, _, err := cl.Exchange(m, srv)
		if err != nil {
			t.Fatal(err)
		}
		var a string
		for _, rr := range r.Answer {
			if x, ok := rr.(*dns.A); ok {
				a = x.A.String()
			}
		}
		if a != "10.77.0.50" {
			t.Errorf("DNS do AD para portal → %q (%v)", a, r.Answer)
		}
	}
	for _, rc := range []RecordChange{{Zone: z, Name: "portal", Type: "CNAME", Data: "intranet.lab.heimdall.test"},
		{Zone: z, Name: "intranet", Type: "AAAA", Data: "fd00::50"}, {Zone: z, Name: "intranet", Type: "A", Data: "10.77.0.50"}} {
		if err := c.DeleteRecord(ctx, rc); err != nil {
			t.Errorf("apagar %+v: %v", rc, err)
		}
	}
	rs, _ = c.Records(ctx, z)
	for _, r := range rs {
		if r.Name == "intranet" || r.Name == "portal" {
			t.Errorf("sobrou %+v", r)
		}
	}
}

func TestWriteDisabled(t *testing.T) {
	c, _ := New(Options{URL: "ldaps://x", BindUser: "u", BindPassword: "p"})
	if _, err := c.CreateUser(context.Background(), NewUser{}); err != ErrWriteDisabled {
		t.Errorf("escrita desligada: %v", err)
	}
}
