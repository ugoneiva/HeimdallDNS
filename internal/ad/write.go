// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package ad

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/go-ldap/ldap/v3"
)

// ErrWriteDisabled volta quando a escrita não foi liberada na configuração.
var ErrWriteDisabled = errors.New("alterações no AD estão desligadas (ad.write)")

func (c *Client) mustWrite() error {
	if !c.opts.Write {
		return ErrWriteDisabled
	}
	return nil
}

// manageable confere as travas antes de alterar um usuário.
func (c *Client) manageable(u User) error {
	switch {
	case u.Privileged:
		return fmt.Errorf("%s é uma conta privilegiada: o HeimdallDNS não altera", u.SAM)
	case !c.inUserOUs(u.DN):
		return fmt.Errorf("%s está fora das OUs liberadas (ad.user_ous)", u.SAM)
	}
	return nil
}

// encodePassword monta o unicodePwd: a senha entre aspas, em UTF-16LE.
// O AD só aceita por conexão criptografada (LDAPS/StartTLS).
func encodePassword(pw string) []byte {
	u := utf16.Encode([]rune(`"` + pw + `"`))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		b[2*i], b[2*i+1] = byte(v), byte(v>>8)
	}
	return b
}

// NewUser é o pedido de criação de usuário.
type NewUser struct {
	OU          string `json:"ou"`
	SAM         string `json:"sam"`
	GivenName   string `json:"given_name"`
	Surname     string `json:"surname"`
	DisplayName string `json:"display_name"`
	UPN         string `json:"upn"`
	Mail        string `json:"mail"`
	Description string `json:"description"`
	Password    string `json:"password"`
	MustChange  bool   `json:"must_change"`
	Enabled     bool   `json:"enabled"`
}

func validSAM(s string) bool {
	if s == "" || len(s) > 20 {
		return false
	}
	for _, r := range s {
		if strings.ContainsRune(`"/\[]:;|=,+*?<>@ `, r) {
			return false
		}
	}
	return true
}

// CreateUser cria o usuário (desabilitado), define a senha e só então
// habilita. Se a senha não passar na política do AD, apaga o que criou.
func (c *Client) CreateUser(ctx context.Context, n NewUser) (User, error) {
	if err := c.mustWrite(); err != nil {
		return User{}, err
	}
	n.SAM = strings.TrimSpace(n.SAM)
	if !validSAM(n.SAM) {
		return User{}, errors.New("login inválido: até 20 caracteres, sem espaços nem \" / \\ [ ] : ; | = , + * ? < > @")
	}
	if !c.inUserOUs(n.OU) {
		return User{}, fmt.Errorf("a OU %q não está liberada (ad.user_ous)", n.OU)
	}
	if n.Password == "" {
		return User{}, errors.New("informe a senha inicial")
	}
	if n.DisplayName == "" {
		n.DisplayName = strings.TrimSpace(n.GivenName + " " + n.Surname)
	}
	if n.DisplayName == "" {
		n.DisplayName = n.SAM
	}
	l, err := c.conn()
	if err != nil {
		return User{}, err
	}
	defer l.Close()
	info, err := c.check(l)
	if err != nil {
		return User{}, err
	}
	if n.UPN == "" {
		n.UPN = n.SAM + "@" + info.Domain
	}
	if _, err := c.findUser(l, n.SAM); err == nil {
		return User{}, fmt.Errorf("já existe o login %q", n.SAM)
	}

	dn := fmt.Sprintf("CN=%s,%s", ldap.EscapeDN(n.DisplayName), n.OU)
	add := ldap.NewAddRequest(dn, nil)
	add.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	add.Attribute("sAMAccountName", []string{n.SAM})
	add.Attribute("userPrincipalName", []string{n.UPN})
	add.Attribute("displayName", []string{n.DisplayName})
	add.Attribute("userAccountControl", []string{strconv.Itoa(uacNormalAccount | uacDisabled)})
	for attr, v := range map[string]string{"givenName": n.GivenName, "sn": n.Surname, "mail": n.Mail, "description": n.Description} {
		if v = strings.TrimSpace(v); v != "" {
			add.Attribute(attr, []string{v})
		}
	}
	if err := l.Add(add); err != nil {
		return User{}, fmt.Errorf("criando o usuário: %w", err)
	}
	rollback := func(cause error) (User, error) {
		if derr := l.Del(ldap.NewDelRequest(dn, nil)); derr != nil {
			return User{}, fmt.Errorf("%w (e não consegui desfazer a criação de %s: %v)", cause, dn, derr)
		}
		return User{}, cause
	}
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace("unicodePwd", []string{string(encodePassword(n.Password))})
	if err := l.Modify(mod); err != nil {
		return rollback(fmt.Errorf("a senha não foi aceita pelo AD (política de senha?): %w", err))
	}
	mod = ldap.NewModifyRequest(dn, nil)
	if n.MustChange {
		mod.Replace("pwdLastSet", []string{"0"})
	}
	if n.Enabled {
		mod.Replace("userAccountControl", []string{strconv.Itoa(uacNormalAccount)})
	}
	if len(mod.Changes) > 0 {
		if err := l.Modify(mod); err != nil {
			return rollback(fmt.Errorf("ajustando a conta: %w", err))
		}
	}
	return c.findUser(l, n.SAM)
}

// userForChange acha o usuário e confere as travas.
func (c *Client) userForChange(l *ldap.Conn, sam string) (User, error) {
	if err := c.mustWrite(); err != nil {
		return User{}, err
	}
	u, err := c.findUser(l, sam)
	if err != nil {
		return u, err
	}
	return u, c.manageable(u)
}

func (c *Client) modifyUser(sam string, change func(*ldap.Conn, User, *ldap.ModifyRequest) error) (User, error) {
	l, err := c.conn()
	if err != nil {
		return User{}, err
	}
	defer l.Close()
	u, err := c.userForChange(l, sam)
	if err != nil {
		return u, err
	}
	mod := ldap.NewModifyRequest(u.DN, nil)
	if err := change(l, u, mod); err != nil {
		return u, err
	}
	if err := l.Modify(mod); err != nil {
		return u, err
	}
	return c.findUser(l, sam)
}

func (c *Client) SetEnabled(ctx context.Context, sam string, enabled bool) (User, error) {
	return c.modifyUser(sam, func(l *ldap.Conn, u User, m *ldap.ModifyRequest) error {
		base, _ := c.baseDN(l)
		es, err := search(l, base, fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(sam)), []string{"userAccountControl"}, 1)
		if err != nil || len(es) == 0 {
			return fmt.Errorf("lendo userAccountControl: %v", err)
		}
		uac, _ := strconv.Atoi(es[0].GetAttributeValue("userAccountControl"))
		if enabled {
			uac &^= uacDisabled
		} else {
			uac |= uacDisabled
		}
		m.Replace("userAccountControl", []string{strconv.Itoa(uac)})
		return nil
	})
}

func (c *Client) ResetPassword(ctx context.Context, sam, password string, mustChange bool) (User, error) {
	if password == "" {
		return User{}, errors.New("informe a nova senha")
	}
	u, err := c.modifyUser(sam, func(_ *ldap.Conn, _ User, m *ldap.ModifyRequest) error {
		m.Replace("unicodePwd", []string{string(encodePassword(password))})
		return nil
	})
	if err != nil {
		return u, fmt.Errorf("a senha não foi aceita pelo AD (política de senha?): %w", err)
	}
	if mustChange {
		return c.modifyUser(sam, func(_ *ldap.Conn, _ User, m *ldap.ModifyRequest) error {
			m.Replace("pwdLastSet", []string{"0"})
			return nil
		})
	}
	return u, nil
}

func (c *Client) Unlock(ctx context.Context, sam string) (User, error) {
	return c.modifyUser(sam, func(_ *ldap.Conn, _ User, m *ldap.ModifyRequest) error {
		m.Replace("lockoutTime", []string{"0"})
		return nil
	})
}

func (c *Client) DeleteUser(ctx context.Context, sam string) error {
	l, err := c.conn()
	if err != nil {
		return err
	}
	defer l.Close()
	u, err := c.userForChange(l, sam)
	if err != nil {
		return err
	}
	return l.Del(ldap.NewDelRequest(u.DN, nil))
}

// SetMembership coloca ou tira o usuário do grupo liberado.
func (c *Client) SetMembership(ctx context.Context, group, sam string, member bool) (Group, error) {
	l, err := c.conn()
	if err != nil {
		return Group{}, err
	}
	defer l.Close()
	if err := c.mustWrite(); err != nil {
		return Group{}, err
	}
	g, members, err := c.findGroup(l, group)
	if err != nil {
		return g, err
	}
	if g.Privileged {
		return g, fmt.Errorf("%s é um grupo privilegiado: o HeimdallDNS não altera", g.Name)
	}
	if !c.groupAllowed(g) {
		return g, fmt.Errorf("o grupo %s não está liberado (ad.managed_groups)", g.Name)
	}
	u, err := c.userForChange(l, sam)
	if err != nil {
		return g, err
	}
	has := false
	for _, m := range members {
		if strings.EqualFold(m, u.DN) {
			has = true
		}
	}
	if has == member {
		return g, nil // já está como pedido
	}
	mod := ldap.NewModifyRequest(g.DN, nil)
	if member {
		mod.Add("member", []string{u.DN})
	} else {
		mod.Delete("member", []string{u.DN})
	}
	if err := l.Modify(mod); err != nil {
		return g, err
	}
	g, _, err = c.findGroup(l, g.DN)
	return g, err
}
