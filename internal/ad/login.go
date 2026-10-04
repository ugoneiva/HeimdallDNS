// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package ad

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// ErrBadCredentials é devolvido para usuário inexistente ou senha errada (sem
// distinguir os dois, para não revelar quais contas existem).
var ErrBadCredentials = errors.New("usuário ou senha incorretos")

// Login confere usuário e senha no AD (bind com a própria conta da pessoa) e
// devolve a conta e os nomes de todos os grupos dela, inclusive os herdados
// por grupos dentro de grupos. Aceita "joao", "joao@empresa.local" e
// "EMPRESA\joao".
func (c *Client) Login(ctx context.Context, name, password string) (User, []string, error) {
	// Senha vazia faria um "bind anônimo", que o LDAP aceita: nunca deixar passar.
	if password == "" || strings.TrimSpace(name) == "" {
		return User{}, nil, ErrBadCredentials
	}
	name = strings.TrimSpace(name)
	if _, after, ok := strings.Cut(name, `\`); ok {
		name = after
	}
	l, err := c.conn()
	if err != nil {
		return User{}, nil, err
	}
	defer l.Close()
	base, err := c.baseDN(l)
	if err != nil {
		return User{}, nil, err
	}
	f := fmt.Sprintf("(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=%s)(userPrincipalName=%s)))",
		ldap.EscapeFilter(name), ldap.EscapeFilter(name))
	es, err := search(l, base, f, userAttrs, 2)
	if err != nil {
		return User{}, nil, err
	}
	if len(es) != 1 {
		return User{}, nil, ErrBadCredentials
	}
	u := c.toUser(es[0])

	ul, err := c.dial()
	if err != nil {
		return User{}, nil, err
	}
	defer ul.Close()
	if err := ul.Bind(u.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			// O AD manda o motivo (conta desativada, bloqueada, senha vencida) no texto.
			return User{}, nil, ErrBadCredentials
		}
		return User{}, nil, fmt.Errorf("autenticando no AD: %w", err)
	}
	if !u.Enabled {
		return User{}, nil, errors.New("conta desativada no Active Directory")
	}
	if u.Locked {
		return User{}, nil, errors.New("conta bloqueada no Active Directory")
	}

	// LDAP_MATCHING_RULE_IN_CHAIN: grupos diretos e herdados (Windows e Samba).
	gs, err := search(l, base, fmt.Sprintf("(&(objectClass=group)(member:1.2.840.113556.1.4.1941:=%s))", ldap.EscapeFilter(u.DN)),
		[]string{"cn"}, 0)
	if err != nil {
		return User{}, nil, err
	}
	groups := make([]string, 0, len(gs))
	for _, g := range gs {
		groups = append(groups, g.GetAttributeValue("cn"))
	}
	return u, groups, nil
}
