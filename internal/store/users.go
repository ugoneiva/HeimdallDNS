// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Papéis dos usuários e dos tokens de API.
const (
	RoleAdmin    = "admin"    // tudo
	RoleOperator = "operator" // opera aparelhos e alertas; não muda a configuração
	RoleViewer   = "viewer"   // só leitura
)

// ValidRole diz se o papel existe.
func ValidRole(r string) bool { return r == RoleAdmin || r == RoleOperator || r == RoleViewer }

// MFA é a verificação em duas etapas (TOTP) de um usuário. Pending guarda o
// segredo até o primeiro código válido; LastStep impede reusar um código.
type MFA struct {
	Secret   string `json:"secret,omitempty"`
	Enabled  bool   `json:"enabled"`
	Pending  string `json:"pending,omitempty"`
	LastStep int64  `json:"last_step,omitempty"`
}

type User struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	Display      string    `json:"display"`
	Role         string    `json:"role"`
	Source       string    `json:"source"` // local ou ad
	PasswordHash string    `json:"password_hash,omitempty"`
	MFA          MFA       `json:"mfa"`
	Disabled     bool      `json:"disabled"`
	Created      time.Time `json:"created"`
	LastLogin    time.Time `json:"last_login"`
}

// ErrNotFound é devolvido quando o registro não existe.
var ErrNotFound = errors.New("não encontrado")

const userCols = `id, username, display, role, source, password_hash, mfa, disabled, created, last_login`

func scanUser(sc interface{ Scan(...any) error }) (User, error) {
	var (
		u              User
		mfa            string
		created, login int64
	)
	if err := sc.Scan(&u.ID, &u.Username, &u.Display, &u.Role, &u.Source, &u.PasswordHash, &mfa, &u.Disabled, &created, &login); err != nil {
		return u, err
	}
	_ = json.Unmarshal([]byte(mfa), &u.MFA)
	u.Created = time.Unix(created, 0)
	if login > 0 {
		u.LastLogin = time.Unix(login, 0)
	}
	return u, nil
}

func (s *Store) Users() ([]User, error) {
	rows, err := s.db.Query(`SELECT ` + userCols + ` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) user(where string, arg any) (User, error) {
	u, err := scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE `+where, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

func (s *Store) UserByID(id int64) (User, error)      { return s.user(`id = ?`, id) }
func (s *Store) UserByName(name string) (User, error) { return s.user(`username = ?`, name) }
func (s *Store) CountUsers() (n int, err error) {
	return n, s.db.QueryRow(`SELECT count(*) FROM users`).Scan(&n)
}

// CountAdmins conta os administradores ativos (o último não pode sair).
func (s *Store) CountAdmins() (n int, err error) {
	return n, s.db.QueryRow(`SELECT count(*) FROM users WHERE role = ? AND disabled = 0`, RoleAdmin).Scan(&n)
}

// SaveUser cria (ID 0) ou atualiza o usuário.
func (s *Store) SaveUser(u *User) error {
	mfa, _ := json.Marshal(u.MFA)
	var last int64
	if !u.LastLogin.IsZero() {
		last = u.LastLogin.Unix()
	}
	if u.ID == 0 {
		if u.Created.IsZero() {
			u.Created = time.Now()
		}
		res, err := s.db.Exec(`INSERT INTO users (username, display, role, source, password_hash, mfa, disabled, created, last_login)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, u.Username, u.Display, u.Role, u.Source, u.PasswordHash, string(mfa), u.Disabled, u.Created.Unix(), last)
		if err != nil {
			return err
		}
		u.ID, err = res.LastInsertId()
		return err
	}
	_, err := s.db.Exec(`UPDATE users SET username = ?, display = ?, role = ?, source = ?, password_hash = ?, mfa = ?, disabled = ?, last_login = ?
		WHERE id = ?`, u.Username, u.Display, u.Role, u.Source, u.PasswordHash, string(mfa), u.Disabled, last, u.ID)
	return err
}

func (s *Store) DeleteUser(id int64) error {
	if _, err := s.db.Exec(`DELETE FROM users WHERE id = ?`, id); err != nil {
		return err
	}
	return s.DeleteUserSessions(id)
}

// ReplaceUsers troca todos os usuários (réplica de alta disponibilidade),
// mantendo os ids do principal; as sessões de quem sumiu caem.
func (s *Store) ReplaceUsers(us []User) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Quem era dono de cada id: se o id passar a ser de outra pessoa, as
	// sessões dele caem (senão herdariam a conta errada).
	old := map[int64]string{}
	rows, err := tx.Query(`SELECT id, username FROM users`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			rows.Close()
			return err
		}
		old[id] = name
	}
	rows.Close()
	if _, err := tx.Exec(`DELETE FROM users`); err != nil {
		return err
	}
	for _, u := range us {
		if prev, ok := old[u.ID]; ok && !strings.EqualFold(prev, u.Username) {
			if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id = ?`, u.ID); err != nil {
				return err
			}
		}
		mfa, _ := json.Marshal(u.MFA)
		var last int64
		if !u.LastLogin.IsZero() {
			last = u.LastLogin.Unix()
		}
		if _, err := tx.Exec(`INSERT INTO users (`+userCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			u.ID, u.Username, u.Display, u.Role, u.Source, u.PasswordHash, string(mfa), u.Disabled, u.Created.Unix(), last); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id NOT IN (SELECT id FROM users WHERE disabled = 0)`); err != nil {
		return err
	}
	return tx.Commit()
}

// APIToken é um token de API com nome, papel e validade.
type APIToken struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Hash      string    `json:"hash,omitempty"`
	Prefix    string    `json:"prefix"`
	Role      string    `json:"role"`
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires"` // zero = não vence
	LastUsed  time.Time `json:"last_used"`
	CreatedBy string    `json:"created_by"`
}

const tokenCols = `id, name, token_hash, prefix, role, created, expires, last_used, created_by`

func scanToken(sc interface{ Scan(...any) error }) (APIToken, error) {
	var (
		t                  APIToken
		created, exp, used int64
	)
	if err := sc.Scan(&t.ID, &t.Name, &t.Hash, &t.Prefix, &t.Role, &created, &exp, &used, &t.CreatedBy); err != nil {
		return t, err
	}
	t.Created = time.Unix(created, 0)
	if exp > 0 {
		t.Expires = time.Unix(exp, 0)
	}
	if used > 0 {
		t.LastUsed = time.Unix(used, 0)
	}
	return t, nil
}

func (s *Store) Tokens() ([]APIToken, error) {
	rows, err := s.db.Query(`SELECT ` + tokenCols + ` FROM api_tokens ORDER BY created DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIToken{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) TokenByHash(hash string) (APIToken, error) {
	t, err := scanToken(s.db.QueryRow(`SELECT `+tokenCols+` FROM api_tokens WHERE token_hash = ?`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	return t, err
}

func (s *Store) CreateToken(t *APIToken) error {
	var exp int64
	if !t.Expires.IsZero() {
		exp = t.Expires.Unix()
	}
	t.Created = time.Now()
	res, err := s.db.Exec(`INSERT INTO api_tokens (name, token_hash, prefix, role, created, expires, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		t.Name, t.Hash, t.Prefix, t.Role, t.Created.Unix(), exp, t.CreatedBy)
	if err != nil {
		return err
	}
	t.ID, err = res.LastInsertId()
	return err
}

// TouchToken marca o uso (no máximo uma gravação por minuto por token).
func (s *Store) TouchToken(id int64, now time.Time) error {
	_, err := s.db.Exec(`UPDATE api_tokens SET last_used = ? WHERE id = ? AND last_used < ?`, now.Unix(), id, now.Unix()-60)
	return err
}

func (s *Store) DeleteToken(id int64) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM api_tokens WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ReplaceTokens troca todos os tokens (réplica), mantendo os ids.
func (s *Store) ReplaceTokens(ts []APIToken) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM api_tokens`); err != nil {
		return err
	}
	for _, t := range ts {
		var exp int64
		if !t.Expires.IsZero() {
			exp = t.Expires.Unix()
		}
		if _, err := tx.Exec(`INSERT INTO api_tokens (`+tokenCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)`,
			t.ID, t.Name, t.Hash, t.Prefix, t.Role, t.Created.Unix(), exp, t.CreatedBy); err != nil {
			return err
		}
	}
	return tx.Commit()
}
