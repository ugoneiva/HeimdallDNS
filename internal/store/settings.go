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

// GetJSON lê uma configuração; devolve false se ela não existir.
func (s *Store) GetJSON(key string, v any) (bool, error) {
	var raw string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal([]byte(raw), v)
}

func (s *Store) SetJSON(key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, string(b))
	return err
}

// List é uma lista de bloqueio cadastrada pela interface.
type List struct {
	ID       int64     `json:"id"`
	Name     string    `json:"name"`
	URL      string    `json:"url"`
	Enabled  bool      `json:"enabled"`
	Category string    `json:"category"`
	Created  time.Time `json:"created"`
}

func (s *Store) Lists() ([]List, error) {
	rows, err := s.db.Query(`SELECT id, name, url, enabled, category, created FROM blocklists ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []List
	for rows.Next() {
		var (
			l       List
			created int64
		)
		if err := rows.Scan(&l.ID, &l.Name, &l.URL, &l.Enabled, &l.Category, &created); err != nil {
			return nil, err
		}
		l.Created = time.Unix(created, 0)
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *Store) AddList(name, url, category string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO blocklists (name, url, enabled, category, created) VALUES (?, ?, 1, ?, ?)`,
		name, url, category, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateList altera nome, estado e/ou categoria; devolve false se a lista não existir.
func (s *Store) UpdateList(id int64, name *string, enabled *bool, category *string) (bool, error) {
	res, err := s.db.Exec(`UPDATE blocklists SET name = COALESCE(?, name), enabled = COALESCE(?, enabled),
		category = COALESCE(?, category) WHERE id = ?`, name, enabled, category, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) DeleteList(id int64) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM blocklists WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// SessionInfo é a origem de uma sessão do painel.
type SessionInfo struct {
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
	Method    string `json:"method"` // como entrou: senha, senha+totp, passkey…
}

// SessionRow é uma sessão ativa. ID é o começo do hash do cookie (o cookie em
// si nunca fica no banco), suficiente para encerrar a sessão pelo painel.
type SessionRow struct {
	ID       string    `json:"id"`
	UserID   int64     `json:"user_id"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires"`
	LastSeen time.Time `json:"last_seen"`
	SessionInfo
}

const sessionIDLen = 16

func (s *Store) CreateSession(hash string, userID int64, expires time.Time, info SessionInfo) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(`INSERT INTO sessions (token_hash, created, expires, user_id, ip, user_agent, method, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		hash, now, expires.Unix(), userID, info.IP, truncate(info.UserAgent, 300), info.Method, now)
	return err
}

// Session devolve o dono da sessão, se ela existir e não tiver vencido, e
// marca o último uso (no máximo uma escrita por minuto).
func (s *Store) Session(hash string) (userID int64, ok bool, err error) {
	var exp, seen int64
	err = s.db.QueryRow(`SELECT expires, user_id, last_seen FROM sessions WHERE token_hash = ?`, hash).Scan(&exp, &userID, &seen)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	now := time.Now().Unix()
	if now >= exp {
		return userID, false, nil
	}
	if now-seen >= 60 {
		_, _ = s.db.Exec(`UPDATE sessions SET last_seen = ? WHERE token_hash = ?`, now, hash)
	}
	return userID, true, nil
}

// Sessions lista as sessões válidas (userID 0 = de todos), mais recentes primeiro.
func (s *Store) Sessions(userID int64) ([]SessionRow, error) {
	rows, err := s.db.Query(`SELECT token_hash, user_id, created, expires, last_seen, ip, user_agent, method FROM sessions
		WHERE expires > ? AND (? = 0 OR user_id = ?) ORDER BY last_seen DESC`, time.Now().Unix(), userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SessionRow{}
	for rows.Next() {
		var (
			r                      SessionRow
			hash                   string
			created, expires, seen int64
		)
		if err := rows.Scan(&hash, &r.UserID, &created, &expires, &seen, &r.IP, &r.UserAgent, &r.Method); err != nil {
			return nil, err
		}
		r.ID = SessionID(hash)
		r.Created, r.Expires = time.Unix(created, 0), time.Unix(expires, 0)
		if seen > 0 {
			r.LastSeen = time.Unix(seen, 0)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SessionID é o identificador público da sessão (começo do hash).
func SessionID(hash string) string {
	if len(hash) > sessionIDLen {
		return hash[:sessionIDLen]
	}
	return hash
}

// DeleteSessionByID encerra uma sessão pelo ID público; userID ≠ 0 só deixa
// encerrar as sessões daquele usuário. Devolve se encerrou alguma.
func (s *Store) DeleteSessionByID(id string, userID int64) (bool, error) {
	if len(id) != sessionIDLen || strings.Trim(id, "0123456789abcdef") != "" {
		return false, nil
	}
	res, err := s.db.Exec(`DELETE FROM sessions WHERE substr(token_hash, 1, ?) = ? AND (? = 0 OR user_id = ?)`, sessionIDLen, id, userID, userID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// DeleteOtherSessions encerra as sessões do usuário menos a atual.
func (s *Store) DeleteOtherSessions(userID int64, keepHash string) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?`, userID, keepHash)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// DeleteUserSessions encerra as sessões de um usuário (troca de senha,
// desativação, mudança de papel).
func (s *Store) DeleteUserSessions(userID int64) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

func (s *Store) DeleteSession(hash string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, hash)
	return err
}

// DeleteSessions encerra todas as sessões (troca de senha) e as vencidas.
func (s *Store) DeleteSessions(all bool) error {
	if all {
		_, err := s.db.Exec(`DELETE FROM sessions`)
		return err
	}
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires <= ?`, time.Now().Unix())
	return err
}

// ReplaceLists troca todas as listas da interface (réplica de alta
// disponibilidade), mantendo os ids do principal.
func (s *Store) ReplaceLists(ls []List) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM blocklists`); err != nil {
		return err
	}
	for _, l := range ls {
		if _, err := tx.Exec(`INSERT INTO blocklists (id, name, url, enabled, category, created) VALUES (?, ?, ?, ?, ?, ?)`,
			l.ID, l.Name, l.URL, l.Enabled, l.Category, l.Created.Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}
