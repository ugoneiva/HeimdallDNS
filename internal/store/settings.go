package store

import (
	"database/sql"
	"encoding/json"
	"errors"
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

func (s *Store) CreateSession(hash string, expires time.Time) error {
	_, err := s.db.Exec(`INSERT INTO sessions (token_hash, created, expires) VALUES (?, ?, ?)`,
		hash, time.Now().Unix(), expires.Unix())
	return err
}

// SessionValid diz se a sessão existe e não venceu.
func (s *Store) SessionValid(hash string) (bool, error) {
	var exp int64
	err := s.db.QueryRow(`SELECT expires FROM sessions WHERE token_hash = ?`, hash).Scan(&exp)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return time.Now().Unix() < exp, nil
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
