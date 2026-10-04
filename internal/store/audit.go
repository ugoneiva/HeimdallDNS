// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package store

import (
	"encoding/json"
	"time"
)

// AuditEntry é uma operação administrativa registrada (ex.: alteração no AD).
type AuditEntry struct {
	ID      int64          `json:"id"`
	Time    time.Time      `json:"time"`
	Actor   string         `json:"actor"`
	IP      string         `json:"ip,omitempty"`
	Action  string         `json:"action"`
	Target  string         `json:"target,omitempty"`
	Details map[string]any `json:"details,omitempty"`
	OK      bool           `json:"ok"`
	Error   string         `json:"error,omitempty"`
}

func (s *Store) InsertAudit(e *AuditEntry) error {
	d, err := json.Marshal(e.Details)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(`INSERT INTO audit_log (ts, actor, ip, action, target, details, ok, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Time.UnixMilli(), e.Actor, e.IP, e.Action, e.Target, string(d), e.OK, e.Error)
	if err != nil {
		return err
	}
	e.ID, err = res.LastInsertId()
	return err
}

func (s *Store) Audit(since time.Time, limit int) ([]AuditEntry, error) {
	rows, err := s.db.Query(`SELECT id, ts, actor, ip, action, target, details, ok, error FROM audit_log
		WHERE ts >= ? ORDER BY id DESC LIMIT ?`, since.UnixMilli(), min(max(limit, 1), 1000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var (
			e       AuditEntry
			ts      int64
			details string
		)
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.IP, &e.Action, &e.Target, &details, &e.OK, &e.Error); err != nil {
			return nil, err
		}
		e.Time = time.UnixMilli(ts)
		_ = json.Unmarshal([]byte(details), &e.Details)
		out = append(out, e)
	}
	return out, rows.Err()
}
