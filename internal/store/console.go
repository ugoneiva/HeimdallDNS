// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package store

import "github.com/ugoneiva/HeimdallDNS/internal/console"

func (s *Store) ConsoleTenants() ([]console.Tenant, error) {
	rows, err := s.db.Query(`SELECT id, name, url, token, insecure_tls FROM console_tenants`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []console.Tenant
	for rows.Next() {
		var t console.Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.URL, &t.Token, &t.InsecureTLS); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) SaveConsoleTenant(t console.Tenant) error {
	_, err := s.db.Exec(`INSERT INTO console_tenants (id, name, url, token, insecure_tls) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET name = excluded.name, url = excluded.url, token = excluded.token,
		insecure_tls = excluded.insecure_tls`, t.ID, t.Name, t.URL, t.Token, t.InsecureTLS)
	return err
}

func (s *Store) DeleteConsoleTenant(id string) error {
	_, err := s.db.Exec(`DELETE FROM console_tenants WHERE id = ?`, id)
	return err
}
