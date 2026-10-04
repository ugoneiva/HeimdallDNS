// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package store

import (
	"database/sql"
	"fmt"
	"os"
)

// SchemaVersion é a versão do banco que este binário conhece.
func SchemaVersion() int { return len(migrations) }

// SnapshotTo grava uma cópia consistente do banco em path (VACUUM INTO, sem
// parar o serviço). Sem full, a cópia sai sem o histórico de consultas
// (os resumos dos gráficos ficam). Sessões do painel nunca vão para a cópia.
func (s *Store) SnapshotTo(path string, full bool) error {
	_ = os.Remove(path)
	if _, err := s.db.Exec(`VACUUM INTO ?`, path); err != nil {
		return fmt.Errorf("cópia do banco: %w", err)
	}
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		return err
	}
	defer db.Close()
	stmts := []string{`DELETE FROM sessions`}
	if !full {
		stmts = append(stmts, `DELETE FROM queries`)
	}
	stmts = append(stmts, `VACUUM`)
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("cópia do banco: %w", err)
		}
	}
	return nil
}

// CheckFile confere se path é um banco do HeimdallDNS íntegro e compatível
// com este binário; devolve a versão do esquema.
func CheckFile(path string) (int, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return 0, err
	}
	defer db.Close()
	var ok string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&ok); err != nil {
		return 0, fmt.Errorf("não é um banco SQLite válido: %w", err)
	}
	if ok != "ok" {
		return 0, fmt.Errorf("banco corrompido: %s", ok)
	}
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return 0, err
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name IN ('clients', 'settings', 'blocklists')`).Scan(&n); err != nil || n != 3 {
		return 0, fmt.Errorf("o arquivo não é um banco do HeimdallDNS")
	}
	if v > SchemaVersion() {
		return v, fmt.Errorf("o backup é de uma versão mais nova do HeimdallDNS (esquema %d; este binário conhece até %d): atualize antes de restaurar", v, SchemaVersion())
	}
	return v, nil
}
