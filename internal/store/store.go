// Package store guarda os dados do HeimdallDNS em SQLite (driver em Go puro,
// sem CGO, para compilar para ARM sem dor).
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	_ "modernc.org/sqlite"

	"github.com/ugoneiva/HeimdallDNS/internal/clients"
)

// migrations em ordem; a posição + 1 é a versão em PRAGMA user_version.
var migrations = []string{
	`CREATE TABLE clients (
		id         TEXT PRIMARY KEY,
		mac        TEXT NOT NULL DEFAULT '',
		vendor     TEXT NOT NULL DEFAULT '',
		hostname   TEXT NOT NULL DEFAULT '',
		ips        TEXT NOT NULL DEFAULT '[]',
		first_seen INTEGER NOT NULL,
		last_seen  INTEGER NOT NULL,
		queries    INTEGER NOT NULL DEFAULT 0,
		blocked    INTEGER NOT NULL DEFAULT 0,
		settings   TEXT NOT NULL DEFAULT '{}'
	);
	CREATE INDEX clients_mac ON clients(mac) WHERE mac != '';`,
}

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite aceita um escritor por vez; evita SQLITE_BUSY
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	var v int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	for i := v; i < len(migrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migração %d: %w", i+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) LoadClients() ([]clients.Record, error) {
	rows, err := s.db.Query(`SELECT id, mac, vendor, hostname, ips, first_seen, last_seen, queries, blocked, settings FROM clients`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []clients.Record
	for rows.Next() {
		var (
			r              clients.Record
			ips, settings  string
			first, last    int64
			queries, block int64
		)
		if err := rows.Scan(&r.ID, &r.MAC, &r.Vendor, &r.Hostname, &ips, &first, &last, &queries, &block, &settings); err != nil {
			return nil, err
		}
		var addrs []string
		if err := json.Unmarshal([]byte(ips), &addrs); err != nil {
			return nil, fmt.Errorf("cliente %s: ips: %w", r.ID, err)
		}
		for _, a := range addrs {
			if ip, err := netip.ParseAddr(a); err == nil {
				r.IPs = append(r.IPs, ip)
			}
		}
		if err := json.Unmarshal([]byte(settings), &r.Settings); err != nil {
			return nil, fmt.Errorf("cliente %s: settings: %w", r.ID, err)
		}
		r.FirstSeen, r.LastSeen = time.Unix(0, first), time.Unix(0, last)
		r.Queries, r.Blocked = uint64(queries), uint64(block)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) SaveClients(recs []clients.Record) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := tx.Prepare(`INSERT INTO clients (id, mac, vendor, hostname, ips, first_seen, last_seen, queries, blocked, settings)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET mac=excluded.mac, vendor=excluded.vendor, hostname=excluded.hostname,
			ips=excluded.ips, last_seen=excluded.last_seen, queries=excluded.queries,
			blocked=excluded.blocked, settings=excluded.settings`)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, r := range recs {
		ips := make([]string, len(r.IPs))
		for i, ip := range r.IPs {
			ips[i] = ip.String()
		}
		ipsJSON, _ := json.Marshal(ips)
		setJSON, err := json.Marshal(r.Settings)
		if err != nil {
			return err
		}
		if _, err := st.Exec(r.ID, r.MAC, r.Vendor, r.Hostname, string(ipsJSON),
			r.FirstSeen.UnixNano(), r.LastSeen.UnixNano(), int64(r.Queries), int64(r.Blocked), string(setJSON)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) DeleteClient(id string) error {
	_, err := s.db.Exec(`DELETE FROM clients WHERE id = ?`, id)
	return err
}
