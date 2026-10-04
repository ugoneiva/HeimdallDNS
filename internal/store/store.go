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

	`CREATE TABLE queries (
		id          INTEGER PRIMARY KEY,
		ts          INTEGER NOT NULL, -- Unix em ms
		client_ip   TEXT NOT NULL,
		client_id   TEXT NOT NULL DEFAULT '',
		name        TEXT NOT NULL,
		qtype       TEXT NOT NULL,
		status      TEXT NOT NULL,
		rcode       TEXT NOT NULL,
		rule        TEXT NOT NULL DEFAULT '',
		upstream    TEXT NOT NULL DEFAULT '',
		duration_us INTEGER NOT NULL
	);
	CREATE INDEX queries_ts ON queries(ts);
	CREATE INDEX queries_client_ts ON queries(client_id, ts);

	CREATE TABLE stats_minute (
		minute     INTEGER NOT NULL, -- Unix / 60
		client_id  TEXT NOT NULL,
		total      INTEGER NOT NULL DEFAULT 0,
		forwarded  INTEGER NOT NULL DEFAULT 0,
		cached     INTEGER NOT NULL DEFAULT 0,
		blocked    INTEGER NOT NULL DEFAULT 0,
		isolated   INTEGER NOT NULL DEFAULT 0,
		local      INTEGER NOT NULL DEFAULT 0,
		refused    INTEGER NOT NULL DEFAULT 0,
		errors     INTEGER NOT NULL DEFAULT 0,
		forward_us INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (minute, client_id)
	) WITHOUT ROWID;

	CREATE TABLE top_domains_hour (
		hour    INTEGER NOT NULL, -- Unix / 3600
		blocked INTEGER NOT NULL,
		name    TEXT NOT NULL,
		count   INTEGER NOT NULL,
		PRIMARY KEY (hour, blocked, name)
	) WITHOUT ROWID;`,

	`CREATE TABLE settings (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	) WITHOUT ROWID;

	CREATE TABLE blocklists (
		id      INTEGER PRIMARY KEY,
		name    TEXT NOT NULL,
		url     TEXT NOT NULL UNIQUE,
		enabled INTEGER NOT NULL DEFAULT 1,
		created INTEGER NOT NULL
	);

	CREATE TABLE sessions (
		token_hash TEXT PRIMARY KEY, -- SHA-256 do cookie; o cookie em si não fica no banco
		created    INTEGER NOT NULL,
		expires    INTEGER NOT NULL
	) WITHOUT ROWID;`,

	`ALTER TABLE blocklists ADD COLUMN category TEXT NOT NULL DEFAULT '';

	CREATE TABLE security_events (
		id          INTEGER PRIMARY KEY,
		first_seen  INTEGER NOT NULL, -- Unix em ms
		last_seen   INTEGER NOT NULL,
		count       INTEGER NOT NULL DEFAULT 1,
		kind        TEXT NOT NULL,
		severity    TEXT NOT NULL,
		client_id   TEXT NOT NULL DEFAULT '',
		client_ip   TEXT NOT NULL DEFAULT '',
		domain      TEXT NOT NULL DEFAULT '',
		summary     TEXT NOT NULL,
		details     TEXT NOT NULL DEFAULT '{}',
		status      TEXT NOT NULL DEFAULT 'open'
	);
	CREATE INDEX security_events_last ON security_events(last_seen);
	CREATE INDEX security_events_dedup ON security_events(kind, client_id, domain, last_seen);

	CREATE TABLE domain_age (
		domain     TEXT PRIMARY KEY,  -- domínio registrável (eTLD+1)
		registered INTEGER NOT NULL,  -- Unix; 0 = desconhecido
		checked    INTEGER NOT NULL,
		source     TEXT NOT NULL DEFAULT ''
	) WITHOUT ROWID;`,

	`CREATE TABLE dhcp_leases (
		ip       TEXT PRIMARY KEY,
		mac      TEXT NOT NULL,
		hostname TEXT NOT NULL DEFAULT '',
		expires  INTEGER NOT NULL
	) WITHOUT ROWID;

	CREATE TABLE dhcp_reservations (
		mac  TEXT PRIMARY KEY,
		ip   TEXT NOT NULL UNIQUE,
		name TEXT NOT NULL DEFAULT ''
	) WITHOUT ROWID;`,

	`CREATE TABLE console_tenants (
		id           TEXT PRIMARY KEY,
		name         TEXT NOT NULL,
		url          TEXT NOT NULL,
		token        TEXT NOT NULL,
		insecure_tls INTEGER NOT NULL DEFAULT 0
	) WITHOUT ROWID;`,
}

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	// _txlock=immediate: transações de escrita pegam o lock no início, evitando
	// SQLITE_BUSY quando duas conexões tentam escrever ao mesmo tempo.
	dsn := "file:" + path + "?_txlock=immediate&_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4) // WAL: leituras em paralelo com a escrita
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
