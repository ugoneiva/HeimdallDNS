package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// SecurityEvent é um alerta de segurança. Repetições do mesmo alerta (mesmo
// tipo, dispositivo e domínio) somam em Count em vez de criar linhas novas.
type SecurityEvent struct {
	ID        int64          `json:"id"`
	FirstSeen time.Time      `json:"first_seen"`
	LastSeen  time.Time      `json:"last_seen"`
	Count     int            `json:"count"`
	Kind      string         `json:"kind"`
	Severity  string         `json:"severity"`
	ClientID  string         `json:"client_id,omitempty"`
	ClientIP  string         `json:"client_ip,omitempty"`
	Domain    string         `json:"domain,omitempty"`
	Summary   string         `json:"summary"`
	Details   map[string]any `json:"details,omitempty"`
	Status    string         `json:"status"` // open ou ack
}

func (s *Store) InsertEvent(e *SecurityEvent) error {
	d, err := json.Marshal(e.Details)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(`INSERT INTO security_events
		(first_seen, last_seen, count, kind, severity, client_id, client_ip, domain, summary, details, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')`,
		e.FirstSeen.UnixMilli(), e.LastSeen.UnixMilli(), max(e.Count, 1), e.Kind, e.Severity,
		e.ClientID, e.ClientIP, e.Domain, e.Summary, string(d))
	if err != nil {
		return err
	}
	e.ID, err = res.LastInsertId()
	e.Status = "open"
	return err
}

// FindRecentEvent procura um alerta igual visto depois de since (para somar).
func (s *Store) FindRecentEvent(kind, clientID, domain string, since time.Time) (int64, error) {
	var id int64
	err := s.db.QueryRow(`SELECT id FROM security_events WHERE kind = ? AND client_id = ? AND domain = ?
		AND last_seen >= ? ORDER BY last_seen DESC LIMIT 1`, kind, clientID, domain, since.UnixMilli()).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return id, err
}

// BumpEvent soma uma ocorrência; o alerta volta a ficar aberto.
func (s *Store) BumpEvent(id int64, at time.Time, details map[string]any) error {
	d, err := json.Marshal(details)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE security_events SET count = count + 1, last_seen = ?, status = 'open',
		details = CASE WHEN ? = 'null' THEN details ELSE ? END WHERE id = ?`, at.UnixMilli(), string(d), string(d), id)
	return err
}

type EventQuery struct {
	Since    time.Time
	Status   string   // "", open, ack
	Kinds    []string // vazio = todos
	ClientID string
	Limit    int
}

func (s *Store) Events(q EventQuery) ([]SecurityEvent, error) {
	where, args := []string{"last_seen >= ?"}, []any{q.Since.UnixMilli()}
	if q.Status != "" {
		where, args = append(where, "status = ?"), append(args, q.Status)
	}
	if len(q.Kinds) > 0 {
		where = append(where, "kind IN ("+placeholders(len(q.Kinds))+")")
		args = appendStrings(args, q.Kinds)
	}
	if q.ClientID != "" {
		where, args = append(where, "client_id = ?"), append(args, q.ClientID)
	}
	limit := min(max(q.Limit, 1), 1000)
	rows, err := s.db.Query(`SELECT id, first_seen, last_seen, count, kind, severity, client_id, client_ip, domain,
		summary, details, status FROM security_events WHERE `+strings.Join(where, " AND ")+`
		ORDER BY last_seen DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SecurityEvent{}
	for rows.Next() {
		var (
			e           SecurityEvent
			first, last int64
			details     string
		)
		if err := rows.Scan(&e.ID, &first, &last, &e.Count, &e.Kind, &e.Severity, &e.ClientID, &e.ClientIP,
			&e.Domain, &e.Summary, &details, &e.Status); err != nil {
			return nil, err
		}
		e.FirstSeen, e.LastSeen = time.UnixMilli(first), time.UnixMilli(last)
		_ = json.Unmarshal([]byte(details), &e.Details)
		out = append(out, e)
	}
	return out, rows.Err()
}

// SetEventStatus marca um alerta (id > 0) ou todos os abertos (id = 0).
func (s *Store) SetEventStatus(id int64, status string) (int64, error) {
	var res sql.Result
	var err error
	if id == 0 {
		res, err = s.db.Exec(`UPDATE security_events SET status = ? WHERE status != ?`, status, status)
	} else {
		res, err = s.db.Exec(`UPDATE security_events SET status = ? WHERE id = ?`, status, id)
	}
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// EventCounts conta alertas abertos por gravidade e, no período, por tipo.
func (s *Store) EventCounts(since time.Time) (open map[string]int, byKind map[string]int, err error) {
	open, byKind = map[string]int{}, map[string]int{}
	rows, err := s.db.Query(`SELECT severity, COUNT(*) FROM security_events WHERE status = 'open' GROUP BY severity`)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			rows.Close()
			return nil, nil, err
		}
		open[k] = n
	}
	rows.Close()
	rows, err = s.db.Query(`SELECT kind, SUM(count) FROM security_events WHERE last_seen >= ? GROUP BY kind`, since.UnixMilli())
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return nil, nil, err
		}
		byKind[k] = n
	}
	return open, byKind, rows.Err()
}

// PurgeEvents apaga alertas mais antigos que before.
func (s *Store) PurgeEvents(before time.Time) error {
	_, err := s.db.Exec(`DELETE FROM security_events WHERE last_seen < ?`, before.UnixMilli())
	return err
}

// DomainAge é a data de registro conhecida de um domínio.
type DomainAge struct {
	Domain     string
	Registered time.Time // zero = desconhecida
	Checked    time.Time
	Source     string
}

func (s *Store) DomainAges() ([]DomainAge, error) {
	rows, err := s.db.Query(`SELECT domain, registered, checked, source FROM domain_age`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DomainAge
	for rows.Next() {
		var (
			d        DomainAge
			reg, chk int64
		)
		if err := rows.Scan(&d.Domain, &reg, &chk, &d.Source); err != nil {
			return nil, err
		}
		if reg > 0 {
			d.Registered = time.Unix(reg, 0)
		}
		d.Checked = time.Unix(chk, 0)
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) SaveDomainAge(d DomainAge) error {
	var reg int64
	if !d.Registered.IsZero() {
		reg = d.Registered.Unix()
	}
	_, err := s.db.Exec(`INSERT INTO domain_age (domain, registered, checked, source) VALUES (?, ?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET registered = excluded.registered, checked = excluded.checked,
		source = excluded.source`, d.Domain, reg, d.Checked.Unix(), d.Source)
	return err
}
