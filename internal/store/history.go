package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/querylog"
)

// purgeChunk limita cada DELETE, para não segurar o banco por muito tempo.
const purgeChunk = 20_000

func (s *Store) InsertQueries(es []querylog.Entry) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := tx.Prepare(`INSERT INTO queries (ts, client_ip, client_id, name, qtype, status, rcode, rule, upstream, duration_us)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, e := range es {
		if _, err := st.Exec(e.Time.UnixMilli(), e.ClientIP, e.ClientID, e.Name, e.Type, e.Status, e.Rcode,
			e.Rule, e.Upstream, int64(e.DurationMS*1000)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) AddStats(stats []querylog.MinuteStat, tops []querylog.DomainCount) error {
	if len(stats) == 0 && len(tops) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if len(stats) > 0 {
		st, err := tx.Prepare(`INSERT INTO stats_minute
			(minute, client_id, total, forwarded, cached, blocked, isolated, local, refused, errors, forward_us)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(minute, client_id) DO UPDATE SET
				total = total + excluded.total, forwarded = forwarded + excluded.forwarded,
				cached = cached + excluded.cached, blocked = blocked + excluded.blocked,
				isolated = isolated + excluded.isolated, local = local + excluded.local,
				refused = refused + excluded.refused, errors = errors + excluded.errors,
				forward_us = forward_us + excluded.forward_us`)
		if err != nil {
			return err
		}
		defer st.Close()
		for _, m := range stats {
			c := m.Counts
			if _, err := st.Exec(m.Minute, m.ClientID, c.Total, c.Forwarded, c.Cached, c.Blocked,
				c.Isolated, c.Local, c.Refused, c.Errors, c.ForwardUS); err != nil {
				return err
			}
		}
	}
	if len(tops) > 0 {
		st, err := tx.Prepare(`INSERT INTO top_domains_hour (hour, blocked, name, count) VALUES (?, ?, ?, ?)
			ON CONFLICT(hour, blocked, name) DO UPDATE SET count = count + excluded.count`)
		if err != nil {
			return err
		}
		defer st.Close()
		for _, d := range tops {
			if _, err := st.Exec(d.Hour, d.Blocked, d.Name, d.Count); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (s *Store) Purge(queriesBefore, statsBefore time.Time) (int64, error) {
	var total int64
	for {
		res, err := s.db.Exec(`DELETE FROM queries WHERE id IN (SELECT id FROM queries WHERE ts < ? LIMIT ?)`,
			queriesBefore.UnixMilli(), purgeChunk)
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
		if n < purgeChunk {
			break
		}
	}
	if _, err := s.db.Exec(`DELETE FROM stats_minute WHERE minute < ?`, statsBefore.Unix()/60); err != nil {
		return total, err
	}
	_, err := s.db.Exec(`DELETE FROM top_domains_hour WHERE hour < ?`, statsBefore.Unix()/3600)
	return total, err
}

// HistoryQuery busca consultas, das mais novas para as mais antigas. BeforeID
// pagina: passe o menor id da página anterior.
type HistoryQuery struct {
	querylog.Filter
	From, To time.Time
	BeforeID int64
	Limit    int
}

func (s *Store) History(q HistoryQuery) ([]querylog.Entry, error) {
	where, args := []string{"ts >= ?", "ts <= ?"}, []any{q.From.UnixMilli(), q.To.UnixMilli()}
	if q.BeforeID > 0 {
		where, args = append(where, "id < ?"), append(args, q.BeforeID)
	}
	if len(q.ClientIDs) > 0 {
		where = append(where, "client_id IN ("+placeholders(len(q.ClientIDs))+")")
		args = appendStrings(args, q.ClientIDs)
	}
	if q.ClientIP != "" {
		where, args = append(where, "client_ip = ?"), append(args, q.ClientIP)
	}
	if len(q.Statuses) > 0 {
		where = append(where, "status IN ("+placeholders(len(q.Statuses))+")")
		args = appendStrings(args, q.Statuses)
	}
	if len(q.Types) > 0 {
		where = append(where, "qtype IN ("+placeholders(len(q.Types))+")")
		args = appendStrings(args, q.Types)
	}
	if q.Search != "" {
		where, args = append(where, `name LIKE ? ESCAPE '\'`), append(args, "%"+escapeLike(strings.ToLower(q.Search))+"%")
	}
	limit := min(max(q.Limit, 1), 1000)
	rows, err := s.db.Query(`SELECT id, ts, client_ip, client_id, name, qtype, status, rcode, rule, upstream, duration_us
		FROM queries WHERE `+strings.Join(where, " AND ")+` ORDER BY id DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []querylog.Entry{}
	for rows.Next() {
		var (
			e      querylog.Entry
			ts, us int64
		)
		if err := rows.Scan(&e.ID, &ts, &e.ClientIP, &e.ClientID, &e.Name, &e.Type, &e.Status, &e.Rcode,
			&e.Rule, &e.Upstream, &us); err != nil {
			return nil, err
		}
		e.Time, e.DurationMS = time.UnixMilli(ts), float64(us)/1000
		out = append(out, e)
	}
	return out, rows.Err()
}

// Bucket é um ponto da série temporal.
type Bucket struct {
	Time time.Time `json:"time"`
	querylog.Counts
	AvgForwardMS float64 `json:"avg_forward_ms"`
}

// Timeseries soma os resumos por minuto em intervalos de step (múltiplo de 1 min).
func (s *Store) Timeseries(from, to time.Time, step time.Duration, clientIDs []string) ([]Bucket, error) {
	stepMin := max(int64(step/time.Minute), 1)
	first, last := from.Unix()/60/stepMin*stepMin, to.Unix()/60
	where, args := "minute >= ? AND minute <= ?", []any{first, last}
	if len(clientIDs) > 0 {
		where += " AND client_id IN (" + placeholders(len(clientIDs)) + ")"
		args = appendStrings(args, clientIDs)
	}
	rows, err := s.db.Query(fmt.Sprintf(`SELECT (minute / %d) * %d AS b, SUM(total), SUM(forwarded), SUM(cached),
		SUM(blocked), SUM(isolated), SUM(local), SUM(refused), SUM(errors), SUM(forward_us)
		FROM stats_minute WHERE %s GROUP BY b ORDER BY b`, stepMin, stepMin, where), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	got := map[int64]Bucket{}
	for rows.Next() {
		var (
			b int64
			c querylog.Counts
		)
		if err := rows.Scan(&b, &c.Total, &c.Forwarded, &c.Cached, &c.Blocked, &c.Isolated, &c.Local,
			&c.Refused, &c.Errors, &c.ForwardUS); err != nil {
			return nil, err
		}
		got[b] = bucket(time.Unix(b*60, 0), c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Preenche os intervalos sem consulta com zero, para o gráfico não pular.
	var out []Bucket
	for b := first; b <= last; b += stepMin {
		if v, ok := got[b]; ok {
			out = append(out, v)
		} else {
			out = append(out, Bucket{Time: time.Unix(b*60, 0)})
		}
	}
	return out, nil
}

// Summary soma o período inteiro e conta os clientes ativos.
func (s *Store) Summary(from, to time.Time, clientIDs []string) (Bucket, int, error) {
	where, args := "minute >= ? AND minute <= ?", []any{from.Unix() / 60, to.Unix() / 60}
	if len(clientIDs) > 0 {
		where += " AND client_id IN (" + placeholders(len(clientIDs)) + ")"
		args = appendStrings(args, clientIDs)
	}
	var (
		c       querylog.Counts
		clients int
	)
	err := s.db.QueryRow(`SELECT COALESCE(SUM(total),0), COALESCE(SUM(forwarded),0), COALESCE(SUM(cached),0),
		COALESCE(SUM(blocked),0), COALESCE(SUM(isolated),0), COALESCE(SUM(local),0), COALESCE(SUM(refused),0),
		COALESCE(SUM(errors),0), COALESCE(SUM(forward_us),0), COUNT(DISTINCT NULLIF(client_id, ''))
		FROM stats_minute WHERE `+where, args...).Scan(&c.Total, &c.Forwarded, &c.Cached, &c.Blocked,
		&c.Isolated, &c.Local, &c.Refused, &c.Errors, &c.ForwardUS, &clients)
	return bucket(from, c), clients, err
}

func bucket(t time.Time, c querylog.Counts) Bucket {
	b := Bucket{Time: t, Counts: c}
	if c.Forwarded > 0 {
		b.AvgForwardMS = float64(c.ForwardUS) / float64(c.Forwarded) / 1000
	}
	return b
}

// Ranked é um item de ranking (domínio ou cliente).
type Ranked struct {
	Key     string `json:"key"`
	Count   int64  `json:"count"`
	Blocked int64  `json:"blocked,omitempty"`
}

// TopDomains usa os resumos por hora; com clientID, usa o histórico detalhado
// (só alcança a retenção das linhas).
func (s *Store) TopDomains(from, to time.Time, blocked bool, clientID string, limit int) ([]Ranked, error) {
	limit = min(max(limit, 1), 100)
	var rows *sql.Rows
	var err error
	if clientID == "" {
		rows, err = s.db.Query(`SELECT name, SUM(count) AS n FROM top_domains_hour
			WHERE hour >= ? AND hour <= ? AND blocked = ? GROUP BY name ORDER BY n DESC LIMIT ?`,
			from.Unix()/3600, to.Unix()/3600, blocked, limit)
	} else {
		cond := "status NOT IN ('blocked', 'isolated')"
		if blocked {
			cond = "status IN ('blocked', 'isolated')"
		}
		rows, err = s.db.Query(`SELECT name, COUNT(*) AS n FROM queries
			WHERE client_id = ? AND ts >= ? AND ts <= ? AND `+cond+` AND status NOT IN ('refused', 'invalid')
			GROUP BY name ORDER BY n DESC LIMIT ?`, clientID, from.UnixMilli(), to.UnixMilli(), limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Ranked{}
	for rows.Next() {
		var r Ranked
		if err := rows.Scan(&r.Key, &r.Count); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// TopClients ordena os clientes por número de consultas no período.
func (s *Store) TopClients(from, to time.Time, limit int) ([]Ranked, error) {
	limit = min(max(limit, 1), 100)
	rows, err := s.db.Query(`SELECT client_id, SUM(total) AS n, SUM(blocked) + SUM(isolated) FROM stats_minute
		WHERE minute >= ? AND minute <= ? AND client_id != '' GROUP BY client_id ORDER BY n DESC LIMIT ?`,
		from.Unix()/60, to.Unix()/60, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Ranked{}
	for rows.Next() {
		var r Ranked
		if err := rows.Scan(&r.Key, &r.Count, &r.Blocked); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func placeholders(n int) string { return strings.TrimSuffix(strings.Repeat("?,", n), ",") }

func appendStrings(args []any, ss []string) []any {
	for _, s := range ss {
		args = append(args, s)
	}
	return args
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}
