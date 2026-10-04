// Package querylog guarda o histórico de consultas: linhas detalhadas (com
// retenção curta), resumos por minuto e por hora (retenção longa), o log ao
// vivo e o tráfego por segundo.
package querylog

import (
	"strings"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/server"
)

// Entry é uma consulta no histórico e no log ao vivo.
type Entry struct {
	ID         int64     `json:"id,omitempty"`
	Time       time.Time `json:"time"`
	ClientIP   string    `json:"client_ip"`
	ClientID   string    `json:"client_id,omitempty"`
	ClientName string    `json:"client_name,omitempty"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Status     string    `json:"status"`
	Rcode      string    `json:"rcode"`
	Rule       string    `json:"rule,omitempty"`
	Category   string    `json:"category,omitempty"`
	Upstream   string    `json:"upstream,omitempty"`
	DurationMS float64   `json:"duration_ms"`
}

func fromEvent(e server.Event) Entry {
	ip := ""
	if e.Client.IsValid() {
		ip = e.Client.String()
	}
	return Entry{
		Time: e.Time, ClientIP: ip, ClientID: e.ClientID, ClientName: e.Display,
		Name: strings.TrimSuffix(e.Name, "."), Type: e.Type, Status: e.Status, Rcode: e.Rcode,
		Rule: e.Rule, Category: e.Category, Upstream: e.Upstream,
		DurationMS: float64(e.Duration.Microseconds()) / 1000,
	}
}

// Counts soma consultas por resultado.
type Counts struct {
	Total     int64 `json:"total"`
	Forwarded int64 `json:"forwarded"`
	Cached    int64 `json:"cached"`
	Blocked   int64 `json:"blocked"`
	Isolated  int64 `json:"isolated"`
	Local     int64 `json:"local"`
	Refused   int64 `json:"refused"`
	Errors    int64 `json:"errors"`
	// Soma do tempo de resposta das encaminhadas, para a latência média.
	ForwardUS int64 `json:"-"`
}

func (c *Counts) add(status string, d time.Duration) {
	c.Total++
	switch status {
	case server.StatusForwarded:
		c.Forwarded++
		c.ForwardUS += d.Microseconds()
	case server.StatusCached, server.StatusStale:
		c.Cached++
	case server.StatusBlocked:
		c.Blocked++
	case server.StatusIsolated:
		c.Isolated++
	case server.StatusLocal:
		c.Local++
	case server.StatusRefused:
		c.Refused++
	case server.StatusError:
		c.Errors++
	}
}

func (c *Counts) merge(o Counts) {
	c.Total += o.Total
	c.Forwarded += o.Forwarded
	c.Cached += o.Cached
	c.Blocked += o.Blocked
	c.Isolated += o.Isolated
	c.Local += o.Local
	c.Refused += o.Refused
	c.Errors += o.Errors
	c.ForwardUS += o.ForwardUS
}

// MinuteStat é o resumo de um cliente num minuto.
type MinuteStat struct {
	Minute   int64 // Unix / 60
	ClientID string
	Counts
}

// DomainCount conta um domínio numa hora (permitido ou bloqueado).
type DomainCount struct {
	Hour    int64 // Unix / 3600
	Name    string
	Blocked bool
	Count   int64
}

// Sink é onde o histórico é gravado (o store SQLite).
type Sink interface {
	InsertQueries([]Entry) error
	AddStats([]MinuteStat, []DomainCount) error
	Purge(queriesBefore, statsBefore time.Time) (int64, error)
}

// Filter seleciona consultas no histórico e no log ao vivo.
type Filter struct {
	ClientIDs []string // vazio = todos (o API resolve id/IP/MAC/nome)
	ClientIP  string
	Statuses  []string
	Types     []string
	Search    string // pedaço do nome, sem diferenciar caixa
}

func (f *Filter) Match(e *Entry) bool {
	if len(f.ClientIDs) > 0 && !contains(f.ClientIDs, e.ClientID) {
		return false
	}
	if f.ClientIP != "" && f.ClientIP != e.ClientIP {
		return false
	}
	if len(f.Statuses) > 0 && !contains(f.Statuses, e.Status) {
		return false
	}
	if len(f.Types) > 0 && !contains(f.Types, e.Type) {
		return false
	}
	if f.Search != "" && !strings.Contains(e.Name, strings.ToLower(f.Search)) {
		return false
	}
	return true
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
