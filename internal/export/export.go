// Package export manda alertas de segurança (e, se pedido, as consultas) para
// um SIEM: arquivo JSON por linha (lido pelo agente do Wazuh) e/ou syslog.
//
// Os nomes dos campos evitam os campos estáticos do Wazuh ("action", "status"
// etc.), que não casam com <field> nas regras; "srcip" é usado de propósito,
// para a resposta ativa do Wazuh poder agir sobre o IP do dispositivo.
package export

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/server"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

// O que exportar das consultas.
const (
	QueriesNone    = "none"
	QueriesBlocked = "blocked" // bloqueadas e isoladas
	QueriesAll     = "all"
)

const (
	maxFileSize = 50 << 20 // gira o arquivo ao passar de 50 MiB (mantém um .1)
	bufferSize  = 20_000
	appName     = "heimdalldns"
)

type Options struct {
	File     string // caminho do arquivo JSON; "" desliga
	Syslog   string // udp://host:514 ou tcp://host:514; "" desliga
	Queries  string // none, blocked ou all
	Hostname string
	Logger   *slog.Logger
}

type record struct {
	severity int // severidade syslog (RFC 5424)
	line     []byte
}

type Exporter struct {
	opts    Options
	log     *slog.Logger
	ch      chan record
	dropped atomic.Uint64

	file     *os.File
	fileSize int64
	network  string
	addr     string
	conn     net.Conn
}

func New(opts Options) (*Exporter, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Queries == "" {
		opts.Queries = QueriesNone
	}
	switch opts.Queries {
	case QueriesNone, QueriesBlocked, QueriesAll:
	default:
		return nil, fmt.Errorf("export.queries %q: use none, blocked ou all", opts.Queries)
	}
	if opts.Hostname == "" {
		opts.Hostname, _ = os.Hostname()
	}
	x := &Exporter{opts: opts, log: opts.Logger, ch: make(chan record, bufferSize)}
	if opts.Syslog != "" {
		u, err := url.Parse(opts.Syslog)
		if err != nil || (u.Scheme != "udp" && u.Scheme != "tcp") || u.Host == "" {
			return nil, fmt.Errorf("export.syslog %q: use udp://host:porta ou tcp://host:porta", opts.Syslog)
		}
		x.network, x.addr = u.Scheme, u.Host
		if u.Port() == "" {
			x.addr = net.JoinHostPort(u.Host, "514")
		}
	}
	if opts.File != "" {
		if err := x.openFile(); err != nil {
			return nil, err
		}
	}
	return x, nil
}

// Enabled diz se há algum destino configurado.
func (x *Exporter) Enabled() bool { return x != nil && (x.opts.File != "" || x.opts.Syslog != "") }

func (x *Exporter) openFile() error {
	if err := os.MkdirAll(filepath.Dir(x.opts.File), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(x.opts.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("export.file: %w", err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	x.file, x.fileSize = f, fi.Size()
	return nil
}

type client struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	IP   string `json:"ip,omitempty"`
}

var syslogSeverity = map[string]int{
	"critical": 2, // crit
	"high":     3, // err
	"medium":   4, // warning
	"low":      5, // notice
}

// Security exporta um alerta. response: alert ou isolated.
func (x *Exporter) Security(ev store.SecurityEvent, clientName, response string) {
	if !x.Enabled() {
		return
	}
	x.send(syslogSeverity[ev.Severity], map[string]any{
		"timestamp":  ev.LastSeen.UTC().Format(time.RFC3339Nano),
		"app":        appName,
		"event_type": "security",
		"event_id":   ev.ID,
		"kind":       ev.Kind,
		"severity":   ev.Severity,
		"summary":    ev.Summary,
		"domain":     ev.Domain,
		"srcip":      ev.ClientIP,
		"client":     client{ID: ev.ClientID, Name: clientName, IP: ev.ClientIP},
		"count":      ev.Count,
		"response":   response,
		"details":    ev.Details,
	})
}

// Audit exporta uma operação administrativa (ex.: alteração no AD).
func (x *Exporter) Audit(e store.AuditEntry) {
	if !x.Enabled() {
		return
	}
	sev := 5 // notice
	if !e.OK {
		sev = 4
	}
	x.send(sev, map[string]any{
		"timestamp":  e.Time.UTC().Format(time.RFC3339Nano),
		"app":        appName,
		"event_type": "audit",
		"event_id":   e.ID,
		"operation":  e.Action,
		"target":     e.Target,
		"actor":      e.Actor,
		"srcip":      e.IP,
		"success":    e.OK,
		"error":      e.Error,
		"details":    e.Details,
	})
}

// Query exporta uma consulta, conforme export.queries. Chamado em toda
// consulta: descarta cedo o que não vai ser exportado.
func (x *Exporter) Query(e server.Event) {
	if !x.Enabled() || x.opts.Queries == QueriesNone {
		return
	}
	blocked := e.Status == server.StatusBlocked || e.Status == server.StatusIsolated
	if x.opts.Queries == QueriesBlocked && !blocked {
		return
	}
	sev := 6 // info
	if blocked {
		sev = 5
	}
	ip := ""
	if e.Client.IsValid() {
		ip = e.Client.String()
	}
	x.send(sev, map[string]any{
		"timestamp":   e.Time.UTC().Format(time.RFC3339Nano),
		"app":         appName,
		"event_type":  "query",
		"domain":      strings.TrimSuffix(e.Name, "."),
		"qtype":       e.Type,
		"result":      e.Status,
		"rcode":       e.Rcode,
		"rule":        e.Rule,
		"category":    e.Category,
		"srcip":       ip,
		"client":      client{ID: e.ClientID, Name: e.Display, IP: ip},
		"upstream":    e.Upstream,
		"duration_ms": float64(e.Duration.Microseconds()) / 1000,
	})
}

func (x *Exporter) send(sev int, v map[string]any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	select {
	case x.ch <- record{severity: sev, line: b}:
	default:
		x.dropped.Add(1)
	}
}

// Dropped conta registros descartados (destino lento ou fora do ar).
func (x *Exporter) Dropped() uint64 {
	if x == nil {
		return 0
	}
	return x.dropped.Load()
}

// Run grava até ctx terminar; esvazia a fila antes de voltar.
func (x *Exporter) Run(ctx context.Context) {
	if !x.Enabled() {
		return
	}
	defer x.close()
	for {
		select {
		case r := <-x.ch:
			x.write(r)
		case <-ctx.Done():
			for {
				select {
				case r := <-x.ch:
					x.write(r)
				default:
					return
				}
			}
		}
	}
}

func (x *Exporter) write(r record) {
	if x.file != nil {
		if x.fileSize+int64(len(r.line))+1 > maxFileSize {
			x.rotate()
		}
		if x.file != nil {
			n, err := x.file.Write(append(r.line, '\n'))
			x.fileSize += int64(n)
			if err != nil {
				x.log.Error("falha ao gravar exportação", "arquivo", x.opts.File, "erro", err)
			}
		}
	}
	if x.network != "" {
		x.syslog(r)
	}
}

func (x *Exporter) rotate() {
	x.file.Close()
	x.file = nil
	if err := os.Rename(x.opts.File, x.opts.File+".1"); err != nil {
		x.log.Error("falha ao girar exportação", "erro", err)
	}
	if err := x.openFile(); err != nil {
		x.log.Error("falha ao reabrir exportação", "erro", err)
	}
}

// syslog envia no formato RFC 5424, facility local0, com o JSON na mensagem
// (o Wazuh decodifica o JSON depois do cabeçalho syslog).
func (x *Exporter) syslog(r record) {
	if x.conn == nil {
		c, err := net.DialTimeout(x.network, x.addr, 3*time.Second)
		if err != nil {
			x.dropped.Add(1)
			return
		}
		x.conn = c
	}
	pri := 16*8 + r.severity
	msg := fmt.Sprintf("<%d>1 %s %s %s - - - %s\n", pri, time.Now().UTC().Format(time.RFC3339Nano), x.opts.Hostname, appName, r.line)
	_ = x.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := x.conn.Write([]byte(msg)); err != nil {
		x.dropped.Add(1)
		x.conn.Close()
		x.conn = nil // reconecta na próxima
	}
}

func (x *Exporter) close() {
	if x.file != nil {
		x.file.Close()
	}
	if x.conn != nil {
		x.conn.Close()
	}
}
