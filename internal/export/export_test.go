package export

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/server"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

func TestFileAndSyslog(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	file := filepath.Join(t.TempDir(), "log", "events.json")
	x, err := New(Options{File: file, Syslog: "udp://" + pc.LocalAddr().String(), Queries: QueriesBlocked, Hostname: "dns01"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { x.Run(ctx); close(done) }()

	x.Security(store.SecurityEvent{ID: 7, LastSeen: time.Now(), Kind: "dga", Severity: "high", ClientID: "c1",
		ClientIP: "192.168.0.5", Summary: "teste", Count: 2}, "Notebook", "isolated")
	q := server.Event{Time: time.Now(), Client: netip.MustParseAddr("192.168.0.5"), Name: "ads.com.", Type: "A",
		Status: server.StatusBlocked, Rule: "||ads.com^"}
	x.Query(q)
	q.Status = server.StatusForwarded
	x.Query(q) // queries=blocked: não exporta

	buf := make([]byte, 4096)
	pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	msg := string(buf[:n])
	// <PRI>: local0 (16*8) + err (3) = 131
	if !strings.HasPrefix(msg, "<131>1 ") || !strings.Contains(msg, " dns01 heimdalldns - - - {") {
		t.Errorf("syslog = %q", msg)
	}

	cancel()
	<-done
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("linha não é JSON: %v", err)
		}
		lines = append(lines, m)
	}
	if len(lines) != 2 {
		t.Fatalf("linhas = %d", len(lines))
	}
	sec, qry := lines[0], lines[1]
	if sec["event_type"] != "security" || sec["kind"] != "dga" || sec["response"] != "isolated" || sec["srcip"] != "192.168.0.5" ||
		sec["app"] != "heimdalldns" || sec["client"].(map[string]any)["name"] != "Notebook" {
		t.Errorf("alerta = %v", sec)
	}
	if qry["event_type"] != "query" || qry["result"] != "blocked" || qry["domain"] != "ads.com" {
		t.Errorf("consulta = %v", qry)
	}
	for _, static := range []string{"action", "status"} { // campos estáticos do Wazuh
		if _, ok := sec[static]; ok {
			t.Errorf("não usar o campo %q (estático no Wazuh)", static)
		}
	}
}

func TestRotate(t *testing.T) {
	file := filepath.Join(t.TempDir(), "e.json")
	x, _ := New(Options{File: file})
	x.fileSize = maxFileSize - 10
	x.write(record{line: []byte(`{"a":1}`)})
	x.write(record{line: []byte(`{"b":2}`)})
	x.close()
	if _, err := os.Stat(file + ".1"); err != nil {
		t.Error("deveria ter girado para .1")
	}
	b, _ := os.ReadFile(file)
	if string(b) != "{\"a\":1}\n{\"b\":2}\n" && string(b) != "{\"b\":2}\n" {
		t.Errorf("arquivo novo = %q", b)
	}
}

func TestDisabled(t *testing.T) {
	x, err := New(Options{})
	if err != nil || x.Enabled() {
		t.Fatal("sem destino = desligado")
	}
	x.Query(server.Event{}) // não bloqueia nem quebra
	if _, err := New(Options{Syslog: "http://x"}); err == nil {
		t.Error("esquema inválido")
	}
	if _, err := New(Options{Queries: "algumas"}); err == nil {
		t.Error("queries inválido")
	}
}
