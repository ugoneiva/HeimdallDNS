package store

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/clients"
)

func TestClientsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "h.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Millisecond)
	rec := clients.Record{
		ID: "abcd1234", MAC: "aa:bb:cc:dd:ee:ff", Vendor: "ACME", Hostname: "tv.casa",
		IPs:       []netip.Addr{netip.MustParseAddr("192.168.0.5"), netip.MustParseAddr("fe80::1")},
		FirstSeen: now.Add(-time.Hour), LastSeen: now, Queries: 42, Blocked: 7,
		Settings: clients.Settings{Name: "TV", Isolated: true, IsolateMode: "drop", Deny: []string{"service:tiktok"}},
	}
	if err := s.SaveClients([]clients.Record{rec}); err != nil {
		t.Fatal(err)
	}
	rec.Queries = 43 // atualização (upsert)
	if err := s.SaveClients([]clients.Record{rec}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s, err = Open(path) // reabre: a migração não pode rodar de novo
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.LoadClients()
	if err != nil || len(got) != 1 {
		t.Fatalf("Load: %v, %d", err, len(got))
	}
	g := got[0]
	if g.ID != rec.ID || g.Queries != 43 || g.Blocked != 7 || len(g.IPs) != 2 || g.IPs[1] != rec.IPs[1] ||
		!g.LastSeen.Equal(rec.LastSeen) || !g.Settings.Isolated || g.Settings.Deny[0] != "service:tiktok" {
		t.Errorf("recarregado = %+v", g)
	}
	if err := s.DeleteClient(rec.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.LoadClients(); len(got) != 0 {
		t.Error("deveria ter apagado")
	}
}
