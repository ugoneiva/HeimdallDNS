package store

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/querylog"
	"github.com/ugoneiva/HeimdallDNS/internal/server"
)

// Grava pelo Recorder de verdade, num SQLite de verdade.
func recordAll(t *testing.T, s *Store, evs []server.Event, storeQueries bool) {
	t.Helper()
	rec := querylog.New(querylog.Options{Sink: s, StoreQueries: storeQueries, Retention: 24 * time.Hour, StatsRetention: 30 * 24 * time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	go rec.Run(ctx)
	for _, e := range evs {
		rec.Record(e)
	}
	cancel()
	<-rec.Done()
	if ev, rows := rec.Dropped(); ev+rows != 0 {
		t.Fatalf("perdeu %d eventos, %d linhas", ev, rows)
	}
}

func ev(t time.Time, client, id, name, status string) server.Event {
	return server.Event{
		Time: t, Client: netip.MustParseAddr(client), ClientID: id, Name: name + ".", Type: "A",
		Status: status, Rcode: "NOERROR", Duration: 2 * time.Millisecond,
	}
}

func TestHistoryAndStats(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	base := time.Now().Truncate(time.Hour).Add(-2 * time.Hour)
	var evs []server.Event
	for i := range 30 { // TV: 30 consultas no minuto 0, 10 bloqueadas
		st := server.StatusForwarded
		name := "netflix.com"
		if i%3 == 0 {
			st, name = server.StatusBlocked, "ads.tracker.com"
		}
		evs = append(evs, ev(base.Add(time.Duration(i)*time.Second), "192.168.0.10", "tv", name, st))
	}
	for i := range 5 { // notebook: 5 consultas 20 minutos depois, do cache
		evs = append(evs, ev(base.Add(20*time.Minute+time.Duration(i)*time.Second), "192.168.0.20", "note", "github.com", server.StatusCached))
	}
	evs = append(evs, ev(base.Add(21*time.Minute), "192.168.0.20", "note", "c2.mal.com", server.StatusIsolated))
	recordAll(t, s, evs, true)

	from, to := base.Add(-time.Minute), base.Add(time.Hour)

	// Histórico com filtros e paginação.
	all, err := s.History(HistoryQuery{From: from, To: to, Limit: 1000})
	if err != nil || len(all) != 36 {
		t.Fatalf("histórico: %d, %v", len(all), err)
	}
	if all[0].Name != "c2.mal.com" || all[0].DurationMS != 2 {
		t.Errorf("mais recente primeiro: %+v", all[0])
	}
	blk, _ := s.History(HistoryQuery{From: from, To: to, Limit: 100,
		Filter: querylog.Filter{ClientIDs: []string{"tv"}, Statuses: []string{server.StatusBlocked}}})
	if len(blk) != 10 {
		t.Errorf("bloqueadas da TV = %d", len(blk))
	}
	srch, _ := s.History(HistoryQuery{From: from, To: to, Limit: 100, Filter: querylog.Filter{Search: "TRACKER"}})
	if len(srch) != 10 {
		t.Errorf("busca = %d", len(srch))
	}
	if like, _ := s.History(HistoryQuery{From: from, To: to, Limit: 100, Filter: querylog.Filter{Search: "%"}}); len(like) != 0 {
		t.Error("% deve ser literal na busca")
	}
	p1, _ := s.History(HistoryQuery{From: from, To: to, Limit: 20})
	p2, _ := s.History(HistoryQuery{From: from, To: to, Limit: 20, BeforeID: p1[19].ID})
	if len(p1) != 20 || len(p2) != 16 || p2[0].ID >= p1[19].ID {
		t.Errorf("paginação: %d + %d", len(p1), len(p2))
	}

	// Resumo.
	sum, active, err := s.Summary(from, to, nil)
	if err != nil || sum.Total != 36 || sum.Blocked != 10 || sum.Isolated != 1 || sum.Cached != 5 || active != 2 {
		t.Errorf("resumo = %+v, ativos %d, %v", sum.Counts, active, err)
	}
	if sum.AvgForwardMS != 2 {
		t.Errorf("latência média = %v", sum.AvgForwardMS)
	}
	if tv, _, _ := s.Summary(from, to, []string{"tv"}); tv.Total != 30 {
		t.Errorf("resumo da TV = %d", tv.Total)
	}

	// Série de 10 em 10 minutos, com os intervalos vazios preenchidos.
	pts, err := s.Timeseries(base, base.Add(59*time.Minute), 10*time.Minute, nil)
	if err != nil || len(pts) != 6 {
		t.Fatalf("série: %d pontos, %v", len(pts), err)
	}
	if pts[0].Total != 30 || pts[1].Total != 0 || pts[2].Total != 6 {
		t.Errorf("série = %d %d %d", pts[0].Total, pts[1].Total, pts[2].Total)
	}

	// Rankings.
	top, _ := s.TopDomains(from, to, false, "", 10)
	if len(top) != 2 || top[0].Key != "netflix.com" || top[0].Count != 20 {
		t.Errorf("top permitidos = %+v", top)
	}
	topBlk, _ := s.TopDomains(from, to, true, "", 10)
	if len(topBlk) != 2 || topBlk[0].Key != "ads.tracker.com" || topBlk[0].Count != 10 {
		t.Errorf("top bloqueados = %+v", topBlk)
	}
	if mine, _ := s.TopDomains(from, to, true, "note", 10); len(mine) != 1 || mine[0].Key != "c2.mal.com" {
		t.Errorf("top bloqueados do notebook = %+v", mine)
	}
	cl, _ := s.TopClients(from, to, 10)
	if len(cl) != 2 || cl[0].Key != "tv" || cl[0].Count != 30 || cl[0].Blocked != 10 || cl[1].Blocked != 1 {
		t.Errorf("top clientes = %+v", cl)
	}

	// Limpeza: linhas antes de base+10min saem; resumos ficam.
	n, err := s.Purge(base.Add(10*time.Minute), base.Add(-time.Hour))
	if err != nil || n != 30 {
		t.Errorf("purge removeu %d, %v", n, err)
	}
	if sum, _, _ := s.Summary(from, to, nil); sum.Total != 36 {
		t.Error("resumos não podiam ter saído")
	}
}

func TestStatsWithoutRawRows(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	recordAll(t, s, []server.Event{ev(now, "10.0.0.1", "a", "x.com", server.StatusForwarded)}, false)
	if rows, _ := s.History(HistoryQuery{From: now.Add(-time.Hour), To: now.Add(time.Hour), Limit: 10}); len(rows) != 0 {
		t.Error("store_queries=false não grava linhas")
	}
	if sum, _, _ := s.Summary(now.Add(-time.Hour), now.Add(time.Hour), nil); sum.Total != 1 {
		t.Error("o resumo é sempre gravado")
	}
}
