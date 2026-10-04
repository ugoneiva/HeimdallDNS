package security

import (
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/clients"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

type fakeExport struct {
	got []string // tipo + resposta
}

func (f *fakeExport) Security(ev store.SecurityEvent, _ string, response string) {
	f.got = append(f.got, ev.Kind+":"+response)
}

func setup(t *testing.T, s Settings) (*Manager, *store.Store, *clients.Registry, *fakeExport) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	reg, _ := clients.NewRegistry(clients.Options{})
	exp := &fakeExport{}
	if s.NRDAction == "" {
		s.NRDAction, s.NRDMaxDays = "alert", 30
	}
	m, err := New(Options{Store: st, Clients: reg, Exporter: exp, Defaults: s})
	if err != nil {
		t.Fatal(err)
	}
	return m, st, reg, exp
}

func TestDedupAndExport(t *testing.T) {
	m, st, _, exp := setup(t, Settings{})
	now := time.Now()
	a := Alert{Time: now, Kind: KindThreat, Severity: SevHigh, ClientID: "c1", ClientIP: "10.0.0.1", Domain: "ruim.com", Summary: "x"}
	m.Raise(a)
	a.Time = now.Add(time.Minute)
	m.Raise(a)
	a.Time = now.Add(2 * time.Minute)
	m.Raise(a)
	evs, _ := st.Events(store.EventQuery{Since: now.Add(-time.Hour), Limit: 10})
	if len(evs) != 1 || evs[0].Count != 3 {
		t.Fatalf("deduplicação: %+v", evs)
	}
	if len(exp.got) != 1 {
		t.Errorf("repetições em 10 min não são reexportadas: %v", exp.got)
	}
	// Outro domínio: alerta separado.
	a.Domain = "outro.com"
	m.Raise(a)
	if evs, _ := st.Events(store.EventQuery{Since: now.Add(-time.Hour), Limit: 10}); len(evs) != 2 {
		t.Errorf("domínio diferente = alerta novo: %d", len(evs))
	}
	// Reconhecido e repetido: volta a abrir.
	st.SetEventStatus(0, "ack")
	m.Raise(a)
	if evs, _ := st.Events(store.EventQuery{Since: now.Add(-time.Hour), Status: "open", Limit: 10}); len(evs) != 1 {
		t.Errorf("repetição reabre o alerta: %d abertos", len(evs))
	}
}

func TestAutoIsolate(t *testing.T) {
	m, _, reg, exp := setup(t, Settings{AutoIsolate: []string{KindDGA}})
	c := reg.Observe(netip.MustParseAddr("192.168.0.50"), time.Now())
	m.Raise(Alert{Kind: KindThreat, Severity: SevHigh, ClientID: c.ID(), Domain: "a.com", Summary: "ameaça"})
	if c.Policy().Isolated {
		t.Fatal("ameaça não está na lista de isolamento automático")
	}
	m.Raise(Alert{Kind: KindDGA, Severity: SevHigh, ClientID: c.ID(), Summary: "dga"})
	if !c.Policy().Isolated {
		t.Fatal("DGA deveria isolar")
	}
	if exp.got[len(exp.got)-1] != "dga:isolated" {
		t.Errorf("exportação deve dizer que isolou: %v", exp.got)
	}
}

func TestIgnoreAndValidate(t *testing.T) {
	m, st, _, _ := setup(t, Settings{Ignore: []string{"Sophosxl.NET."}})
	if m.Settings().Ignore[0] != "sophosxl.net" {
		t.Errorf("normalização: %v", m.Settings().Ignore)
	}
	m.Raise(Alert{Kind: KindTunnel, Severity: SevHigh, Domain: "sophosxl.net", Summary: "x"})
	if evs, _ := st.Events(store.EventQuery{Since: time.Now().Add(-time.Hour), Limit: 10}); len(evs) != 0 {
		t.Error("domínio ignorado não gera alerta")
	}
	bad := m.Settings()
	bad.NRDAction = "explodir"
	if m.SetSettings(bad) == nil {
		t.Error("nrd_action inválido")
	}
	bad = m.Settings()
	bad.AutoIsolate = []string{KindNewDevice}
	if m.SetSettings(bad) == nil {
		t.Error("dispositivo novo não pode isolar automaticamente")
	}
	ok := m.Settings()
	ok.DGA = true
	if err := m.SetSettings(ok); err != nil || !m.Settings().DGA {
		t.Errorf("salvar: %v", err)
	}
	// Persistiu: um gerente novo lê do banco.
	m2, _ := New(Options{Store: st, Defaults: Settings{NRDAction: "alert", NRDMaxDays: 30}})
	if !m2.Settings().DGA {
		t.Error("configurações do painel devem valer sobre os padrões")
	}
}

func TestSettingsNeverNull(t *testing.T) {
	m, err := New(Options{Defaults: Settings{NRDAction: "alert", NRDMaxDays: 30}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(m.Settings())
	if strings.Contains(string(b), "null") {
		t.Errorf("listas vazias saíram como null: %s", b)
	}
}
