package clients

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/filter"
)

const manufSample = `# comentário
00:00:0C	Cisco	Cisco Systems, Inc
BC:F8:7E	Isons	Isons Telecom
00:55:DA:00/28	ShinkoTechno	Shinko Technos co.,ltd.
00:1B:C5:00:00/36	Converging	Converging Systems Inc.
`

func TestOUI(t *testing.T) {
	db, err := ParseOUI(strings.NewReader(manufSample))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"00:00:0c:11:22:33": "Cisco Systems, Inc",
		"BC-F8-7E-E7-78-0A": "Isons Telecom",
		"00:55:da:0f:ff:ff": "Shinko Technos co.,ltd.", // dentro do /28
		"00:55:da:10:00:00": "",                        // fora do /28
		"00:1b:c5:00:00:01": "Converging Systems Inc.", // /36
		"da:a1:19:00:00:01": PrivateMAC,                // bit local ligado
		"lixo":              "",
	}
	for mac, want := range cases {
		if got := db.Lookup(mac); got != want {
			t.Errorf("Lookup(%s) = %q, quero %q", mac, got, want)
		}
	}
	var nilDB *OUI
	if nilDB.Lookup("da:a1:19:00:00:01") != PrivateMAC {
		t.Error("sem base ainda deve reconhecer MAC privado")
	}
}

func TestParseNeighbors(t *testing.T) {
	out := `192.168.1.1 dev wlan0 lladdr bc:f8:7e:e7:78:0a REACHABLE
192.168.1.50 dev wlan0  FAILED
fe80::1 dev wlan0 lladdr bc:f8:7e:e7:78:0a router STALE
2804:14c::10 dev eth0 lladdr 00:00:00:00:00:00 STALE
`
	m := parseIPNeigh([]byte(out))
	if len(m) != 2 || m[netip.MustParseAddr("fe80::1")] != "bc:f8:7e:e7:78:0a" {
		t.Errorf("ip neigh = %v", m)
	}
	arp := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         bc:f8:7e:e7:78:0a     *        wlan0
192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        wlan0
`
	if m := parseProcARP([]byte(arp)); len(m) != 1 || m[netip.MustParseAddr("192.168.1.1")] == "" {
		t.Errorf("proc arp = %v", m)
	}
}

// memStore guarda em memória, para os testes.
type memStore struct{ recs map[string]Record }

func (m *memStore) LoadClients() ([]Record, error) {
	var out []Record
	for _, r := range m.recs {
		out = append(out, r)
	}
	return out, nil
}
func (m *memStore) SaveClients(rs []Record) error {
	for _, r := range rs {
		m.recs[r.ID] = r
	}
	return nil
}
func (m *memStore) DeleteClient(id string) error { delete(m.recs, id); return nil }

type fakeNet struct{ table map[netip.Addr]string }

func (f *fakeNet) get() (map[netip.Addr]string, error) {
	out := map[netip.Addr]string{}
	for k, v := range f.table {
		out[k] = v
	}
	return out, nil
}

func newReg(t *testing.T, st Persister, n *fakeNet) *Registry {
	t.Helper()
	r, err := NewRegistry(Options{Store: st, Neighbors: n.get})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// enrich simula o que Run faz quando um IP novo aparece.
func enrich(r *Registry, ip netip.Addr) {
	r.refreshNeighbors(true)
	r.applyNeighbor(ip)
}

var (
	ipA  = netip.MustParseAddr("192.168.1.10")
	ipB  = netip.MustParseAddr("192.168.1.20")
	ip6  = netip.MustParseAddr("2804:14c::abcd")
	macX = "aa:aa:aa:00:00:01"
	macY = "aa:aa:aa:00:00:02"
)

func TestObserveAndMAC(t *testing.T) {
	n := &fakeNet{table: map[netip.Addr]string{ipA: macX}}
	r := newReg(t, nil, n)
	c := r.Observe(ipA, time.Now())
	if r.Observe(ipA, time.Now()) != c {
		t.Fatal("o mesmo IP deve dar o mesmo cliente")
	}
	enrich(r, ipA)
	v := c.View()
	if v.MAC != macX || v.Queries != 2 {
		t.Errorf("view = %+v", v)
	}
	if got, _ := r.Find(macX); got != c {
		t.Error("Find pelo MAC")
	}
}

func TestDHCPChangeKeepsIdentity(t *testing.T) {
	n := &fakeNet{table: map[netip.Addr]string{ipA: macX}}
	r := newReg(t, nil, n)
	c := r.Observe(ipA, time.Now())
	enrich(r, ipA)
	if err := r.Update(c, func(s *Settings) error { s.Name = "TV da sala"; return nil }); err != nil {
		t.Fatal(err)
	}

	// O aparelho ganhou outro IP pelo DHCP.
	n.table = map[netip.Addr]string{ipB: macX}
	tmp := r.Observe(ipB, time.Now())
	enrich(r, ipB)
	if got := r.lookupIP(ipB); got != c {
		t.Fatal("o IP novo deveria ir para o mesmo dispositivo")
	}
	if _, err := r.Find(tmp.ID()); err == nil {
		t.Error("o cliente provisório deveria ter sido absorvido")
	}
	if v := c.View(); v.Queries != 2 || v.Display != "TV da sala" {
		t.Errorf("view = %+v", v)
	}
}

func TestIPv6JoinsDevice(t *testing.T) {
	n := &fakeNet{table: map[netip.Addr]string{ipA: macX, ip6: macX}}
	r := newReg(t, nil, n)
	c := r.Observe(ipA, time.Now())
	enrich(r, ipA)
	r.Observe(ip6, time.Now())
	enrich(r, ip6)
	if r.lookupIP(ip6) != c || len(c.View().IPs) != 2 {
		t.Errorf("IPv6 deveria entrar no mesmo dispositivo: %+v", c.View())
	}
}

func TestIPReassignedToNewDevice(t *testing.T) {
	n := &fakeNet{table: map[netip.Addr]string{ipA: macX}}
	r := newReg(t, nil, n)
	old := r.Observe(ipA, time.Now())
	enrich(r, ipA)
	n.table = map[netip.Addr]string{ipA: macY}
	enrich(r, ipA)
	nw := r.lookupIP(ipA)
	if nw == old || nw.View().MAC != macY {
		t.Fatalf("IP deveria ir para um dispositivo novo: %+v", nw.View())
	}
	if len(old.View().IPs) != 0 || old.View().MAC != macX {
		t.Errorf("antigo = %+v", old.View())
	}
}

func TestIsolationPolicy(t *testing.T) {
	r := newReg(t, nil, &fakeNet{})
	c := r.Observe(ipA, time.Now())
	if c.Policy().IsolatedFor("google.com") {
		t.Fatal("cliente novo não está isolado")
	}
	if err := r.Isolate(c, ModeDrop, "malware", []string{"update.antivirus.com"}); err != nil {
		t.Fatal(err)
	}
	p := c.Policy()
	if !p.IsolatedFor("google.com.") || p.IsolatedFor("cdn.update.antivirus.com.") || p.IsolateMode != ModeDrop {
		t.Errorf("política = %+v", p)
	}
	if err := r.Release(c); err != nil || c.Policy().IsolatedFor("google.com") {
		t.Error("deveria ter sido liberado")
	}
	if err := r.Isolate(c, "explodir", "", nil); err == nil {
		t.Error("modo inválido deveria falhar")
	}
	if c.Policy().Isolated {
		t.Error("falha não pode mudar o estado")
	}
	if r.Isolate(c, "", "", nil) != nil || c.Policy().IsolateMode != ModeRefused {
		t.Error("sem modo deve usar o padrão")
	}
}

func TestClientRules(t *testing.T) {
	r := newReg(t, nil, &fakeNet{})
	c := r.Observe(ipA, time.Now())
	err := r.Update(c, func(s *Settings) error {
		s.Deny = []string{"service:social"}
		s.Allow = []string{"linkedin.com"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	p := c.Policy()
	if p.Match("www.instagram.com").Verdict != filter.Blocked || p.Match("static.licdn.com").Verdict != filter.Blocked {
		t.Error("service:social deveria bloquear Instagram e LinkedIn CDN")
	}
	if p.Match("www.linkedin.com").Verdict != filter.Allowed {
		t.Error("exceção do cliente deveria liberar linkedin.com")
	}
	if p.Match("github.com").Verdict != filter.Pass {
		t.Error("o resto passa")
	}
	if err := r.Update(c, func(s *Settings) error { s.Deny = []string{"service:naoexiste"}; return nil }); err == nil {
		t.Error("serviço desconhecido deveria falhar")
	}
}

func TestPersistence(t *testing.T) {
	st := &memStore{recs: map[string]Record{}}
	n := &fakeNet{table: map[netip.Addr]string{ipA: macX}}
	r := newReg(t, st, n)
	c := r.Observe(ipA, time.Now())
	enrich(r, ipA)
	c.CountBlocked()
	if err := r.Isolate(c, ModeNXDomain, "teste", nil); err != nil {
		t.Fatal(err)
	}
	r.Flush()

	r2 := newReg(t, st, n)
	c2, err := r2.Find(ipA.String())
	if err != nil {
		t.Fatal(err)
	}
	v := c2.View()
	if v.ID != c.ID() || v.MAC != macX || v.Blocked != 1 || v.Queries != 1 || !c2.Policy().IsolatedFor("x.com") {
		t.Errorf("recarregado = %+v", v)
	}
	if err := r2.Forget(c2); err != nil || len(st.recs) != 0 {
		t.Errorf("Forget: %v, %d", err, len(st.recs))
	}
}

func TestFindByName(t *testing.T) {
	r := newReg(t, nil, &fakeNet{})
	a := r.Observe(ipA, time.Now())
	b := r.Observe(ipB, time.Now())
	r.Update(a, func(s *Settings) error { s.Name = "Notebook"; return nil })
	r.Update(b, func(s *Settings) error { s.Name = "notebook"; return nil })
	if _, err := r.Find("NOTEBOOK"); err == nil {
		t.Error("nome repetido deveria pedir o id")
	}
	r.Update(b, func(s *Settings) error { s.Name = "TV"; return nil })
	if c, err := r.Find("notebook"); err != nil || c != a {
		t.Errorf("Find por nome: %v", err)
	}
	if _, err := r.Find("nada"); err != ErrNotFound {
		t.Errorf("err = %v", err)
	}
}

func TestOnNewSkipsKnownDeviceWithNewIP(t *testing.T) {
	var got []string
	n := &fakeNet{table: map[netip.Addr]string{ipA: macX}}
	r, _ := NewRegistry(Options{Neighbors: n.get, OnNew: func(id string, _ netip.Addr) { got = append(got, id) }})
	enrichNew := func(ip netip.Addr) {
		r.refreshNeighbors(true)
		r.applyNeighbor(ip)
		if c := r.lookupIP(ip); c != nil {
			r.confirmNew(c, ip)
		}
	}
	first := r.Observe(ipA, time.Now())
	enrichNew(ipA)
	if len(got) != 1 || got[0] != first.ID() {
		t.Fatalf("primeiro aparelho deveria avisar: %v", got)
	}
	// Mesmo aparelho (MAC) com IP novo: não é novo.
	n.table = map[netip.Addr]string{ipB: macX}
	r.Observe(ipB, time.Now())
	enrichNew(ipB)
	if len(got) != 1 {
		t.Errorf("troca de IP não pode avisar dispositivo novo: %v", got)
	}
	// Aparelho realmente novo.
	ipC := netip.MustParseAddr("192.168.1.30")
	n.table = map[netip.Addr]string{ipC: macY}
	r.Observe(ipC, time.Now())
	enrichNew(ipC)
	if len(got) != 2 {
		t.Errorf("aparelho novo deveria avisar: %v", got)
	}
	// Loopback nunca avisa.
	lo := netip.MustParseAddr("127.0.0.1")
	r.Observe(lo, time.Now())
	enrichNew(lo)
	if len(got) != 2 {
		t.Errorf("loopback não avisa: %v", got)
	}
}

func TestLearnLease(t *testing.T) {
	var newIDs []string
	r, _ := NewRegistry(Options{OnNew: func(id string, _ netip.Addr) { newIDs = append(newIDs, id) }})
	// Aparelho que ainda não consultou o DNS entra pelo DHCP.
	r.LearnLease(ipA, "AA:AA:AA:00:00:01", "tv-sala")
	c := r.lookupIP(ipA)
	if c == nil || c.View().MAC != macX || c.View().Hostname != "tv-sala" || c.View().Queries != 0 {
		t.Fatalf("aparelho do DHCP = %+v", c)
	}
	if len(newIDs) != 1 {
		t.Errorf("deveria avisar dispositivo novo: %v", newIDs)
	}
	// Mesmo MAC com IP novo: o mesmo aparelho, sem aviso.
	r.LearnLease(ipB, macX, "tv-sala")
	if r.lookupIP(ipB) != c || len(newIDs) != 1 {
		t.Errorf("troca de IP: %v %v", r.lookupIP(ipB), newIDs)
	}
	// Aparelho que já consultava pelo IP ganha MAC e nome.
	ipC := netip.MustParseAddr("192.168.1.30")
	d := r.Observe(ipC, time.Now())
	r.LearnLease(ipC, macY, "notebook")
	if v := d.View(); v.MAC != macY || v.Hostname != "notebook" {
		t.Errorf("aprendeu pelo DHCP: %+v", v)
	}
}

func TestApplyRemote(t *testing.T) {
	st := &memStore{recs: map[string]Record{}}
	n := &fakeNet{table: map[netip.Addr]string{ipA: macX}}
	r := newReg(t, st, n)
	local := r.Observe(ipA, time.Now()) // o mesmo aparelho, visto pela réplica com outro id
	enrich(r, ipA)
	oldID := local.ID()

	err := r.ApplyRemote([]State{
		{ID: "principal1", MAC: macX, Hostname: "tv", Settings: Settings{Name: "TV da sala", Isolated: true, IsolateMode: ModeNXDomain, AccessToken: "abcd1234abcd1234"}},
		{ID: "principal2", MAC: macY, IPs: []netip.Addr{ipB}, Settings: Settings{Deny: []string{"service:tiktok"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := r.Find("principal1")
	if c != local || c.ID() != "principal1" {
		t.Fatalf("a réplica deveria adotar o id do principal: %v", c)
	}
	if !c.Policy().IsolatedFor("x.com") || c.Policy().IsolateMode != ModeNXDomain || c.View().Display != "TV da sala" {
		t.Errorf("configurações do principal: %+v", c.View())
	}
	if r.ByToken("abcd1234abcd1234") != c {
		t.Error("token de fora da rede deveria valer na réplica")
	}
	if _, ok := st.recs[oldID]; ok {
		t.Error("o id antigo deveria sair do banco")
	}
	d, _ := r.Find(ipB.String())
	if d == nil || d.ID() != "principal2" || d.Policy().Match("www.tiktok.com").Verdict == 0 {
		t.Errorf("aparelho só do principal: %+v", d)
	}
	// Liberado no principal: libera na réplica.
	r.ApplyRemote([]State{{ID: "principal1", MAC: macX, Settings: Settings{Name: "TV da sala"}}})
	if c.Policy().Isolated || r.ByToken("abcd1234abcd1234") != nil {
		t.Error("liberação e revogação do token deveriam valer")
	}
}
