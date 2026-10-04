// Package clients é o radar de dispositivos: registra cada IP que consulta o
// DNS, descobre MAC, fabricante e nome, e guarda a política de cada cliente
// (isolamento e regras próprias).
package clients

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/filter"
)

// Modos de isolamento (os mesmos do bloqueio).
const (
	ModeNull     = "null"
	ModeNXDomain = "nxdomain"
	ModeRefused  = "refused"
	ModeDrop     = "drop"
)

const (
	maxIPs        = 8                // IPs guardados por dispositivo (IPv6 troca muito)
	ptrRefresh    = time.Hour        // de quanto em quanto tempo renova o nome reverso
	neighMinDelay = 2 * time.Second  // intervalo mínimo entre leituras da tabela de vizinhos
	flushEvery    = 15 * time.Second // gravação dos contadores
)

var ErrNotFound = errors.New("cliente não encontrado")

// Settings é o que o usuário controla em cada cliente.
type Settings struct {
	Name            string    `json:"name,omitempty"`
	Isolated        bool      `json:"isolated,omitempty"`
	IsolateMode     string    `json:"isolate_mode,omitempty"`
	IsolateReason   string    `json:"isolate_reason,omitempty"`
	IsolatedAt      time.Time `json:"isolated_at,omitzero"`
	Exceptions      []string  `json:"exceptions,omitempty"` // liberados mesmo isolado
	Allow           []string  `json:"allow,omitempty"`
	Deny            []string  `json:"deny,omitempty"`
	SkipGlobalLists bool      `json:"skip_global_lists,omitempty"`
	// AccessToken identifica o aparelho fora da rede (DoH /dns-query/<token>,
	// DoT <token>.<host público>), com a política dele em qualquer lugar.
	AccessToken string `json:"access_token,omitempty"`
}

// Policy é a versão compilada e imutável de Settings, lida a cada consulta.
type Policy struct {
	ClientID    string
	Display     string
	Isolated    bool
	IsolateMode string
	SkipGlobal  bool
	exceptions  *filter.Matcher
	rules       *filter.Matcher
}

// IsolatedFor diz se a consulta deve ser barrada pelo isolamento.
func (p *Policy) IsolatedFor(name string) bool {
	if p == nil || !p.Isolated {
		return false
	}
	return p.exceptions.Match(name).Verdict == filter.Pass
}

// Match aplica as regras próprias do cliente.
func (p *Policy) Match(name string) filter.Result {
	if p == nil {
		return filter.Result{}
	}
	return p.rules.Match(name)
}

// Record é o cliente como vai para o banco.
type Record struct {
	ID        string
	MAC       string
	Vendor    string
	Hostname  string
	IPs       []netip.Addr
	FirstSeen time.Time
	LastSeen  time.Time
	Queries   uint64
	Blocked   uint64
	Settings  Settings
}

// Persister guarda os clientes (implementado pelo store SQLite).
type Persister interface {
	LoadClients() ([]Record, error)
	SaveClients([]Record) error
	DeleteClient(id string) error
}

// View é o cliente como sai na API.
type View struct {
	ID        string       `json:"id"`
	Display   string       `json:"display"`
	MAC       string       `json:"mac,omitempty"`
	Vendor    string       `json:"vendor,omitempty"`
	Hostname  string       `json:"hostname,omitempty"`
	IPs       []netip.Addr `json:"ips"`
	FirstSeen time.Time    `json:"first_seen"`
	LastSeen  time.Time    `json:"last_seen"`
	Queries   uint64       `json:"queries"`
	Blocked   uint64       `json:"blocked"`
	Settings  Settings     `json:"settings"`
}

type Client struct {
	id string

	mu        sync.Mutex // protege os campos abaixo
	mac       string
	vendor    string
	hostname  string
	ips       []netip.Addr
	firstSeen time.Time
	settings  Settings
	ptrAt     time.Time

	lastSeen atomic.Int64 // UnixNano
	queries  atomic.Uint64
	blocked  atomic.Uint64
	dirty    atomic.Bool
	policy   atomic.Pointer[Policy]
}

func (c *Client) ID() string { return c.id }

// Policy e CountBlocked aceitam cliente nil (servidor sem radar).
func (c *Client) Policy() *Policy {
	if c == nil {
		return nil
	}
	return c.policy.Load()
}

func (c *Client) CountBlocked() {
	if c != nil {
		c.blocked.Add(1)
	}
}

func (c *Client) markDirty() { c.dirty.Store(true) }
func (c *Client) touch(t time.Time) {
	c.lastSeen.Store(t.UnixNano())
	c.queries.Add(1)
	c.dirty.Store(true)
}

// displayLocked escolhe o nome mostrado: o dado pelo usuário, o reverso ou o IP.
func (c *Client) displayLocked() string {
	switch {
	case c.settings.Name != "":
		return c.settings.Name
	case c.hostname != "":
		return c.hostname
	case len(c.ips) > 0:
		return c.ips[0].String()
	}
	return c.id
}

// rebuildLocked recompila a política a partir de settings.
func (c *Client) rebuildLocked(defaultMode string) []string {
	s := c.settings
	p := &Policy{
		ClientID:    c.id,
		Display:     c.displayLocked(),
		Isolated:    s.Isolated,
		IsolateMode: s.IsolateMode,
		SkipGlobal:  s.SkipGlobalLists,
	}
	if p.IsolateMode == "" {
		p.IsolateMode = defaultMode
	}
	var invalid []string
	var bad []string
	p.exceptions, bad = filter.CompileUserRules(s.Exceptions, nil)
	invalid = append(invalid, bad...)
	p.rules, bad = filter.CompileUserRules(s.Allow, s.Deny)
	invalid = append(invalid, bad...)
	c.policy.Store(p)
	return invalid
}

func (c *Client) recordLocked() Record {
	return Record{
		ID: c.id, MAC: c.mac, Vendor: c.vendor, Hostname: c.hostname,
		IPs:       slices.Clone(c.ips),
		FirstSeen: c.firstSeen,
		LastSeen:  time.Unix(0, c.lastSeen.Load()),
		Queries:   c.queries.Load(),
		Blocked:   c.blocked.Load(),
		Settings:  c.settings,
	}
}

func (c *Client) View() View {
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.recordLocked()
	return View{
		ID: r.ID, Display: c.displayLocked(), MAC: r.MAC, Vendor: r.Vendor, Hostname: r.Hostname,
		IPs: r.IPs, FirstSeen: r.FirstSeen, LastSeen: r.LastSeen,
		Queries: r.Queries, Blocked: r.Blocked, Settings: r.Settings,
	}
}

func (c *Client) addIPLocked(ip netip.Addr) {
	if i := slices.Index(c.ips, ip); i >= 0 {
		c.ips = slices.Delete(c.ips, i, i+1)
	}
	c.ips = slices.Insert(c.ips, 0, ip) // o mais recente primeiro
	if len(c.ips) > maxIPs {
		c.ips = c.ips[:maxIPs]
	}
}

func (c *Client) removeIPLocked(ip netip.Addr) {
	if i := slices.Index(c.ips, ip); i >= 0 {
		c.ips = slices.Delete(c.ips, i, i+1)
	}
}

type Options struct {
	Store       Persister                                         // nil = só memória
	Neighbors   func() (map[netip.Addr]string, error)             // nil = sem MAC
	PTR         func(context.Context, netip.Addr) (string, error) // nil = sem nome reverso
	IsolateMode string
	// OnNew avisa de um dispositivo novo de verdade: só depois de procurar o MAC,
	// para um aparelho conhecido que trocou de IP não parecer novo.
	OnNew  func(id string, ip netip.Addr)
	Logger *slog.Logger
}

type Registry struct {
	opts Options
	log  *slog.Logger

	mu    sync.RWMutex
	byID  map[string]*Client
	byIP  map[netip.Addr]*Client
	byMAC map[string]*Client
	byTok map[string]*Client

	fresh     map[string]bool // criados e ainda não confirmados como novos (ver OnNew)
	vendors   atomic.Pointer[OUI]
	enrich    chan netip.Addr
	neighMu   sync.Mutex
	neighAt   time.Time
	neighbors map[netip.Addr]string
}

func NewRegistry(opts Options) (*Registry, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.IsolateMode == "" {
		opts.IsolateMode = ModeRefused
	}
	r := &Registry{
		opts:   opts,
		log:    opts.Logger,
		byID:   map[string]*Client{},
		byIP:   map[netip.Addr]*Client{},
		byMAC:  map[string]*Client{},
		byTok:  map[string]*Client{},
		fresh:  map[string]bool{},
		enrich: make(chan netip.Addr, 1024),
	}
	if opts.Store == nil {
		return r, nil
	}
	recs, err := opts.Store.LoadClients()
	if err != nil {
		return nil, fmt.Errorf("carregando clientes: %w", err)
	}
	for _, rec := range recs {
		c := &Client{
			id: rec.ID, mac: rec.MAC, vendor: rec.Vendor, hostname: rec.Hostname,
			ips: rec.IPs, firstSeen: rec.FirstSeen, settings: rec.Settings,
		}
		c.lastSeen.Store(rec.LastSeen.UnixNano())
		c.queries.Store(rec.Queries)
		c.blocked.Store(rec.Blocked)
		if bad := c.rebuildLocked(opts.IsolateMode); len(bad) > 0 {
			r.log.Warn("regras inválidas no cliente", "cliente", rec.ID, "regras", bad)
		}
		r.byID[c.id] = c
		for _, ip := range c.ips {
			r.byIP[ip] = c
		}
		if c.mac != "" {
			r.byMAC[c.mac] = c
		}
		if t := c.settings.AccessToken; t != "" {
			r.byTok[t] = c
		}
	}
	r.log.Info("clientes carregados", "total", len(recs))
	return r, nil
}

// Observe registra uma consulta do IP e devolve o cliente. É chamado em toda
// consulta, então o caminho comum é só uma leitura de mapa e contadores atômicos.
func (r *Registry) Observe(ip netip.Addr, t time.Time) *Client {
	ip = ip.Unmap()
	r.mu.RLock()
	c := r.byIP[ip]
	r.mu.RUnlock()
	if c == nil {
		c = r.newClient(ip, t)
	}
	c.touch(t)
	return c
}

func (r *Registry) newClient(ip netip.Addr, t time.Time) *Client {
	r.mu.Lock()
	if c := r.byIP[ip]; c != nil { // outra consulta criou antes
		r.mu.Unlock()
		return c
	}
	c := &Client{id: r.newIDLocked(), ips: []netip.Addr{ip}, firstSeen: t}
	if ip.IsLoopback() {
		c.hostname = "localhost"
	}
	c.rebuildLocked(r.opts.IsolateMode)
	r.byID[c.id] = c
	r.byIP[ip] = c
	r.mu.Unlock()

	r.log.Info("novo dispositivo", "id", c.id, "ip", ip)
	if !ip.IsLoopback() {
		r.mu.Lock()
		r.fresh[c.id] = true
		r.mu.Unlock()
	}
	select {
	case r.enrich <- ip:
	default: // fila cheia: o ciclo periódico pega depois
	}
	return c
}

func (r *Registry) newIDLocked() string {
	for {
		b := make([]byte, 4)
		_, _ = rand.Read(b)
		id := hex.EncodeToString(b)
		if r.byID[id] == nil {
			return id
		}
	}
}

// SetVendors troca a base de fabricantes e preenche quem ainda não tem.
func (r *Registry) SetVendors(db *OUI) {
	r.vendors.Store(db)
	for _, c := range r.all() {
		c.mu.Lock()
		if c.mac != "" {
			if v := db.Lookup(c.mac); v != "" && v != c.vendor {
				c.vendor = v
				c.markDirty()
			}
		}
		c.mu.Unlock()
	}
}

func (r *Registry) all() []*Client {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Client, 0, len(r.byID))
	for _, c := range r.byID {
		out = append(out, c)
	}
	return out
}

// List devolve todos os clientes, os vistos mais recentemente primeiro.
func (r *Registry) List() []View {
	cs := r.all()
	out := make([]View, len(cs))
	for i, c := range cs {
		out[i] = c.View()
	}
	slices.SortFunc(out, func(a, b View) int { return b.LastSeen.Compare(a.LastSeen) })
	return out
}

// Find acha o cliente pelo id, IP, MAC ou nome (exato, sem diferenciar caixa).
func (r *Registry) Find(ref string) (*Client, error) {
	ref = strings.TrimSpace(ref)
	r.mu.RLock()
	if c := r.byID[ref]; c != nil {
		r.mu.RUnlock()
		return c, nil
	}
	if ip, err := netip.ParseAddr(ref); err == nil {
		if c := r.byIP[ip.Unmap()]; c != nil {
			r.mu.RUnlock()
			return c, nil
		}
	}
	if mac := normMAC(ref); mac != "" {
		if c := r.byMAC[mac]; c != nil {
			r.mu.RUnlock()
			return c, nil
		}
	}
	r.mu.RUnlock()
	var found []*Client
	for _, c := range r.all() {
		c.mu.Lock()
		if strings.EqualFold(c.settings.Name, ref) || strings.EqualFold(c.hostname, ref) {
			found = append(found, c)
		}
		c.mu.Unlock()
	}
	switch len(found) {
	case 0:
		return nil, ErrNotFound
	case 1:
		return found[0], nil
	}
	return nil, fmt.Errorf("%q corresponde a %d clientes; use o id", ref, len(found))
}

// Update altera as configurações do cliente e grava na hora.
func (r *Registry) Update(c *Client, f func(*Settings) error) error {
	c.mu.Lock()
	s := c.settings
	s.Exceptions = slices.Clone(s.Exceptions)
	s.Allow, s.Deny = slices.Clone(s.Allow), slices.Clone(s.Deny)
	if err := f(&s); err != nil {
		c.mu.Unlock()
		return err
	}
	if s.IsolateMode != "" && !validMode(s.IsolateMode) {
		c.mu.Unlock()
		return fmt.Errorf("modo %q: use null, nxdomain, refused ou drop", s.IsolateMode)
	}
	for _, list := range [][]string{s.Exceptions, s.Allow, s.Deny} {
		if _, bad := filter.CompileUserRules(list, nil); len(bad) > 0 {
			c.mu.Unlock()
			return fmt.Errorf("regras inválidas: %s", strings.Join(bad, ", "))
		}
	}
	c.settings = s
	c.rebuildLocked(r.opts.IsolateMode)
	rec := c.recordLocked()
	c.mu.Unlock()
	if r.opts.Store != nil {
		return r.opts.Store.SaveClients([]Record{rec})
	}
	return nil
}

// Isolate corta o DNS do cliente, exceto os domínios em exceptions.
func (r *Registry) Isolate(c *Client, mode, reason string, exceptions []string) error {
	err := r.Update(c, func(s *Settings) error {
		s.Isolated, s.IsolateMode, s.IsolateReason, s.Exceptions = true, mode, reason, exceptions
		s.IsolatedAt = time.Now()
		return nil
	})
	if err == nil {
		r.log.Warn("cliente isolado", "id", c.id, "cliente", c.Policy().Display, "modo", c.Policy().IsolateMode, "motivo", reason)
	}
	return err
}

func (r *Registry) Release(c *Client) error {
	err := r.Update(c, func(s *Settings) error {
		s.Isolated, s.IsolateReason, s.IsolatedAt, s.Exceptions = false, "", time.Time{}, nil
		return nil
	})
	if err == nil {
		r.log.Info("cliente liberado", "id", c.id, "cliente", c.Policy().Display)
	}
	return err
}

// ByToken acha o aparelho pelo token de acesso de fora da rede.
func (r *Registry) ByToken(tok string) *Client {
	if tok == "" {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byTok[strings.ToLower(tok)]
}

// ObserveToken registra uma consulta de um aparelho identificado pelo token
// (fora da rede). O IP público não entra na lista de IPs do aparelho: atrás
// de um NAT ele é de muita gente.
func (r *Registry) ObserveToken(tok string, t time.Time) *Client {
	c := r.ByToken(tok)
	if c != nil {
		c.touch(t)
	}
	return c
}

// SetToken cria (ou troca) o token de acesso do aparelho. Vazio = revoga.
func (r *Registry) SetToken(c *Client, revoke bool) (string, error) {
	tok := ""
	if !revoke {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		tok = hex.EncodeToString(b) // 16 caracteres, válido como rótulo DNS (DoT por SNI)
	}
	var old string
	err := r.Update(c, func(s *Settings) error {
		old, s.AccessToken = s.AccessToken, tok
		return nil
	})
	if err != nil {
		return "", err
	}
	r.mu.Lock()
	delete(r.byTok, old)
	if tok != "" {
		r.byTok[tok] = c
	}
	r.mu.Unlock()
	return tok, nil
}

// ValidToken diz se o token pertence a algum aparelho (para o certificado ACME por nome).
func (r *Registry) ValidToken(tok string) bool { return r.ByToken(tok) != nil }

// Forget apaga o cliente. Se ele consultar de novo, volta como novo.
func (r *Registry) Forget(c *Client) error {
	r.mu.Lock()
	c.mu.Lock()
	delete(r.byID, c.id)
	if t := c.settings.AccessToken; t != "" {
		delete(r.byTok, t)
	}
	for _, ip := range c.ips {
		if r.byIP[ip] == c {
			delete(r.byIP, ip)
		}
	}
	if c.mac != "" && r.byMAC[c.mac] == c {
		delete(r.byMAC, c.mac)
	}
	c.mu.Unlock()
	r.mu.Unlock()
	if r.opts.Store != nil {
		return r.opts.Store.DeleteClient(c.id)
	}
	return nil
}

func validMode(m string) bool {
	switch m {
	case ModeNull, ModeNXDomain, ModeRefused, ModeDrop:
		return true
	}
	return false
}

// Run descobre MAC e nome dos clientes novos, atualiza todos periodicamente e
// grava os contadores. Retorna quando ctx termina, depois de gravar tudo.
func (r *Registry) Run(ctx context.Context, neighEvery time.Duration) {
	if neighEvery <= 0 {
		neighEvery = time.Minute
	}
	neigh := time.NewTicker(neighEvery)
	flush := time.NewTicker(flushEvery)
	defer neigh.Stop()
	defer flush.Stop()
	for {
		select {
		case <-ctx.Done():
			r.Flush()
			return
		case ip := <-r.enrich:
			r.refreshNeighbors(false)
			r.applyNeighbor(ip)
			if c := r.lookupIP(ip); c != nil {
				r.resolvePTR(ctx, c, ip)
				r.confirmNew(c, ip)
			}
		case <-neigh.C:
			r.refreshNeighbors(true)
			r.neighMu.Lock()
			ips := make([]netip.Addr, 0, len(r.neighbors))
			for ip := range r.neighbors {
				ips = append(ips, ip)
			}
			r.neighMu.Unlock()
			for _, ip := range ips {
				r.applyNeighbor(ip)
			}
			for _, c := range r.all() {
				c.mu.Lock()
				stale := time.Since(c.ptrAt) > ptrRefresh && len(c.ips) > 0
				var ip netip.Addr
				if stale {
					ip = c.ips[0]
				}
				c.mu.Unlock()
				if stale {
					r.resolvePTR(ctx, c, ip)
				}
			}
		case <-flush.C:
			r.Flush()
		}
	}
}

func (r *Registry) lookupIP(ip netip.Addr) *Client {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byIP[ip]
}

func (r *Registry) refreshNeighbors(force bool) {
	if r.opts.Neighbors == nil {
		return
	}
	r.neighMu.Lock()
	defer r.neighMu.Unlock()
	if !force && time.Since(r.neighAt) < neighMinDelay {
		return
	}
	m, err := r.opts.Neighbors()
	if err != nil {
		r.log.Debug("tabela de vizinhos indisponível", "erro", err)
		return
	}
	r.neighbors, r.neighAt = m, time.Now()
}

// applyNeighbor associa o IP ao MAC visto na rede. Se o MAC já pertence a outro
// cliente (o IP mudou pelo DHCP, ou é outro endereço IPv6 do mesmo aparelho),
// o IP passa para ele, e um cliente que só existia por esse IP é absorvido.
func (r *Registry) applyNeighbor(ip netip.Addr) {
	r.neighMu.Lock()
	mac := r.neighbors[ip]
	r.neighMu.Unlock()
	if mac == "" {
		return
	}
	vendor := r.vendors.Load().Lookup(mac)

	r.mu.Lock()
	defer r.mu.Unlock()
	cur := r.byIP[ip]
	if cur == nil {
		return // IP visto na rede mas que nunca consultou
	}
	cur.mu.Lock()
	curMAC := cur.mac
	cur.mu.Unlock()
	if curMAC == mac {
		return
	}
	owner := r.byMAC[mac]
	switch {
	case owner == nil && curMAC == "":
		// Primeira vez que descobrimos o MAC deste cliente.
		cur.mu.Lock()
		cur.mac, cur.vendor = mac, vendor
		cur.markDirty()
		cur.mu.Unlock()
		r.byMAC[mac] = cur
	case owner == nil:
		// O IP agora é de outro aparelho, ainda desconhecido.
		cur.mu.Lock()
		cur.removeIPLocked(ip)
		cur.markDirty()
		cur.mu.Unlock()
		n := &Client{id: r.newIDLocked(), mac: mac, vendor: vendor, ips: []netip.Addr{ip}, firstSeen: time.Now()}
		n.lastSeen.Store(time.Now().UnixNano())
		n.rebuildLocked(r.opts.IsolateMode)
		n.markDirty()
		r.byID[n.id], r.byIP[ip], r.byMAC[mac] = n, n, n
		r.fresh[n.id] = true // aparelho desconhecido: confirmNew avisa
		r.log.Info("IP passou para outro dispositivo", "ip", ip, "mac", mac, "id", n.id)
	default:
		// O IP pertence a um aparelho que já conhecemos pelo MAC.
		owner.mu.Lock()
		owner.addIPLocked(ip)
		owner.markDirty()
		owner.mu.Unlock()
		r.byIP[ip] = owner
		cur.mu.Lock()
		cur.removeIPLocked(ip)
		absorb := curMAC == "" && len(cur.ips) == 0 && cur.settings.Name == "" && !cur.settings.Isolated &&
			len(cur.settings.Allow) == 0 && len(cur.settings.Deny) == 0
		cur.markDirty()
		cur.mu.Unlock()
		if absorb {
			owner.queries.Add(cur.queries.Load())
			owner.blocked.Add(cur.blocked.Load())
			if last := cur.lastSeen.Load(); last > owner.lastSeen.Load() {
				owner.lastSeen.Store(last)
			}
			delete(r.byID, cur.id)
			delete(r.fresh, cur.id)
			if r.opts.Store != nil {
				go func() { _ = r.opts.Store.DeleteClient(cur.id) }()
			}
		}
		r.log.Debug("IP associado a dispositivo conhecido", "ip", ip, "id", owner.id)
	}
}

func (r *Registry) resolvePTR(ctx context.Context, c *Client, ip netip.Addr) {
	c.mu.Lock()
	c.ptrAt = time.Now()
	c.mu.Unlock()
	if r.opts.PTR == nil || ip.IsLoopback() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	name, err := r.opts.PTR(ctx, ip)
	if err != nil || name == "" {
		return
	}
	c.mu.Lock()
	if c.hostname != name {
		c.hostname = name
		c.markDirty()
		c.rebuildLocked(r.opts.IsolateMode) // o nome mostrado pode ter mudado
	}
	c.mu.Unlock()
}

// confirmNew dispara OnNew se o cliente que ficou com o IP é um dos recém-criados.
// Se ele foi absorvido por um aparelho conhecido (mesmo MAC), não é novo.
func (r *Registry) confirmNew(c *Client, ip netip.Addr) {
	r.mu.Lock()
	isNew := r.fresh[c.id]
	delete(r.fresh, c.id)
	if len(r.fresh) > 1000 { // sobras de absorvidos: não cresce sem limite
		clear(r.fresh)
	}
	r.mu.Unlock()
	if isNew && r.opts.OnNew != nil {
		r.opts.OnNew(c.id, ip)
	}
}

// Flush grava os clientes alterados desde a última gravação.
func (r *Registry) Flush() {
	if r.opts.Store == nil {
		return
	}
	var recs []Record
	for _, c := range r.all() {
		if !c.dirty.Swap(false) {
			continue
		}
		c.mu.Lock()
		recs = append(recs, c.recordLocked())
		c.mu.Unlock()
	}
	if len(recs) == 0 {
		return
	}
	if err := r.opts.Store.SaveClients(recs); err != nil {
		r.log.Error("falha ao gravar clientes", "erro", err)
		for _, rec := range recs { // tenta de novo no próximo ciclo
			if c := r.byIDSafe(rec.ID); c != nil {
				c.markDirty()
			}
		}
	}
}

func (r *Registry) byIDSafe(id string) *Client {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byID[id]
}
