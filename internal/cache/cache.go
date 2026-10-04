// Package cache guarda respostas DNS em memória (LRU), respeitando o TTL de
// cada registro, com cache negativo (RFC 2308) e resposta vencida enquanto
// renova (serve-stale, RFC 8767).
package cache

import (
	"container/list"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// staleTTL é o TTL entregue numa resposta vencida (valor sugerido pela RFC 8767).
const staleTTL = 30

// negativeTTL vale para respostas negativas sem SOA.
const negativeTTL = 60

type Key struct {
	Name   string // minúsculo, com ponto final
	Qtype  uint16
	Qclass uint16
	DO     bool // o cliente pediu registros DNSSEC
}

type Options struct {
	Size       int
	MinTTL     uint32
	MaxTTL     uint32        // 0 = sem teto
	ServeStale time.Duration // por quanto tempo uma resposta vencida ainda serve; 0 desliga
}

type entry struct {
	key     Key
	msg     *dns.Msg // sem o registro OPT
	stored  time.Time
	expires time.Time
}

type Cache struct {
	opts Options
	now  func() time.Time

	mu    sync.Mutex
	ll    *list.List // frente = usado mais recentemente
	items map[Key]*list.Element

	hits, misses atomic.Uint64
}

func New(opts Options) *Cache {
	if opts.Size <= 0 {
		opts.Size = 20000
	}
	return &Cache{opts: opts, now: time.Now, ll: list.New(), items: make(map[Key]*list.Element)}
}

// Get devolve uma cópia da resposta com os TTLs já descontados. stale indica
// que a resposta venceu mas ainda pode ser servida; quem chamou deve renovar.
func (c *Cache) Get(k Key) (msg *dns.Msg, stale bool, ok bool) {
	now := c.now()
	c.mu.Lock()
	el, found := c.items[k]
	if !found {
		c.mu.Unlock()
		c.misses.Add(1)
		return nil, false, false
	}
	e := el.Value.(*entry)
	if now.After(e.expires) {
		if c.opts.ServeStale <= 0 || now.Sub(e.expires) > c.opts.ServeStale {
			c.ll.Remove(el)
			delete(c.items, k)
			c.mu.Unlock()
			c.misses.Add(1)
			return nil, false, false
		}
		stale = true
	}
	c.ll.MoveToFront(el)
	c.mu.Unlock()
	c.hits.Add(1)

	msg = e.msg.Copy()
	if stale {
		setTTL(msg, func(uint32) uint32 { return staleTTL })
		return msg, true, true
	}
	elapsed := uint32(now.Sub(e.stored) / time.Second)
	remaining := uint32(e.expires.Sub(now)/time.Second) + 1
	setTTL(msg, func(orig uint32) uint32 {
		if orig <= elapsed { // min_ttl esticou a vida da entrada
			return remaining
		}
		return min(orig-elapsed, remaining)
	})
	return msg, false, true
}

// Set guarda a resposta se ela puder ir para o cache.
func (c *Cache) Set(k Key, msg *dns.Msg) {
	ttl, ok := c.ttlFor(msg)
	if !ok {
		return
	}
	m := msg.Copy()
	stripOPT(m)
	now := c.now()
	e := &entry{key: k, msg: m, stored: now, expires: now.Add(time.Duration(ttl) * time.Second)}

	c.mu.Lock()
	defer c.mu.Unlock()
	if el, found := c.items[k]; found {
		el.Value = e
		c.ll.MoveToFront(el)
		return
	}
	c.items[k] = c.ll.PushFront(e)
	for c.ll.Len() > c.opts.Size {
		old := c.ll.Back()
		c.ll.Remove(old)
		delete(c.items, old.Value.(*entry).key)
	}
}

func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

func (c *Cache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll.Init()
	clear(c.items)
}

type Stats struct {
	Entries int    `json:"entries"`
	Hits    uint64 `json:"hits"`
	Misses  uint64 `json:"misses"`
}

func (c *Cache) Stats() Stats {
	return Stats{Entries: c.Len(), Hits: c.hits.Load(), Misses: c.misses.Load()}
}

// ttlFor calcula por quanto tempo a resposta vale: o menor TTL entre os
// registros, ou o da SOA numa resposta negativa.
func (c *Cache) ttlFor(m *dns.Msg) (uint32, bool) {
	if m == nil || m.Truncated {
		return 0, false
	}
	var ttl uint32
	switch m.Rcode {
	case dns.RcodeSuccess:
		if len(m.Answer) == 0 {
			ttl = negTTL(m)
			break
		}
		ttl = minTTL(m)
	case dns.RcodeNameError:
		ttl = negTTL(m)
	default: // SERVFAIL, REFUSED etc. não vão para o cache
		return 0, false
	}
	ttl = max(ttl, c.opts.MinTTL)
	if c.opts.MaxTTL > 0 {
		ttl = min(ttl, c.opts.MaxTTL)
	}
	return ttl, ttl > 0
}

func minTTL(m *dns.Msg) uint32 {
	ttl := ^uint32(0)
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range sec {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			ttl = min(ttl, rr.Header().Ttl)
		}
	}
	return ttl
}

func negTTL(m *dns.Msg) uint32 {
	for _, rr := range m.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return min(soa.Hdr.Ttl, soa.Minttl)
		}
	}
	return negativeTTL
}

func setTTL(m *dns.Msg, f func(uint32) uint32) {
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range sec {
			h := rr.Header()
			if h.Rrtype != dns.TypeOPT {
				h.Ttl = f(h.Ttl)
			}
		}
	}
}

func stripOPT(m *dns.Msg) {
	extra := m.Extra[:0]
	for _, rr := range m.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			extra = append(extra, rr)
		}
	}
	m.Extra = extra
}
