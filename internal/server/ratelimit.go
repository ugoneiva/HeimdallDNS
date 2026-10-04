package server

import (
	"hash/maphash"
	"net/netip"
	"sync"
	"time"
)

// RateLimit limita as consultas por IP (balde de fichas). QPS 0 desliga.
type RateLimit struct {
	QPS    float64
	Burst  int
	Exempt []netip.Prefix // além do loopback, que nunca é limitado
}

const (
	limiterShards = 64
	alertEvery    = time.Minute // no máximo um aviso por IP por minuto
	idleAfter     = 5 * time.Minute
)

type bucket struct {
	tokens    float64
	last      time.Time
	lastAlert time.Time
	dropped   uint64 // recusadas desde o último aviso
}

type limiterShard struct {
	mu        sync.Mutex
	m         map[netip.Addr]*bucket
	lastSweep time.Time
}

type rateLimiter struct {
	cfg    RateLimit
	seed   maphash.Seed
	shards [limiterShards]limiterShard
}

func newRateLimiter(cfg RateLimit) *rateLimiter {
	if cfg.QPS <= 0 {
		return nil
	}
	if cfg.Burst < 1 {
		cfg.Burst = int(cfg.QPS * 5)
	}
	l := &rateLimiter{cfg: cfg, seed: maphash.MakeSeed()}
	for i := range l.shards {
		l.shards[i].m = map[netip.Addr]*bucket{}
	}
	return l
}

func (l *rateLimiter) exempt(ip netip.Addr) bool {
	if ip.IsLoopback() {
		return true
	}
	for _, p := range l.cfg.Exempt {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// allow gasta uma ficha. Quando recusa, alert diz se é hora de avisar (com
// quantas foram recusadas desde o último aviso).
func (l *rateLimiter) allow(ip netip.Addr, now time.Time) (ok bool, alert bool, dropped uint64) {
	if l == nil || l.exempt(ip) {
		return true, false, 0
	}
	b16 := ip.As16()
	sh := &l.shards[maphash.Bytes(l.seed, b16[:])%limiterShards]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if now.Sub(sh.lastSweep) > time.Minute {
		// Esquece os IPs parados (o mapa não cresce sem fim).
		for k, b := range sh.m {
			if now.Sub(b.last) > idleAfter {
				delete(sh.m, k)
			}
		}
		sh.lastSweep = now
	}
	b := sh.m[ip]
	if b == nil {
		b = &bucket{tokens: float64(l.cfg.Burst), last: now}
		sh.m[ip] = b
	}
	b.tokens = min(float64(l.cfg.Burst), b.tokens+now.Sub(b.last).Seconds()*l.cfg.QPS)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, false, 0
	}
	b.dropped++
	if now.Sub(b.lastAlert) >= alertEvery {
		b.lastAlert = now
		d := b.dropped
		b.dropped = 0
		return false, true, d
	}
	return false, false, 0
}
