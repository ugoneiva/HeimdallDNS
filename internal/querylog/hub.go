// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package querylog

import (
	"sync"
	"sync/atomic"
)

const subBuffer = 1024

// Subscription é um assinante do log ao vivo. Se ele não der conta de ler,
// as consultas excedentes são descartadas (e contadas) em vez de atrasar o DNS.
type Subscription struct {
	C       chan Entry
	filter  Filter
	dropped atomic.Uint64
	hub     *hub
	once    sync.Once
}

// Dropped devolve e zera quantas consultas foram descartadas.
func (s *Subscription) Dropped() uint64 { return s.dropped.Swap(0) }

func (s *Subscription) Close() {
	s.once.Do(func() {
		s.hub.mu.Lock()
		delete(s.hub.subs, s)
		s.hub.mu.Unlock()
	})
}

type hub struct {
	mu   sync.RWMutex
	subs map[*Subscription]struct{}
}

func (h *hub) subscribe(f Filter) *Subscription {
	s := &Subscription{C: make(chan Entry, subBuffer), filter: f, hub: h}
	h.mu.Lock()
	h.subs[s] = struct{}{}
	h.mu.Unlock()
	return s
}

func (h *hub) publish(e *Entry) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for s := range h.subs {
		if !s.filter.Match(e) {
			continue
		}
		select {
		case s.C <- *e:
		default:
			s.dropped.Add(1)
		}
	}
}
