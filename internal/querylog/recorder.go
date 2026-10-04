package querylog

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/server"
)

const (
	inBuffer      = 100_000 // eventos esperando o agregador
	maxBatch      = 5_000   // linhas por lote
	jobQueue      = 4       // lotes esperando o banco
	flushEvery    = time.Second
	purgeEvery    = time.Hour
	maxTopPerHour = 50_000 // domínios distintos por hora; o resto vira "(outros)"
	otherDomains  = "(outros)"
	realtimeSecs  = 120
)

type Options struct {
	Sink           Sink
	StoreQueries   bool          // grava as linhas detalhadas
	Retention      time.Duration // das linhas detalhadas
	StatsRetention time.Duration // dos resumos
	Logger         *slog.Logger
}

type minuteKey struct {
	minute int64
	client string
}

type topKey struct {
	hour    int64
	name    string
	blocked bool
}

type job struct {
	entries []Entry
	stats   []MinuteStat
	tops    []DomainCount
}

// Second é o tráfego de um segundo.
type Second struct {
	Time    int64 `json:"t"` // Unix
	Total   int64 `json:"total"`
	Blocked int64 `json:"blocked"` // inclui isolados
	Cached  int64 `json:"cached"`
}

// Recorder recebe os eventos do servidor sem bloquear, agrega e grava.
type Recorder struct {
	opts Options
	log  *slog.Logger
	in   chan server.Event
	jobs chan job
	hub  hub

	// estado do agregador (uma goroutine só)
	raw     []Entry
	minutes map[minuteKey]*Counts
	tops    map[topKey]int64
	topHour int64
	topSize int

	rtMu sync.Mutex
	rt   [realtimeSecs]Second

	dropped    atomic.Uint64 // eventos perdidos (agregador atrasado)
	droppedRaw atomic.Uint64 // linhas detalhadas perdidas (banco atrasado)
	done       chan struct{}
}

func New(opts Options) *Recorder {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Recorder{
		opts:    opts,
		log:     opts.Logger,
		in:      make(chan server.Event, inBuffer),
		jobs:    make(chan job, jobQueue),
		hub:     hub{subs: map[*Subscription]struct{}{}},
		minutes: map[minuteKey]*Counts{},
		tops:    map[topKey]int64{},
		done:    make(chan struct{}),
	}
}

// Record é o OnQuery do servidor: nunca bloqueia.
func (r *Recorder) Record(e server.Event) {
	select {
	case r.in <- e:
	default:
		r.dropped.Add(1)
	}
}

// Dropped devolve quantos eventos e quantas linhas detalhadas foram perdidos.
func (r *Recorder) Dropped() (events, rows uint64) {
	return r.dropped.Load(), r.droppedRaw.Load()
}

// Subscribe assina o log ao vivo. Chame Close ao terminar.
func (r *Recorder) Subscribe(f Filter) *Subscription { return r.hub.subscribe(f) }

// Realtime devolve os últimos n segundos completos, do mais antigo ao mais novo.
func (r *Recorder) Realtime(n int) []Second {
	n = min(max(n, 1), realtimeSecs-1)
	now := time.Now().Unix()
	out := make([]Second, n)
	r.rtMu.Lock()
	defer r.rtMu.Unlock()
	for i := range n {
		sec := now - int64(n-i) // termina no segundo anterior (o atual está incompleto)
		s := r.rt[sec%realtimeSecs]
		if s.Time != sec {
			s = Second{Time: sec}
		}
		out[i] = s
	}
	return out
}

// Run agrega até ctx terminar; grava o que faltar antes de voltar.
func (r *Recorder) Run(ctx context.Context) {
	writerDone := make(chan struct{})
	go r.writer(writerDone)
	t := time.NewTicker(flushEvery)
	defer t.Stop()
	for {
		select {
		case e := <-r.in:
			r.process(e)
			if len(r.raw) >= maxBatch {
				r.flush(false)
			}
		case <-t.C:
			r.flush(false)
		case <-ctx.Done():
			for { // esvazia o que já chegou
				select {
				case e := <-r.in:
					r.process(e)
					continue
				default:
				}
				break
			}
			r.flush(true)
			close(r.jobs)
			<-writerDone
			close(r.done)
			return
		}
	}
}

// Done fecha quando o Recorder terminou de gravar.
func (r *Recorder) Done() <-chan struct{} { return r.done }

func (r *Recorder) process(ev server.Event) {
	e := fromEvent(ev)
	r.hub.publish(&e)

	sec := ev.Time.Unix()
	r.rtMu.Lock()
	s := &r.rt[sec%realtimeSecs]
	if s.Time != sec {
		*s = Second{Time: sec}
	}
	s.Total++
	switch e.Status {
	case server.StatusBlocked, server.StatusIsolated:
		s.Blocked++
	case server.StatusCached, server.StatusStale:
		s.Cached++
	}
	r.rtMu.Unlock()

	mk := minuteKey{ev.Time.Unix() / 60, e.ClientID}
	c := r.minutes[mk]
	if c == nil {
		c = &Counts{}
		r.minutes[mk] = c
	}
	c.add(e.Status, ev.Duration)

	if e.Name != "" && e.Status != server.StatusRefused && e.Status != server.StatusInvalid {
		hour := ev.Time.Unix() / 3600
		if hour != r.topHour {
			r.topHour, r.topSize = hour, 0
		}
		blocked := e.Status == server.StatusBlocked || e.Status == server.StatusIsolated
		tk := topKey{hour, e.Name, blocked}
		if _, ok := r.tops[tk]; !ok {
			if r.topSize >= maxTopPerHour {
				tk.name = otherDomains
			} else {
				r.topSize++
			}
		}
		r.tops[tk]++
	}

	if r.opts.StoreQueries {
		r.raw = append(r.raw, e)
	}
}

// flush manda o que foi agregado para o banco. Se a fila estiver cheia, as
// linhas detalhadas são descartadas, mas os resumos ficam para a próxima vez.
func (r *Recorder) flush(wait bool) {
	if len(r.raw) == 0 && len(r.minutes) == 0 && len(r.tops) == 0 {
		return
	}
	j := job{entries: r.raw}
	for k, c := range r.minutes {
		j.stats = append(j.stats, MinuteStat{Minute: k.minute, ClientID: k.client, Counts: *c})
	}
	for k, n := range r.tops {
		j.tops = append(j.tops, DomainCount{Hour: k.hour, Name: k.name, Blocked: k.blocked, Count: n})
	}
	if wait {
		r.jobs <- j
	} else {
		select {
		case r.jobs <- j:
		default:
			r.droppedRaw.Add(uint64(len(r.raw)))
			r.raw = r.raw[:0]
			return // resumos seguem acumulando
		}
	}
	r.raw = make([]Entry, 0, len(r.raw))
	clear(r.minutes)
	clear(r.tops)
}

func (r *Recorder) writer(done chan struct{}) {
	defer close(done)
	purge := time.NewTicker(purgeEvery)
	defer purge.Stop()
	r.purge()
	for {
		select {
		case j, ok := <-r.jobs:
			if !ok {
				return
			}
			if len(j.entries) > 0 {
				if err := r.opts.Sink.InsertQueries(j.entries); err != nil {
					r.droppedRaw.Add(uint64(len(j.entries)))
					r.log.Error("falha ao gravar consultas", "erro", err)
				}
			}
			if err := r.opts.Sink.AddStats(j.stats, j.tops); err != nil {
				r.log.Error("falha ao gravar resumos", "erro", err)
			}
		case <-purge.C:
			r.purge()
		}
	}
}

func (r *Recorder) purge() {
	now := time.Now()
	n, err := r.opts.Sink.Purge(now.Add(-r.opts.Retention), now.Add(-r.opts.StatsRetention))
	if err != nil {
		r.log.Error("falha na limpeza do histórico", "erro", err)
		return
	}
	if n > 0 {
		r.log.Info("histórico antigo removido", "linhas", n)
	}
}
