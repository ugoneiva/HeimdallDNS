package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/clients"
	"github.com/ugoneiva/HeimdallDNS/internal/querylog"
	"github.com/ugoneiva/HeimdallDNS/internal/server"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
)

const heartbeat = 15 * time.Second

// Atalhos aceitos no filtro de status, além dos nomes exatos.
var statusAliases = map[string][]string{
	"blocked": {server.StatusBlocked, server.StatusIsolated},
	"allowed": {server.StatusForwarded, server.StatusCached, server.StatusStale, server.StatusLocal},
	"cached":  {server.StatusCached, server.StatusStale},
}

// period lê range (1h, 24h, 7d…) ou from/to (RFC 3339).
func period(r *http.Request, def time.Duration) (time.Time, time.Time, error) {
	q := r.URL.Query()
	to := time.Now()
	if v := q.Get("to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("to: %w", err)
		}
		to = t
	}
	if v := q.Get("from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("from: %w", err)
		}
		return t, to, nil
	}
	d := def
	if v := q.Get("range"); v != "" {
		var err error
		if d, err = parseDuration(v); err != nil {
			return time.Time{}, time.Time{}, err
		}
	}
	return to.Add(-d), to, nil
}

// parseDuration aceita também dias ("7d").
func parseDuration(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("range %q inválido", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("range %q inválido", s)
	}
	return d, nil
}

// filter monta o filtro a partir de client, status, type e q.
func (a *api) filter(r *http.Request) (querylog.Filter, error) {
	q := r.URL.Query()
	var f querylog.Filter
	if ref := q.Get("client"); ref != "" {
		c, err := a.Clients.Find(ref)
		switch {
		case err == nil:
			f.ClientIDs = []string{c.ID()}
		case errors.Is(err, clients.ErrNotFound):
			ip, perr := netip.ParseAddr(ref)
			if perr != nil {
				return f, err
			}
			f.ClientIP = ip.Unmap().String()
		default:
			return f, err
		}
	}
	for _, s := range splitParam(q.Get("status")) {
		if alias, ok := statusAliases[s]; ok {
			f.Statuses = append(f.Statuses, alias...)
		} else {
			f.Statuses = append(f.Statuses, s)
		}
	}
	for _, t := range splitParam(q.Get("type")) {
		f.Types = append(f.Types, strings.ToUpper(t))
	}
	f.Search = strings.ToLower(strings.TrimSpace(q.Get("q")))
	return f, nil
}

func splitParam(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func intParam(r *http.Request, name string, def int) int {
	if n, err := strconv.Atoi(r.URL.Query().Get(name)); err == nil {
		return n
	}
	return def
}

func (a *api) clientName(id string) string {
	if id == "" {
		return ""
	}
	if c, err := a.Clients.Find(id); err == nil {
		return c.Policy().Display
	}
	return ""
}

// queries devolve o histórico paginado: GET /api/queries?range=1h&client=…&status=blocked&before=<id>
func (a *api) queries(w http.ResponseWriter, r *http.Request) {
	from, to, err := period(r, 24*time.Hour)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	f, err := a.filter(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	limit := intParam(r, "limit", 100)
	es, err := a.Store.History(store.HistoryQuery{
		Filter: f, From: from, To: to, Limit: limit, BeforeID: int64(intParam(r, "before", 0)),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	names := map[string]string{}
	for i := range es {
		id := es[i].ClientID
		if _, ok := names[id]; !ok {
			names[id] = a.clientName(id)
		}
		es[i].ClientName = names[id]
	}
	next := int64(0)
	if len(es) == min(max(limit, 1), 1000) {
		next = es[len(es)-1].ID
	}
	writeJSON(w, http.StatusOK, map[string]any{"queries": es, "next_before": next})
}

// sse prepara a resposta de Server-Sent Events.
func sse(w http.ResponseWriter) (http.Flusher, bool) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, errors.New("streaming não suportado"))
		return nil, false
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no") // nginx não segura os eventos
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "retry: 3000\n\n")
	fl.Flush()
	return fl, true
}

func sendEvent(w http.ResponseWriter, event string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
	return err
}

// liveQueries transmite as consultas em tempo real (SSE, evento "query").
func (a *api) liveQueries(w http.ResponseWriter, r *http.Request) {
	f, err := a.filter(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	fl, ok := sse(w)
	if !ok {
		return
	}
	sub := a.Log.Subscribe(f)
	defer sub.Close()
	hb := time.NewTicker(heartbeat)
	defer hb.Stop()
	drops := time.NewTicker(time.Second)
	defer drops.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-a.Context.Done():
			return
		case e := <-sub.C:
			if err := sendEvent(w, "query", e); err != nil {
				return
			}
			// Junta o que já estiver na fila antes de enviar (menos flushes).
			for n := 0; n < 100; n++ {
				select {
				case e := <-sub.C:
					if err := sendEvent(w, "query", e); err != nil {
						return
					}
					continue
				default:
				}
				break
			}
			fl.Flush()
		case <-drops.C:
			if n := sub.Dropped(); n > 0 {
				if sendEvent(w, "dropped", map[string]uint64{"count": n}) != nil {
					return
				}
				fl.Flush()
			}
		case <-hb.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			fl.Flush()
		}
	}
}

// liveStats transmite o tráfego de cada segundo (SSE, evento "tick").
func (a *api) liveStats(w http.ResponseWriter, r *http.Request) {
	fl, ok := sse(w)
	if !ok {
		return
	}
	// Começa com o último minuto, para o gráfico já nascer preenchido.
	if sendEvent(w, "history", a.Log.Realtime(60)) != nil {
		return
	}
	fl.Flush()
	// Alinha no início de cada segundo, um pouco depois para o segundo fechar.
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second + 50*time.Millisecond)))
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		if err := sendEvent(w, "tick", a.Log.Realtime(1)[0]); err != nil {
			return
		}
		fl.Flush()
		select {
		case <-r.Context().Done():
			return
		case <-a.Context.Done():
			return
		case <-t.C:
		}
	}
}

func (a *api) realtime(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.Log.Realtime(intParam(r, "seconds", 60)))
}

func (a *api) summary(w http.ResponseWriter, r *http.Request) {
	from, to, err := period(r, 24*time.Hour)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	f, err := a.filter(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	b, active, err := a.Store.Summary(from, to, f.ClientIDs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	pct := func(n int64) float64 {
		if b.Total == 0 {
			return 0
		}
		return float64(n) * 100 / float64(b.Total)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"from": from, "to": to, "counts": b.Counts,
		"blocked_pct":    pct(b.Blocked + b.Isolated),
		"cached_pct":     pct(b.Cached),
		"avg_forward_ms": b.AvgForwardMS,
		"active_clients": active,
	})
}

// autoStep escolhe o intervalo para dar 60–300 pontos no gráfico.
func autoStep(d time.Duration) time.Duration {
	switch {
	case d <= 2*time.Hour:
		return time.Minute
	case d <= 6*time.Hour:
		return 5 * time.Minute
	case d <= 24*time.Hour:
		return 10 * time.Minute
	case d <= 7*24*time.Hour:
		return time.Hour
	}
	return 24 * time.Hour
}

func (a *api) timeseries(w http.ResponseWriter, r *http.Request) {
	from, to, err := period(r, 24*time.Hour)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	f, err := a.filter(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	step := autoStep(to.Sub(from))
	if v := r.URL.Query().Get("step"); v != "" {
		if step, err = parseDuration(v); err != nil || step < time.Minute {
			writeErr(w, http.StatusBadRequest, errors.New("step mínimo é 1m"))
			return
		}
	}
	if to.Sub(from)/step > 2000 {
		writeErr(w, http.StatusBadRequest, errors.New("pontos demais; aumente o step"))
		return
	}
	bs, err := a.Store.Timeseries(from, to, step, f.ClientIDs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"step_s": int(step.Seconds()), "points": bs})
}

// top: kind=domains (permitidos), blocked (bloqueados) ou clients.
func (a *api) top(w http.ResponseWriter, r *http.Request) {
	from, to, err := period(r, 24*time.Hour)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	limit := intParam(r, "limit", 10)
	type item struct {
		Key     string `json:"key"`
		Name    string `json:"name,omitempty"`
		Count   int64  `json:"count"`
		Blocked int64  `json:"blocked,omitempty"`
	}
	var rs []store.Ranked
	kind := r.URL.Query().Get("kind")
	switch kind {
	case "", "domains", "blocked":
		f, ferr := a.filter(r)
		if ferr != nil {
			writeErr(w, http.StatusBadRequest, ferr)
			return
		}
		client := ""
		if len(f.ClientIDs) > 0 {
			client = f.ClientIDs[0]
		}
		rs, err = a.Store.TopDomains(from, to, kind == "blocked", client, limit)
	case "clients":
		rs, err = a.Store.TopClients(from, to, limit)
	default:
		writeErr(w, http.StatusBadRequest, fmt.Errorf("kind %q: use domains, blocked ou clients", kind))
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]item, len(rs))
	for i, x := range rs {
		out[i] = item{Key: x.Key, Count: x.Count, Blocked: x.Blocked}
		if kind == "clients" {
			out[i].Name = a.clientName(x.Key)
		}
	}
	writeJSON(w, http.StatusOK, out)
}
