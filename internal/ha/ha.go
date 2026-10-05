// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

// Package ha replica a configuração entre nós do HeimdallDNS: um principal e
// uma ou mais réplicas. A réplica faz long-poll no principal, então uma
// mudança (um isolamento, por exemplo) chega nela em cerca de um segundo.
// Histórico, contadores e alertas ficam em cada nó.
package ha

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/clients"
	"github.com/ugoneiva/HeimdallDNS/internal/security"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
	"github.com/ugoneiva/HeimdallDNS/internal/webfilter"
)

const (
	RolePrimary = "primary"
	RoleReplica = "replica"

	pollEvery = 500 * time.Millisecond // o principal confere mudanças neste ritmo
	maxBody   = 64 << 20
)

// Tempos de espera (variáveis para os testes encurtarem).
var (
	longPoll  = 25 * time.Second // tempo máximo de uma espera da réplica
	retryWait = 5 * time.Second
)

// Snapshot é tudo o que vai do principal para as réplicas.
type Snapshot struct {
	Version   string                 `json:"version"`
	Lists     []store.List           `json:"lists"`
	Allow     []string               `json:"allow"`
	Deny      []string               `json:"deny"`
	Security  security.Settings      `json:"security"`
	Users     []store.User           `json:"users"`  // contas do painel (hash da senha e MFA)
	Tokens    []store.APIToken       `json:"tokens"` // tokens de API (só o hash)
	Clients   []clients.State        `json:"clients"`
	Local     []store.LocalRecord    `json:"local,omitempty"`
	Upstream  store.UpstreamSettings `json:"upstream"`
	Groups    []clients.Group        `json:"groups"`
	WebFilter webfilter.Settings     `json:"webfilter"`
}

// stamp calcula a versão (hash do conteúdo).
func (s *Snapshot) stamp() error {
	s.Version = ""
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	h := sha256.Sum256(b)
	s.Version = hex.EncodeToString(h[:12])
	return nil
}

// ReplicaInfo é uma réplica vista pelo principal.
type ReplicaInfo struct {
	Addr     string    `json:"addr"`
	LastSeen time.Time `json:"last_seen"`
	Version  string    `json:"version"`
}

// Source é o lado do principal.
type Source struct {
	token string
	build func() (Snapshot, error)
	log   *slog.Logger

	mu       sync.Mutex
	replicas map[string]ReplicaInfo
}

func NewSource(token string, build func() (Snapshot, error), log *slog.Logger) *Source {
	if log == nil {
		log = slog.Default()
	}
	return &Source{token: token, build: build, log: log, replicas: map[string]ReplicaInfo{}}
}

func (s *Source) current() (Snapshot, error) {
	snap, err := s.build()
	if err != nil {
		return snap, err
	}
	return snap, snap.stamp()
}

// ServeHTTP atende GET /api/sync/snapshot?since=<versão>. Responde na hora se
// a versão mudou; senão espera até 25 s por uma mudança (304 se nada mudar).
func (s *Source) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || s.token == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) != 1 {
		http.Error(w, "token de sincronização inválido", http.StatusUnauthorized)
		return
	}
	since := r.URL.Query().Get("since")
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	deadline := time.Now().Add(longPoll)
	for {
		snap, err := s.current()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if snap.Version != since {
			s.seen(host, snap.Version)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(snap)
			return
		}
		if time.Now().After(deadline) {
			s.seen(host, since)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(pollEvery):
		}
	}
}

func (s *Source) seen(addr, version string) {
	s.mu.Lock()
	s.replicas[addr] = ReplicaInfo{Addr: addr, LastSeen: time.Now(), Version: version}
	s.mu.Unlock()
}

// Replicas lista as réplicas vistas na última hora.
func (s *Source) Replicas() []ReplicaInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []ReplicaInfo{}
	for k, v := range s.replicas {
		if time.Since(v.LastSeen) > time.Hour {
			delete(s.replicas, k)
			continue
		}
		out = append(out, v)
	}
	return out
}

// Version devolve a versão atual (para o painel do principal).
func (s *Source) Version() string {
	snap, err := s.current()
	if err != nil {
		return ""
	}
	return snap.Version
}

// Replica é o lado da réplica.
type Replica struct {
	url   string
	token string
	apply func(Snapshot) error
	hc    *http.Client
	log   *slog.Logger

	mu       sync.Mutex
	version  string
	lastSync time.Time
	lastErr  string
}

type ReplicaOptions struct {
	PrimaryURL  string // URL base da API do principal, ex.: https://10.0.0.2:8053
	Token       string
	InsecureTLS bool // aceita certificado autoassinado do principal
	Apply       func(Snapshot) error
	Logger      *slog.Logger
}

func NewReplica(o ReplicaOptions) (*Replica, error) {
	if o.PrimaryURL == "" || o.Token == "" || o.Apply == nil {
		return nil, errors.New("ha: réplica precisa de primary_url e sync_token")
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if o.InsecureTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &Replica{url: strings.TrimSuffix(o.PrimaryURL, "/"), token: o.Token, apply: o.Apply, log: o.Logger,
		hc: &http.Client{Transport: tr, Timeout: longPoll + 15*time.Second}}, nil
}

// Run sincroniza até ctx terminar.
func (r *Replica) Run(ctx context.Context) {
	for ctx.Err() == nil {
		if err := r.once(ctx); err != nil && ctx.Err() == nil {
			r.mu.Lock()
			first := r.lastErr != err.Error()
			r.lastErr = err.Error()
			r.mu.Unlock()
			if first {
				r.log.Warn("sincronização com o principal falhou; tentando de novo", "principal", r.url, "erro", err)
			}
			select {
			case <-ctx.Done():
			case <-time.After(retryWait):
			}
		}
	}
}

func (r *Replica) once(ctx context.Context) error {
	r.mu.Lock()
	since := r.version
	r.mu.Unlock()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url+"/api/sync/snapshot?since="+since, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	// O long-poll pode ficar 25 s sem resposta: o erro anterior é limpo assim
	// que a conexão com o principal abre, não só quando a resposta chega.
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { r.connected() },
	}))
	resp, err := r.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		r.ok(since)
		return nil
	case http.StatusOK:
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("principal respondeu %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var snap Snapshot
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&snap); err != nil {
		return fmt.Errorf("snapshot inválido: %w", err)
	}
	if err := r.apply(snap); err != nil {
		return fmt.Errorf("aplicando snapshot: %w", err)
	}
	if since == "" || r.lastErrSet() {
		r.log.Info("sincronizado com o principal", "principal", r.url, "versao", snap.Version, "dispositivos", len(snap.Clients))
	}
	r.ok(snap.Version)
	return nil
}

func (r *Replica) connected() {
	r.mu.Lock()
	had := r.lastErr != ""
	r.lastErr = ""
	r.mu.Unlock()
	if had {
		r.log.Info("reconectado ao principal", "principal", r.url)
	}
}

func (r *Replica) lastErrSet() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastErr != ""
}

func (r *Replica) ok(version string) {
	r.mu.Lock()
	r.version, r.lastSync, r.lastErr = version, time.Now(), ""
	r.mu.Unlock()
}

// Status resume a sincronização (para o painel da réplica).
type Status struct {
	PrimaryURL string    `json:"primary_url"`
	Version    string    `json:"version"`
	LastSync   time.Time `json:"last_sync,omitzero"`
	Error      string    `json:"error,omitempty"`
}

func (r *Replica) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Status{PrimaryURL: r.url, Version: r.version, LastSync: r.lastSync, Error: r.lastErr}
}
