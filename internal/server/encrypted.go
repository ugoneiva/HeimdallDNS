package server

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const dohPath = "/dns-query"

// DoH atende DNS sobre HTTPS (RFC 8484): GET ?dns=<base64url> ou POST com
// application/dns-message. O caminho /dns-query/<token> identifica o aparelho.
func (s *Server) DoH() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.URL.Path, dohPath)
		if !ok || (tok != "" && !strings.HasPrefix(tok, "/")) {
			http.NotFound(w, r)
			return
		}
		tok = strings.Trim(tok, "/")
		if strings.Contains(tok, "/") {
			http.NotFound(w, r)
			return
		}

		var raw []byte
		switch r.Method {
		case http.MethodGet:
			b64 := strings.TrimRight(r.URL.Query().Get("dns"), "=")
			var err error
			if raw, err = base64.RawURLEncoding.DecodeString(b64); err != nil || len(raw) == 0 {
				http.Error(w, "parâmetro dns inválido", http.StatusBadRequest)
				return
			}
		case http.MethodPost:
			if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/dns-message") {
				http.Error(w, "use Content-Type: application/dns-message", http.StatusUnsupportedMediaType)
				return
			}
			var err error
			if raw, err = io.ReadAll(io.LimitReader(r.Body, dns.MaxMsgSize+1)); err != nil || len(raw) > dns.MaxMsgSize {
				http.Error(w, "mensagem grande demais", http.StatusRequestEntityTooLarge)
				return
			}
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "método não permitido", http.StatusMethodNotAllowed)
			return
		}
		req := new(dns.Msg)
		if err := req.Unpack(raw); err != nil {
			http.Error(w, "mensagem DNS inválida", http.StatusBadRequest)
			return
		}

		resp := s.answer(req, origin{client: addrFromHTTP(r.RemoteAddr), proto: "doh", token: tok})
		if resp == nil { // "drop" não existe no HTTP: recusa
			resp = reply(req, dns.RcodeRefused)
			s.finalize(req, resp, "doh")
		}
		out, err := resp.Pack()
		if err != nil {
			http.Error(w, "falha ao montar a resposta", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(int(minTTL(resp))))
		_, _ = w.Write(out)
	})
}

func addrFromHTTP(remote string) netip.Addr {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	a, _ := netip.ParseAddr(host)
	return a.Unmap()
}

// minTTL é o menor TTL da resposta, para o Cache-Control (RFC 8484 §5.1).
func minTTL(m *dns.Msg) uint32 {
	ttl := uint32(0)
	first := true
	for _, sec := range [][]dns.RR{m.Answer, m.Ns} {
		for _, rr := range sec {
			if t := rr.Header().Ttl; first || t < ttl {
				ttl, first = t, false
			}
		}
	}
	return ttl
}

// startEncrypted abre DoT e DoH, se configurados.
func (s *Server) startEncrypted() error {
	needTLS := len(s.opts.DoTListen) > 0 || (s.opts.DoHListen != "" && !s.opts.DoHPlain)
	if needTLS && s.opts.TLS == nil {
		return errors.New("DoT/DoH precisam de certificado (dns.tls_cert/tls_key ou dns.acme)")
	}
	for _, addr := range s.opts.DoTListen {
		cfg := s.opts.TLS.Clone()
		cfg.NextProtos = []string{"dot"} // RFC 7858; clientes sem ALPN também passam
		ln, err := tls.Listen("tcp", addr, cfg)
		if err != nil {
			return fmt.Errorf("dot %s: %w", addr, err)
		}
		srv := &dns.Server{Listener: ln, Net: "tcp-tls", Handler: s, ReadTimeout: 5 * time.Second,
			IdleTimeout: func() time.Duration { return 30 * time.Second }}
		s.servers = append(s.servers, srv)
		go func() {
			if err := srv.ActivateAndServe(); err != nil {
				s.log.Error("DoT parou", "erro", err)
			}
		}()
		s.dotAddrs = append(s.dotAddrs, ln.Addr())
		s.log.Info("DoT ouvindo", "endereco", ln.Addr().String())
	}
	if s.opts.DoHListen == "" {
		return nil
	}
	ln, err := net.Listen("tcp", s.opts.DoHListen)
	if err != nil {
		return fmt.Errorf("doh %s: %w", s.opts.DoHListen, err)
	}
	mux := http.NewServeMux()
	mux.Handle(dohPath, s.DoH())
	mux.Handle(dohPath+"/", s.DoH())
	s.doh = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	if !s.opts.DoHPlain {
		cfg := s.opts.TLS.Clone()
		if len(cfg.NextProtos) == 0 {
			cfg.NextProtos = []string{"h2", "http/1.1"}
		}
		s.doh.TLSConfig = cfg
	}
	s.dohAddr = ln.Addr()
	go func() {
		var err error
		if s.opts.DoHPlain {
			err = s.doh.Serve(ln)
		} else {
			err = s.doh.ServeTLS(ln, "", "")
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("DoH parou", "erro", err)
		}
	}()
	scheme := "https"
	if s.opts.DoHPlain {
		scheme = "http"
	}
	s.log.Info("DoH ouvindo", "endereco", scheme+"://"+ln.Addr().String()+dohPath)
	return nil
}
