// Comando heimdalldns: servidor DNS com filtro e radar de dispositivos.
// Sem subcomando, roda o servidor; com subcomando (clients, isolate…),
// conversa com um servidor em execução pela API.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/api"
	"github.com/ugoneiva/HeimdallDNS/internal/cache"
	"github.com/ugoneiva/HeimdallDNS/internal/clients"
	"github.com/ugoneiva/HeimdallDNS/internal/config"
	"github.com/ugoneiva/HeimdallDNS/internal/detect"
	"github.com/ugoneiva/HeimdallDNS/internal/dhcp"
	"github.com/ugoneiva/HeimdallDNS/internal/export"
	"github.com/ugoneiva/HeimdallDNS/internal/filter"
	"github.com/ugoneiva/HeimdallDNS/internal/nrd"
	"github.com/ugoneiva/HeimdallDNS/internal/querylog"
	"github.com/ugoneiva/HeimdallDNS/internal/security"
	"github.com/ugoneiva/HeimdallDNS/internal/server"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
	"github.com/ugoneiva/HeimdallDNS/internal/tlsconf"
	"github.com/ugoneiva/HeimdallDNS/internal/upstream"
	"github.com/ugoneiva/HeimdallDNS/internal/webui"
)

var version = "dev"

const defaultConfig = "/etc/heimdalldns/heimdalldns.yaml"

func main() {
	var err error
	if len(os.Args) > 1 && isCommand(os.Args[1]) {
		err = runCLI(os.Args[1], os.Args[2:])
	} else {
		err = runServer()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "heimdalldns:", err)
		os.Exit(1)
	}
}

// loadConfig lê o arquivo; se ele não existir e o caminho for o padrão, usa os
// valores padrão (devolve missing = true).
func loadConfig(path string, explicit bool) (cfg *config.Config, missing bool, err error) {
	cfg, err = config.Load(path)
	if errors.Is(err, fs.ErrNotExist) && !explicit {
		return config.Default(), true, nil
	}
	return cfg, false, err
}

func runServer() error {
	cfgPath := flag.String("config", defaultConfig, "arquivo de configuração YAML")
	listen := flag.String("listen", "", "endereços DNS separados por vírgula (substitui dns.listen)")
	apiListen := flag.String("api", "", "endereço da API (substitui api.listen; \"off\" desliga)")
	dataDir := flag.String("data-dir", "", "diretório de dados (substitui data_dir)")
	showVersion := flag.Bool("version", false, "mostra a versão")
	flag.Usage = usage
	flag.Parse()
	if *showVersion {
		fmt.Println("heimdalldns", version)
		return nil
	}

	cfg, missing, err := loadConfig(*cfgPath, flagSet(flag.CommandLine, "config"))
	if err != nil {
		return err
	}
	if *listen != "" {
		cfg.DNS.Listen = strings.Split(*listen, ",")
	}
	if *apiListen != "" {
		cfg.API.Listen = *apiListen
		if *apiListen == "off" {
			cfg.API.Listen = ""
		}
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(cfg.Log.Level)}))
	slog.SetDefault(log)
	if missing {
		log.Warn("arquivo de configuração não encontrado; usando os padrões", "arquivo", *cfgPath)
	}
	log.Info("iniciando HeimdallDNS", "versao", version)
	started := time.Now()

	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(filepath.Join(cfg.DataDir, "heimdall.db"))
	if err != nil {
		return err
	}
	defer db.Close()

	ups, err := upstream.New(upstream.Options{
		Servers:   cfg.Upstream.Servers,
		Bootstrap: cfg.Upstream.Bootstrap,
		Mode:      cfg.Upstream.Mode,
		Timeout:   cfg.Upstream.Timeout,
		Logger:    log.With("componente", "upstream"),
	})
	if err != nil {
		return err
	}
	defer ups.Close()
	go ups.HealthCheck(ctx, cfg.Upstream.HealthInterval)

	lists := make([]filter.ListSpec, len(cfg.Filter.Lists))
	for i, l := range cfg.Filter.Lists {
		lists[i] = filter.ListSpec{Name: l.Name, URL: l.URL, Enabled: l.IsEnabled(), Category: l.Category}
	}
	flt := filter.NewManager(filter.ManagerOptions{
		Lists:    lists,
		Allow:    cfg.Filter.Allow,
		Deny:     cfg.Filter.Deny,
		CacheDir: filepath.Join(cfg.DataDir, "lists"),
		Interval: cfg.Filter.UpdateInterval,
		Logger:   log.With("componente", "filtro"),
	})
	if err := api.LoadUserFilter(db, flt); err != nil {
		return err
	}
	flt.Start(ctx)

	// O alerta de dispositivo novo precisa do gerente de segurança, criado logo abaixo.
	var sec *security.Manager
	reg, err := newRegistry(cfg, db, log.With("componente", "radar"), func(id string, ip netip.Addr) {
		if sec == nil || !sec.Settings().NewDevice {
			return
		}
		sec.Raise(security.Alert{
			Kind: security.KindNewDevice, Severity: security.SevLow, ClientID: id, ClientIP: ip.String(),
			Summary: "Dispositivo novo na rede: " + sec.ClientName(id, ip.String()),
		})
	})
	if err != nil {
		return err
	}

	exp, err := export.New(export.Options{
		File: cfg.Export.File, Syslog: cfg.Export.Syslog, Queries: cfg.Export.Queries,
		Logger: log.With("componente", "exportacao"),
	})
	if err != nil {
		return err
	}
	expDone := make(chan struct{})
	go func() {
		exp.Run(ctx)
		close(expDone)
	}()
	secOpts := security.Options{
		Store: db, Clients: reg, Logger: log.With("componente", "seguranca"),
		Defaults: security.Settings{
			DGA: cfg.Security.DGA, Tunnel: cfg.Security.Tunnel, NRD: cfg.Security.NRD,
			NRDAction: cfg.Security.NRDAction, NRDMaxDays: max(1, int(cfg.Security.NRDMaxAge.Hours()/24)),
			NewDevice: cfg.Security.NewDeviceAlerts, AutoIsolate: cfg.Security.AutoIsolate,
			Ignore: cfg.Security.IgnoreDomains,
		},
	}
	if exp.Enabled() {
		secOpts.Exporter = exp
		log.Info("exportação para SIEM ligada", "arquivo", cfg.Export.File, "syslog", cfg.Export.Syslog, "consultas", cfg.Export.Queries)
	}
	if sec, err = security.New(secOpts); err != nil {
		return err
	}
	go func() {
		sec.Purge()
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sec.Purge()
			}
		}
	}()
	nrdCheck, err := nrd.New(nrd.Options{
		Store: db, DataDir: cfg.DataDir, Settings: sec.Settings, Raise: sec.Raise, Name: sec.ClientName,
		Logger: log.With("componente", "idade-dominios"),
	})
	if err != nil {
		return err
	}
	go nrdCheck.Run(ctx)
	det := detect.New(detect.Options{
		Settings: sec.Settings, Raise: sec.Raise, Name: sec.ClientName, NRD: nrdCheck,
		Logger: log.With("componente", "deteccao"),
	})
	go det.Run(ctx)
	regDone := make(chan struct{})
	go func() {
		reg.Run(ctx, cfg.Clients.NeighborInterval)
		close(regDone)
	}()
	go func() {
		oui, err := clients.LoadOUI(ctx, filepath.Join(cfg.DataDir, "manuf"), cfg.Clients.VendorDBMaxAge)
		if err != nil {
			log.Warn("base de fabricantes indisponível", "erro", err)
			return
		}
		reg.SetVendors(oui)
	}()

	qlog := querylog.New(querylog.Options{
		Sink:           db,
		StoreQueries:   cfg.History.StoreQueries,
		Retention:      cfg.History.Retention,
		StatsRetention: cfg.History.StatsRetention,
		Logger:         log.With("componente", "historico"),
	})
	go qlog.Run(ctx)

	dhcpSrv, err := newDHCP(cfg, db, reg, log.With("componente", "dhcp"))
	if err != nil {
		return err
	}
	if dhcpSrv != nil {
		if err := dhcpSrv.Start(ctx); err != nil {
			return fmt.Errorf("%w (a porta 67 exige root ou CAP_NET_BIND_SERVICE e CAP_NET_RAW)", err)
		}
	}

	tlsCfg, err := tlsconf.New(tlsconf.Options{
		CertFile: cfg.DNS.TLSCert, KeyFile: cfg.DNS.TLSKey,
		ACME: cfg.DNS.ACME, Email: cfg.DNS.ACMEEmail, CacheDir: filepath.Join(cfg.DataDir, "acme"),
		Host: cfg.DNS.PublicHost, ValidToken: reg.ValidToken,
	})
	if err != nil {
		return err
	}

	allowed, _ := cfg.AllowedPrefixes()
	local, _ := cfg.LocalAddrs()
	dnsCache := cache.New(cache.Options{
		Size:       cfg.Cache.Size,
		MinTTL:     cfg.Cache.MinTTL,
		MaxTTL:     cfg.Cache.MaxTTL,
		ServeStale: cfg.Cache.ServeStale,
	})
	srv := server.New(server.Options{
		Listen:       cfg.DNS.Listen,
		Allowed:      allowed,
		BlockMode:    cfg.DNS.BlockMode,
		BlockTTL:     cfg.DNS.BlockTTL,
		LocalRecords: local,
		Cache:        dnsCache,
		Filter:       flt.Matcher,
		Upstream:     ups,
		Clients:      reg,
		NRD:          nrdCheck,
		LocalLookup:  dhcpLookup(dhcpSrv),
		LocalPTR:     dhcpPTR(dhcpSrv),
		TLS:          tlsCfg,
		PublicHost:   cfg.DNS.PublicHost,
		DoTListen:    cfg.DNS.DoTListen,
		DoHListen:    cfg.DNS.DoHListen,
		DoHPlain:     cfg.DNS.DoHPlainHTTP,
		Timeout:      cfg.Upstream.Timeout + time.Second,
		Logger:       log.With("componente", "dns"),
		OnQuery:      onQuery(qlog, det, exp, log, cfg.Log.Queries),
	})
	if err := srv.Start(); err != nil {
		return err
	}

	var httpSrv *http.Server
	if cfg.API.Listen != "" {
		token, err := apiToken(cfg)
		if err != nil {
			return err
		}
		ln, err := net.Listen("tcp", cfg.API.Listen)
		if err != nil {
			return fmt.Errorf("api %s: %w", cfg.API.Listen, err)
		}
		tls := cfg.API.TLSCert != ""
		httpSrv = &http.Server{
			Handler: api.New(api.Deps{
				Context: ctx, Token: token, Version: version, Started: started,
				Server: srv, Cache: dnsCache, Upstream: ups, Filter: flt, Clients: reg,
				Store: db, Log: qlog, Security: sec, NRD: nrdCheck, UI: webui.FS(), Secure: tls, DHCP: dhcpSrv,
				Encrypted: api.Encrypted{
					PublicHost: cfg.DNS.PublicHost, DoH: cfg.DNS.DoHListen != "", DoT: len(cfg.DNS.DoTListen) > 0,
					DoHPort: portOf(cfg.DNS.DoHListen), DoTPort: portOf(firstOr(cfg.DNS.DoTListen)),
				},
				Logger: log.With("componente", "api"),
			}),
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			var err error
			if tls {
				err = httpSrv.ServeTLS(ln, cfg.API.TLSCert, cfg.API.TLSKey)
			} else {
				err = httpSrv.Serve(ln)
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("API parou", "erro", err)
			}
		}()
		scheme := "http"
		if tls {
			scheme = "https"
		}
		log.Info("painel e API ouvindo", "endereco", scheme+"://"+ln.Addr().String())
	}

	// SIGHUP baixa as listas de novo.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	for {
		select {
		case <-hup:
			log.Info("SIGHUP: atualizando as listas")
			go flt.Refresh(ctx)
		case <-ctx.Done():
			log.Info("encerrando")
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if httpSrv != nil {
				_ = httpSrv.Shutdown(sctx)
			}
			srv.Shutdown(sctx)
			cancel()
			<-regDone     // grava os clientes
			<-qlog.Done() // grava o histórico pendente
			<-expDone     // esvazia a fila de exportação
			c := srv.Counters()
			log.Info("consultas atendidas", "total", c.Total, "bloqueadas", c.Blocked, "isoladas", c.Isolated, "cache", c.Cached)
			return nil
		}
	}
}

func newRegistry(cfg *config.Config, db *store.Store, log *slog.Logger, onNew func(string, netip.Addr)) (*clients.Registry, error) {
	opts := clients.Options{
		Store:       db,
		Neighbors:   clients.Neighbors,
		IsolateMode: cfg.Clients.IsolateMode,
		OnNew:       onNew,
		Logger:      log,
	}
	switch ptr := cfg.Clients.PTRServer; ptr {
	case "":
	case "auto":
		if gw, err := clients.DefaultGateway(); err == nil {
			opts.PTR = clients.PTRLookup(net.JoinHostPort(gw.String(), "53"))
			log.Info("nomes reversos pelo gateway", "servidor", gw)
		} else {
			log.Warn("sem gateway para os nomes reversos", "erro", err)
		}
	default:
		if _, _, err := net.SplitHostPort(ptr); err != nil {
			ptr = net.JoinHostPort(ptr, "53")
		}
		opts.PTR = clients.PTRLookup(ptr)
	}
	return clients.NewRegistry(opts)
}

// apiToken usa o token da configuração ou o de <data_dir>/api.token, criando
// um aleatório na primeira vez.
func apiToken(cfg *config.Config) (string, error) {
	if cfg.API.Token != "" {
		return cfg.API.Token, nil
	}
	path := filepath.Join(cfg.DataDir, "api.token")
	if b, err := os.ReadFile(path); err == nil {
		if t := strings.TrimSpace(string(b)); t != "" {
			return t, nil
		}
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	t := hex.EncodeToString(b)
	if err := os.WriteFile(path, []byte(t+"\n"), 0o600); err != nil {
		return "", err
	}
	slog.Info("token da API criado", "arquivo", path)
	return t, nil
}

// onQuery manda cada consulta para o histórico, as detecções, a exportação
// e, se pedido, para o log. Nenhum deles bloqueia.
func onQuery(qlog *querylog.Recorder, det *detect.Detector, exp *export.Exporter, log *slog.Logger, logQueries bool) func(server.Event) {
	return func(e server.Event) {
		qlog.Record(e)
		det.Observe(e)
		exp.Query(e)
		if !logQueries {
			return
		}
		log.Info("consulta", "cliente", e.Client, "nome_cliente", e.Display, "nome", e.Name, "tipo", e.Type,
			"status", e.Status, "rcode", e.Rcode, "regra", e.Rule, "upstream", e.Upstream,
			"tempo", e.Duration.Round(time.Microsecond))
	}
}

// newDHCP monta o servidor DHCP se estiver ligado (nil, nil se não).
func newDHCP(cfg *config.Config, db *store.Store, reg *clients.Registry, log *slog.Logger) (*dhcp.Server, error) {
	c := cfg.DHCP
	if !c.Enabled {
		return nil, nil
	}
	serverIP, subnet, err := dhcp.InterfaceAddr(c.Interface)
	if err != nil {
		return nil, err
	}
	if c.Subnet != "" {
		if subnet, err = netip.ParsePrefix(c.Subnet); err != nil {
			return nil, fmt.Errorf("dhcp.subnet: %w", err)
		}
		subnet = subnet.Masked()
	}
	start, _ := netip.ParseAddr(c.RangeStart)
	end, _ := netip.ParseAddr(c.RangeEnd)
	parse := func(list []string, field string) ([]netip.Addr, error) {
		var out []netip.Addr
		for _, v := range list {
			a, err := netip.ParseAddr(strings.TrimSpace(v))
			if err != nil || !a.Is4() {
				return nil, fmt.Errorf("dhcp.%s: %q inválido", field, v)
			}
			out = append(out, a)
		}
		return out, nil
	}
	routers, err := parse(c.Router, "router")
	if err != nil {
		return nil, err
	}
	if len(routers) == 0 {
		if gw, err := clients.DefaultGateway(); err == nil && subnet.Contains(gw) {
			routers = []netip.Addr{gw}
		}
	}
	dnsServers, err := parse(c.DNS, "dns")
	if err != nil {
		return nil, err
	}
	log.Warn("DHCP ligado: confirme que o DHCP do roteador está desligado, ou os dois vão brigar",
		"interface", c.Interface)
	return dhcp.New(dhcp.Options{
		Interface: c.Interface, Start: start, End: end, Subnet: subnet, ServerIP: serverIP,
		Routers: routers, DNS: dnsServers, Domain: c.Domain, LeaseTime: c.LeaseTime, Store: db, Logger: log,
		OnLease: func(l dhcp.Lease) { reg.LearnLease(l.IP, l.MAC, l.Hostname) },
	})
}

func dhcpLookup(s *dhcp.Server) func(string) []netip.Addr {
	if s == nil {
		return nil
	}
	return s.Lookup
}

func dhcpPTR(s *dhcp.Server) func(netip.Addr) string {
	if s == nil {
		return nil
	}
	return s.PTR
}

func portOf(addr string) string {
	if _, p, err := net.SplitHostPort(addr); err == nil {
		return p
	}
	return ""
}

func firstOr(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

func parseLevel(s string) slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(s)); err != nil {
		return slog.LevelInfo
	}
	return l
}

func flagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func usage() {
	fmt.Fprintf(os.Stderr, `Uso:
  heimdalldns [opções]              roda o servidor
  heimdalldns <comando> [opções]    controla um servidor em execução

Comandos:
  status                            resumo do servidor
  clients                           lista os dispositivos
  client  <ref>                     detalhes de um dispositivo
  name    <ref> <nome>              dá um nome ao dispositivo
  isolate <ref> [-mode m] [-reason texto] [-except dom1,dom2]
  release <ref>                     tira do isolamento
  rules   <ref> [-deny r1,r2] [-allow r1,r2] [-global=false]
  forget  <ref>                     esquece o dispositivo
  services                          serviços para regras (service:tiktok, service:social…)
  passwd                            define uma nova senha do painel (recupera o acesso)

<ref> é o id, IP, MAC ou nome do dispositivo.

Opções do servidor:
`)
	flag.PrintDefaults()
}
