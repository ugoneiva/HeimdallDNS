// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

// Comando heimdalldns: servidor DNS com filtro e radar de dispositivos.
// Sem subcomando, roda o servidor; com subcomando (clients, isolate…),
// conversa com um servidor em execução pela API.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/ad"
	"github.com/ugoneiva/HeimdallDNS/internal/api"
	"github.com/ugoneiva/HeimdallDNS/internal/backup"
	"github.com/ugoneiva/HeimdallDNS/internal/cache"
	"github.com/ugoneiva/HeimdallDNS/internal/clients"
	"github.com/ugoneiva/HeimdallDNS/internal/config"
	"github.com/ugoneiva/HeimdallDNS/internal/console"
	"github.com/ugoneiva/HeimdallDNS/internal/detect"
	"github.com/ugoneiva/HeimdallDNS/internal/dhcp"
	"github.com/ugoneiva/HeimdallDNS/internal/export"
	"github.com/ugoneiva/HeimdallDNS/internal/filter"
	"github.com/ugoneiva/HeimdallDNS/internal/forward"
	"github.com/ugoneiva/HeimdallDNS/internal/ha"
	"github.com/ugoneiva/HeimdallDNS/internal/notify"
	"github.com/ugoneiva/HeimdallDNS/internal/nrd"
	"github.com/ugoneiva/HeimdallDNS/internal/querylog"
	"github.com/ugoneiva/HeimdallDNS/internal/security"
	"github.com/ugoneiva/HeimdallDNS/internal/server"
	"github.com/ugoneiva/HeimdallDNS/internal/store"
	"github.com/ugoneiva/HeimdallDNS/internal/tlsconf"
	"github.com/ugoneiva/HeimdallDNS/internal/upstream"
	"github.com/ugoneiva/HeimdallDNS/internal/webfilter"
	"github.com/ugoneiva/HeimdallDNS/internal/webui"
)

// Preenchidos na compilação (-ldflags -X); ver Makefile e .goreleaser.yaml.
var (
	version = "dev"
	commit  = ""
	date    = ""
)

// errRestart pede para o main recarregar o binário (aplicar uma restauração).
var errRestart = errors.New("reinício pedido")

// autoBackup gera as cópias automáticas: a primeira 5 min depois de subir.
func autoBackup(ctx context.Context, a backup.Auto, every time.Duration, nt *notify.Manager, log *slog.Logger) {
	t := time.NewTimer(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if name, err := a.RunOnce(); err != nil {
				log.Error("backup automático falhou", "erro", err)
				nt.Send(systemNotice("Backup automático falhou", err, [2]string{"Pasta", a.Dir}))
			} else {
				log.Info("backup automático gravado", "arquivo", name)
			}
			t.Reset(every)
		}
	}
}

const defaultConfig = "/etc/heimdalldns/heimdalldns.yaml"

func main() {
	var err error
	switch {
	case len(os.Args) > 1 && os.Args[1] == "console":
		err = runConsole(os.Args[2:])
	case len(os.Args) > 1 && isCommand(os.Args[1]):
		err = runCLI(os.Args[1], os.Args[2:])
	default:
		err = runServer()
		if errors.Is(err, errRestart) {
			// Mesmo processo (o systemd não percebe), binário e argumentos.
			exe, xerr := os.Executable()
			if xerr == nil {
				xerr = syscall.Exec(exe, os.Args, os.Environ())
			}
			err = fmt.Errorf("reinício: %w", xerr)
		}
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
		if commit != "" {
			fmt.Println("commit", commit, "compilado em", date)
		}
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
	var restartRequested atomic.Bool
	restart := func() {
		restartRequested.Store(true)
		stop()
	}

	// Restauração pendente (pedida pelo painel): troca o banco antes de abrir.
	if m, kept, err := backup.ApplyStaged(cfg.DataDir); err != nil {
		log.Error("restauração pendente falhou; seguindo com o banco atual", "erro", err)
	} else if m != nil {
		log.Warn("backup restaurado", "de", m.Hostname, "criado", m.Created, "versao", m.Version, "banco_anterior", kept)
	}
	db, err := store.Open(filepath.Join(cfg.DataDir, "heimdall.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	node, _ := os.Hostname()
	nt := notify.New(notify.Options{Node: node, Logger: log.With("componente", "notificacoes")})
	if err := api.LoadNotify(db, nt); err != nil {
		log.Warn("notificações do painel inválidas; seguindo sem elas", "erro", err)
	}
	go nt.Run(ctx)
	backupDir := cfg.Backup.Dir
	if backupDir == "" {
		backupDir = filepath.Join(cfg.DataDir, "backups")
	}
	configPath := *cfgPath
	if missing {
		configPath = ""
	}
	if cfg.Backup.Interval > 0 {
		go autoBackup(ctx, backup.Auto{Options: backup.Options{Store: db, TempDir: cfg.DataDir, ConfigPath: configPath,
			Full: cfg.Backup.Full, Version: version}, Dir: backupDir, Keep: cfg.Backup.Keep}, cfg.Backup.Interval, nt, log.With("componente", "backup"))
	}

	ups, err := upstream.New(upstream.Options{
		Servers:   cfg.Upstream.Servers,
		Bootstrap: cfg.Upstream.Bootstrap,
		Mode:      cfg.Upstream.Mode,
		Timeout:   cfg.Upstream.Timeout,
		Logger:    log.With("componente", "upstream"),

		RequireDNSSEC: cfg.Upstream.RequireDNSSEC,
	})
	if err != nil {
		return err
	}
	defer ups.Close()
	if err := api.LoadUpstream(db, ups); err != nil {
		log.Warn("upstreams do painel inválidos; usando os do arquivo", "erro", err)
	}
	ups.SetOnHealth(func(up bool, servers []string) { nt.Send(upstreamNotice(up, servers)) })
	go ups.HealthCheck(ctx, cfg.Upstream.HealthInterval)

	fwRules := make([]forward.Rule, len(cfg.DNS.Conditional))
	for i, c := range cfg.DNS.Conditional {
		fwRules[i] = forward.Rule{Domain: c.Domain, Network: c.Network, Servers: c.Servers, Comment: c.Comment}
	}
	fwd, err := forward.NewManager(fwRules, cfg.Upstream.Timeout, log.With("componente", "encaminhamento"))
	if err != nil {
		return err
	}
	defer fwd.Close()
	if err := api.LoadForward(db, fwd); err != nil {
		log.Warn("encaminhamento condicional do painel inválido; usando só o do arquivo", "erro", err)
	}

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
		OnListError: func(name, url string, err error) {
			nt.Send(systemNotice("Lista de bloqueio não atualizou: "+name, err, [2]string{"Endereço", url}))
		},
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
	reg.SetOnIsolation(func(c *clients.Client, isolated bool, reason string) { nt.Send(isolationNotice(c, isolated, reason)) })
	if err := api.LoadGroups(db, reg); err != nil {
		log.Warn("grupos de dispositivos inválidos; seguindo sem eles", "erro", err)
	}
	// Filtro web: só as categorias em uso (globais ou de algum grupo) são baixadas.
	wf := webfilter.New(webfilter.Options{CacheDir: filepath.Join(cfg.DataDir, "lists"), Interval: cfg.Filter.UpdateInterval,
		Logger: log.With("componente", "filtro-web")})
	if err := api.LoadWebFilter(db, wf, reg); err != nil {
		log.Warn("configuração do filtro web inválida; seguindo sem ela", "erro", err)
	}
	go wf.Run(ctx)

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
		Notify: func(ev store.SecurityEvent, client, response string) { nt.Send(securityNotice(ev, client, response)) },
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
	fwd.OnChange = dnsCache.Flush
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
		WebFilter:    wf,
		Forward:      fwd,
		PrivateUpstream: func() bool {
			servers, _ := ups.Config()
			return forward.HasPrivate(servers)
		},
		LocalLookup: dhcpLookup(dhcpSrv),
		LocalPTR:    dhcpPTR(dhcpSrv),
		TLS:         tlsCfg,
		PublicHost:  cfg.DNS.PublicHost,
		DoTListen:   cfg.DNS.DoTListen,
		DoHListen:   cfg.DNS.DoHListen,
		DoHPlain:    cfg.DNS.DoHPlainHTTP,
		Timeout:     cfg.Upstream.Timeout + time.Second,
		Logger:      log.With("componente", "dns"),
		OnQuery:     onQuery(qlog, det, exp, log, cfg.Log.Queries),
		RateLimit:   rateLimit(cfg),
		OnRateLimit: func(ip netip.Addr, id string, dropped uint64) {
			sec.Raise(security.Alert{
				Kind: security.KindFlood, Severity: security.SevMedium, ClientID: id, ClientIP: ip.String(),
				Summary: fmt.Sprintf("%s passou do limite de %g consultas/s; o excesso está sendo recusado",
					sec.ClientName(id, ip.String()), cfg.DNS.RateLimit.QPS),
				Details: map[string]any{"dropped": dropped, "qps_limit": cfg.DNS.RateLimit.QPS},
			})
		},
	})
	if err := api.LoadLocal(db, local, srv); err != nil {
		log.Warn("registros locais do painel inválidos; usando só os do arquivo", "erro", err)
	}
	if err := srv.Start(); err != nil {
		if errors.Is(err, syscall.EADDRINUSE) {
			return fmt.Errorf("%w\n  a porta já está em uso: no Ubuntu/Debian/Fedora costuma ser o systemd-resolved;\n"+
				"  desligue o ouvinte dele (DNSStubListener=no em /etc/systemd/resolved.conf e systemctl restart systemd-resolved)\n"+
				"  ou ponha em dns.listen só o IP da rede (ex.: [\"192.168.0.2:53\"])", err)
		}
		if errors.Is(err, syscall.EACCES) {
			return fmt.Errorf("%w\n  portas abaixo de 1024 exigem root ou CAP_NET_BIND_SERVICE (o serviço do systemd já dá)", err)
		}
		return err
	}

	haDeps, err := newHA(ctx, cfg, db, flt, sec, reg, srv, ups, wf, fwd, nt, local, log.With("componente", "ha"))
	if err != nil {
		return err
	}
	adClient, err := newAD(ctx, cfg, log.With("componente", "ad"))
	if err != nil {
		return err
	}
	var auditExp api.AuditExporter
	if exp.Enabled() {
		auditExp = exp
	}

	var httpSrv *http.Server
	if cfg.API.Listen != "" {
		token, err := apiToken(cfg)
		if err != nil {
			return err
		}
		if cfg.API.TLSCert == "auto" {
			if cfg.API.TLSCert, cfg.API.TLSKey, err = tlsconf.SelfSigned(cfg.DataDir); err != nil {
				return fmt.Errorf("certificado do painel: %w", err)
			}
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
				HA: haDeps, AD: adClient, Audit: auditExp, WebFilter: wf, Forward: fwd, Notify: nt,
				ADLogin: api.ADLogin{Enabled: cfg.AD.Login.Enabled, AdminGroups: cfg.AD.Login.AdminGroups,
					OperatorGroups: cfg.AD.Login.OperatorGroups, ViewerGroups: cfg.AD.Login.ViewerGroups, RequireMFA: cfg.AD.Login.RequireMFA},
				Encrypted: api.Encrypted{
					PublicHost: cfg.DNS.PublicHost, DoH: cfg.DNS.DoHListen != "", DoT: len(cfg.DNS.DoTListen) > 0,
					DoHPort: portOf(cfg.DNS.DoHListen), DoTPort: portOf(firstOr(cfg.DNS.DoTListen)),
				},
				DataDir: cfg.DataDir, ConfigPath: configPath, BackupDir: backupDir, BackupKeep: cfg.Backup.Keep,
				BackupAuto: cfg.Backup.Interval > 0, Restart: restart,
				LocalConfig:    local,
				UpstreamConfig: upstream.Options{Servers: cfg.Upstream.Servers, Bootstrap: cfg.Upstream.Bootstrap, Mode: cfg.Upstream.Mode},
				Logger:         log.With("componente", "api"),
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
			go wf.Refresh(ctx)
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
			if restartRequested.Load() {
				return errRestart
			}
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

// runConsole roda o console de MSP: acompanha vários HeimdallDNS pela API.
func runConsole(args []string) error {
	fs := flag.NewFlagSet("console", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8070", "endereço do console")
	dataDir := fs.String("data-dir", "/var/lib/heimdalldns-console", "diretório de dados (guarda os tokens dos clientes)")
	cert := fs.String("tls-cert", "", "certificado HTTPS")
	key := fs.String("tls-key", "", "chave do certificado")
	_ = fs.Parse(args)

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)
	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return err
	}
	db, err := store.Open(filepath.Join(*dataDir, "console.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	con, err := console.New(console.Options{Store: db, Logger: log})
	if err != nil {
		return err
	}
	go con.Run(ctx)
	srv := &http.Server{
		Handler: api.New(api.Deps{Context: ctx, Version: version, Started: time.Now(), Store: db, Console: con,
			UI: webui.FS(), Secure: *cert != "", Logger: log}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	scheme := "http"
	if *cert != "" {
		scheme = "https"
	}
	log.Info("console de MSP ouvindo", "endereco", scheme+"://"+ln.Addr().String())
	if *cert != "" {
		err = srv.ServeTLS(ln, *cert, *key)
	} else {
		err = srv.Serve(ln)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// newAD conecta ao Active Directory, se ligado. Uma falha de conexão não
// impede o DNS de subir: só fica registrada (o DC pode estar fora do ar).
func newAD(ctx context.Context, cfg *config.Config, log *slog.Logger) (*ad.Client, error) {
	c := cfg.AD
	if !c.Enabled {
		return nil, nil
	}
	pw, err := os.ReadFile(c.BindPasswordFile)
	if err != nil {
		return nil, fmt.Errorf("ad.bind_password_file: %w", err)
	}
	client, err := ad.New(ad.Options{URL: c.URL, BaseDN: c.BaseDN, BindUser: c.BindUser,
		BindPassword: strings.TrimRight(string(pw), "\r\n"), CAFile: c.CAFile, InsecureTLS: c.InsecureTLS,
		Write: c.Write, UserOUs: c.UserOUs, ManagedGroups: c.ManagedGroups, DNSZones: c.DNSZones, Logger: log})
	if err != nil {
		return nil, err
	}
	if info, err := client.Check(ctx); err != nil {
		log.Warn("Active Directory inacessível agora", "erro", err)
	} else {
		log.Info("Active Directory conectado", "dominio", info.Domain, "servidor", info.DNSHostName, "tipo", info.Vendor, "escrita", info.Write)
	}
	return client, nil
}

// newHA liga a alta disponibilidade: o principal publica o snapshot; a
// réplica o puxa e aplica (listas, regras, segurança, dispositivos, senha).
func newHA(ctx context.Context, cfg *config.Config, db *store.Store, flt *filter.Manager, sec *security.Manager,
	reg *clients.Registry, srv *server.Server, ups *upstream.Group, wf *webfilter.Manager, fwd *forward.Manager, nt *notify.Manager, localCfg map[string][]netip.Addr, log *slog.Logger) (api.HA, error) {
	h := api.HA{Role: cfg.HA.Role}
	switch cfg.HA.Role {
	case ha.RolePrimary:
		h.Source = ha.NewSource(cfg.HA.SyncToken, func() (ha.Snapshot, error) {
			snap := ha.Snapshot{Security: sec.Settings(), Clients: reg.Export()}
			var err error
			if snap.Lists, err = db.Lists(); err != nil {
				return snap, err
			}
			if _, err = db.GetJSON(api.AllowKey, &snap.Allow); err != nil {
				return snap, err
			}
			if _, err = db.GetJSON(api.DenyKey, &snap.Deny); err != nil {
				return snap, err
			}
			if _, err = db.GetJSON(api.LocalKey, &snap.Local); err != nil {
				return snap, err
			}
			if _, err = db.GetJSON(api.UpstreamKey, &snap.Upstream); err != nil {
				return snap, err
			}
			if _, err = db.GetJSON(api.GroupsKey, &snap.Groups); err != nil {
				return snap, err
			}
			if _, err = db.GetJSON(api.ForwardKey, &snap.Forward); err != nil {
				return snap, err
			}
			snap.Notify = nt.Settings()
			snap.WebFilter = wf.Settings()
			if snap.Users, err = db.Users(); err != nil {
				return snap, err
			}
			for i := range snap.Users {
				// Só o que importa para entrar: o resto muda a cada login e
				// faria a versão do snapshot girar à toa.
				snap.Users[i].LastLogin = time.Time{}
				snap.Users[i].MFA.Pending, snap.Users[i].MFA.LastStep = "", 0
				for j := range snap.Users[i].MFA.Passkeys {
					snap.Users[i].MFA.Passkeys[j].LastUsed = time.Time{}
				}
			}
			if snap.Tokens, err = db.Tokens(); err != nil {
				return snap, err
			}
			for i := range snap.Tokens {
				snap.Tokens[i].LastUsed = time.Time{}
			}
			return snap, nil
		}, log)
		log.Info("nó principal: réplicas sincronizam em /api/sync/snapshot")
	case ha.RoleReplica:
		var lastLists, lastRules, lastLocal, lastUps, lastUsers, lastTokens, lastGroups, lastWeb, lastFwd, lastNotify string
		r, err := ha.NewReplica(ha.ReplicaOptions{
			PrimaryURL: cfg.HA.PrimaryURL, Token: cfg.HA.SyncToken, InsecureTLS: cfg.HA.InsecureTLS, Logger: log,
			Apply: func(s ha.Snapshot) error {
				// Listas e regras só remontam o filtro quando mudam (é caro).
				lb, _ := json.Marshal(s.Lists)
				rb, _ := json.Marshal([][]string{s.Allow, s.Deny})
				if string(lb) != lastLists || string(rb) != lastRules {
					if err := db.ReplaceLists(s.Lists); err != nil {
						return err
					}
					if err := db.SetJSON(api.AllowKey, s.Allow); err != nil {
						return err
					}
					if err := db.SetJSON(api.DenyKey, s.Deny); err != nil {
						return err
					}
					if err := api.LoadUserFilter(db, flt); err != nil {
						return err
					}
					go flt.Apply(ctx)
					lastLists, lastRules = string(lb), string(rb)
				}
				if err := sec.SetSettings(s.Security); err != nil {
					return err
				}
				if b, _ := json.Marshal(s.Local); string(b) != lastLocal {
					if err := db.SetJSON(api.LocalKey, s.Local); err != nil {
						return err
					}
					if err := api.LoadLocal(db, localCfg, srv); err != nil {
						return err
					}
					lastLocal = string(b)
				}
				if b, _ := json.Marshal(s.Upstream); string(b) != lastUps {
					if err := db.SetJSON(api.UpstreamKey, s.Upstream); err != nil {
						return err
					}
					opts := upstream.Options{Servers: cfg.Upstream.Servers, Bootstrap: cfg.Upstream.Bootstrap, Mode: cfg.Upstream.Mode}
					if len(s.Upstream.Servers) > 0 {
						opts = upstream.Options{Servers: s.Upstream.Servers, Mode: s.Upstream.Mode}
					}
					if err := ups.Reconfigure(opts); err != nil {
						return err
					}
					lastUps = string(b)
				}
				if b, _ := json.Marshal(s.Notify); string(b) != lastNotify {
					if err := db.SetJSON(api.NotifyKey, s.Notify); err != nil {
						return err
					}
					if err := nt.SetSettings(s.Notify); err != nil {
						return err
					}
					lastNotify = string(b)
				}
				if b, _ := json.Marshal(s.Forward); string(b) != lastFwd {
					if err := db.SetJSON(api.ForwardKey, s.Forward); err != nil {
						return err
					}
					if err := fwd.Apply(s.Forward); err != nil {
						return err
					}
					lastFwd = string(b)
				}
				if b, _ := json.Marshal(s.Groups); string(b) != lastGroups {
					if err := db.SetJSON(api.GroupsKey, s.Groups); err != nil {
						return err
					}
					if err := reg.SetGroups(s.Groups); err != nil {
						return err
					}
					lastGroups = string(b)
				}
				if b, _ := json.Marshal(s.WebFilter); string(b) != lastWeb {
					if err := wf.SetSettings(s.WebFilter); err != nil {
						return err
					}
					if err := db.SetJSON(api.WebFilterKey, s.WebFilter); err != nil {
						return err
					}
					lastWeb = string(b)
				}
				api.UpdateWebUsed(wf, reg)
				if b, _ := json.Marshal(s.Users); string(b) != lastUsers {
					// Mantém o que é deste nó: último acesso e o passo do MFA já
					// usado (senão um código poderia ser reusado aqui).
					if local, err := db.Users(); err == nil {
						byID := map[int64]store.User{}
						for _, u := range local {
							byID[u.ID] = u
						}
						for i, u := range s.Users {
							if l, ok := byID[u.ID]; ok && strings.EqualFold(l.Username, u.Username) {
								s.Users[i].LastLogin = l.LastLogin
								if l.MFA.Secret == u.MFA.Secret {
									s.Users[i].MFA.LastStep = l.MFA.LastStep
								}
								s.Users[i].MFA.Recovery = keepUsedRecovery(u.MFA.Recovery, l.MFA.Recovery)
								for j, pk := range s.Users[i].MFA.Passkeys {
									for _, lp := range l.MFA.Passkeys {
										if lp.ID == pk.ID {
											s.Users[i].MFA.Passkeys[j].LastUsed = lp.LastUsed
										}
									}
								}
							}
						}
					}
					if err := db.ReplaceUsers(s.Users); err != nil {
						return err
					}
					lastUsers = string(b)
				}
				if b, _ := json.Marshal(s.Tokens); string(b) != lastTokens {
					if err := db.ReplaceTokens(s.Tokens); err != nil {
						return err
					}
					lastTokens = string(b)
				}
				return reg.ApplyRemote(s.Clients)
			},
		})
		if err != nil {
			return h, err
		}
		h.Replica = r
		go r.Run(ctx)
		log.Info("nó réplica: configuração vem do principal", "principal", cfg.HA.PrimaryURL)
	}
	return h, nil
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

func rateLimit(cfg *config.Config) server.RateLimit {
	rl := server.RateLimit{QPS: cfg.DNS.RateLimit.QPS, Burst: cfg.DNS.RateLimit.Burst}
	for _, p := range cfg.DNS.RateLimit.Exempt {
		if pfx, err := netip.ParsePrefix(p); err == nil {
			rl.Exempt = append(rl.Exempt, pfx.Masked())
		}
	}
	return rl
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
  users                             lista as contas do painel
  passwd  [-user nome]              define uma nova senha (recupera o acesso; padrão: admin)
  mfa-off [-user nome]              desliga a verificação em duas etapas e apaga as passkeys (perdeu o celular)
  backup  [-o arquivo] [-full] [-encrypt | -passphrase-file f]
                                    baixa um backup (banco + configuração)
  restore <arquivo> [-passphrase-file f] [-restart]
                                    restaura um backup (vale ao reiniciar)
  console [-listen] [-data-dir]     roda o console de MSP (vários HeimdallDNS num painel só)

<ref> é o id, IP, MAC ou nome do dispositivo.

Opções do servidor:
`)
	flag.PrintDefaults()
}

// keepUsedRecovery: um código de recuperação gasto nesta réplica não volta
// a valer com a sincronização. Se o principal gerou códigos novos (nenhum em
// comum), valem os novos.
func keepUsedRecovery(primary, local []string) []string {
	var common []string
	for _, h := range primary {
		if slices.Contains(local, h) {
			common = append(common, h)
		}
	}
	if len(common) == 0 {
		return primary
	}
	return common
}
