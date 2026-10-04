// Comando heimdalldns: servidor DNS com filtro de bloqueio.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/cache"
	"github.com/ugoneiva/HeimdallDNS/internal/config"
	"github.com/ugoneiva/HeimdallDNS/internal/filter"
	"github.com/ugoneiva/HeimdallDNS/internal/server"
	"github.com/ugoneiva/HeimdallDNS/internal/upstream"
)

var version = "dev"

const defaultConfig = "/etc/heimdalldns/heimdalldns.yaml"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "heimdalldns:", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := flag.String("config", defaultConfig, "arquivo de configuração YAML")
	listen := flag.String("listen", "", "endereços DNS separados por vírgula (substitui dns.listen)")
	dataDir := flag.String("data-dir", "", "diretório de dados (substitui data_dir)")
	showVersion := flag.Bool("version", false, "mostra a versão")
	flag.Parse()
	if *showVersion {
		fmt.Println("heimdalldns", version)
		return nil
	}

	cfg, err := config.Load(*cfgPath)
	switch {
	case errors.Is(err, fs.ErrNotExist) && !flagSet("config"):
		cfg = config.Default()
	case err != nil:
		return err
	}
	if *listen != "" {
		cfg.DNS.Listen = strings.Split(*listen, ",")
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(cfg.Log.Level)}))
	slog.SetDefault(log)
	if errors.Is(err, fs.ErrNotExist) {
		log.Warn("arquivo de configuração não encontrado; usando os padrões", "arquivo", *cfgPath)
	}
	log.Info("iniciando HeimdallDNS", "versao", version)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
		lists[i] = filter.ListSpec{Name: l.Name, URL: l.URL, Enabled: l.IsEnabled()}
	}
	flt := filter.NewManager(filter.ManagerOptions{
		Lists:    lists,
		Allow:    cfg.Filter.Allow,
		Deny:     cfg.Filter.Deny,
		CacheDir: filepath.Join(cfg.DataDir, "lists"),
		Interval: cfg.Filter.UpdateInterval,
		Logger:   log.With("componente", "filtro"),
	})
	flt.Start(ctx)

	allowed, _ := cfg.AllowedPrefixes()
	local, _ := cfg.LocalAddrs()
	srv := server.New(server.Options{
		Listen:       cfg.DNS.Listen,
		Allowed:      allowed,
		BlockMode:    cfg.DNS.BlockMode,
		BlockTTL:     cfg.DNS.BlockTTL,
		LocalRecords: local,
		Cache: cache.New(cache.Options{
			Size:       cfg.Cache.Size,
			MinTTL:     cfg.Cache.MinTTL,
			MaxTTL:     cfg.Cache.MaxTTL,
			ServeStale: cfg.Cache.ServeStale,
		}),
		Filter:   flt.Matcher,
		Upstream: ups,
		Timeout:  cfg.Upstream.Timeout + time.Second,
		Logger:   log.With("componente", "dns"),
		OnQuery:  queryLogger(log, cfg.Log.Queries),
	})
	if err := srv.Start(); err != nil {
		return err
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
			srv.Shutdown(sctx)
			cancel()
			c := srv.Counters()
			log.Info("consultas atendidas", "total", c.Total, "bloqueadas", c.Blocked, "cache", c.Cached)
			return nil
		}
	}
}

func queryLogger(log *slog.Logger, enabled bool) func(server.Event) {
	if !enabled {
		return nil
	}
	return func(e server.Event) {
		log.Info("consulta", "cliente", e.Client, "nome", e.Name, "tipo", e.Type,
			"status", e.Status, "rcode", e.Rcode, "regra", e.Rule, "upstream", e.Upstream,
			"tempo", e.Duration.Round(time.Microsecond))
	}
}

func parseLevel(s string) slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(s)); err != nil {
		return slog.LevelInfo
	}
	return l
}

func flagSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}
