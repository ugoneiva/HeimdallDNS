// Package config carrega e valida a configuração do HeimdallDNS (YAML).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Modos de resposta para domínios bloqueados.
const (
	BlockNull     = "null"     // A 0.0.0.0 / AAAA :: (padrão; o navegador falha rápido)
	BlockNXDomain = "nxdomain" // domínio inexistente
	BlockRefused  = "refused"  // recusa explícita
	BlockDrop     = "drop"     // não responde (o cliente espera o tempo-limite)
)

// Estratégias de upstream.
const (
	UpstreamFastest  = "fastest"  // o de menor latência medida, com failover
	UpstreamParallel = "parallel" // consulta todos e usa a primeira resposta
	UpstreamFailover = "failover" // na ordem configurada
)

type Config struct {
	DNS          DNS                 `yaml:"dns"`
	Upstream     Upstream            `yaml:"upstream"`
	Cache        Cache               `yaml:"cache"`
	Filter       Filter              `yaml:"filter"`
	Clients      Clients             `yaml:"clients"`
	API          API                 `yaml:"api"`
	History      History             `yaml:"history"`
	Security     Security            `yaml:"security"`
	Export       Export              `yaml:"export"`
	DHCP         DHCP                `yaml:"dhcp"`
	HA           HA                  `yaml:"ha"`
	AD           AD                  `yaml:"ad"`
	Backup       Backup              `yaml:"backup"`
	LocalRecords map[string][]string `yaml:"local_records"`
	DataDir      string              `yaml:"data_dir"`
	Log          Log                 `yaml:"log"`
}

type DNS struct {
	Listen          []string `yaml:"listen"`
	AllowedNetworks []string `yaml:"allowed_networks"`
	BlockMode       string   `yaml:"block_mode"`
	BlockTTL        uint32   `yaml:"block_ttl"`

	// DNS criptografado, para aparelhos dentro e fora da rede.
	PublicHost   string   `yaml:"public_host"`    // ex.: dns.empresa.com.br
	DoTListen    []string `yaml:"dot_listen"`     // ex.: [":853"]
	DoHListen    string   `yaml:"doh_listen"`     // ex.: ":443"
	DoHPlainHTTP bool     `yaml:"doh_plain_http"` // atrás de proxy reverso que termina o TLS
	TLSCert      string   `yaml:"tls_cert"`
	TLSKey       string   `yaml:"tls_key"`
	ACME         bool     `yaml:"acme"` // certificado automático (Let's Encrypt, TLS-ALPN-01 na 443)
	ACMEEmail    string   `yaml:"acme_email"`
}

// EncryptedEnabled diz se DoT ou DoH estão ligados.
func (d DNS) EncryptedEnabled() bool { return len(d.DoTListen) > 0 || d.DoHListen != "" }

type Upstream struct {
	Servers        []string      `yaml:"servers"`
	Bootstrap      []string      `yaml:"bootstrap"`
	Mode           string        `yaml:"mode"`
	Timeout        time.Duration `yaml:"timeout"`
	HealthInterval time.Duration `yaml:"health_interval"`
}

type Cache struct {
	Size       int           `yaml:"size"`
	MinTTL     uint32        `yaml:"min_ttl"`
	MaxTTL     uint32        `yaml:"max_ttl"`
	ServeStale time.Duration `yaml:"serve_stale"` // 0 desliga
}

type Filter struct {
	Lists          []List        `yaml:"lists"`
	UpdateInterval time.Duration `yaml:"update_interval"`
	// Regras próprias. Domínio simples vale para ele e os subdomínios;
	// também aceitam a sintaxe das listas (||dominio^, /regex/).
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

type List struct {
	Name     string `yaml:"name"`
	URL      string `yaml:"url"` // http(s)://, file:// ou caminho local
	Enabled  *bool  `yaml:"enabled"`
	Category string `yaml:"category"` // "" (anúncios/rastreadores) ou "threat" (ameaças: bloqueio vira alerta)
}

func (l List) IsEnabled() bool { return l.Enabled == nil || *l.Enabled }

type Clients struct {
	// Servidor para os nomes reversos (PTR) dos dispositivos: "auto" usa o
	// gateway padrão (o roteador conhece os nomes do DHCP); "" desliga.
	PTRServer string `yaml:"ptr_server"`
	// Resposta padrão para um cliente isolado.
	IsolateMode      string        `yaml:"isolate_mode"`
	NeighborInterval time.Duration `yaml:"neighbor_interval"`
	// Base de fabricantes (OUI): baixada se faltar ou ficar mais velha que isso.
	VendorDBMaxAge time.Duration `yaml:"vendor_db_max_age"`
}

type API struct {
	Listen string `yaml:"listen"` // "" desliga
	// Token de acesso. Vazio = gerado em <data_dir>/api.token na primeira vez.
	Token string `yaml:"token"`
	// HTTPS para o painel e a API (recomendado fora do localhost).
	TLSCert string `yaml:"tls_cert"` // "auto" = autoassinado em <data_dir>/panel.crt
	TLSKey  string `yaml:"tls_key"`
}

// Backup são as cópias automáticas (o painel também gera cópias na hora).
type Backup struct {
	Interval time.Duration `yaml:"interval"` // 0 desliga as automáticas
	Keep     int           `yaml:"keep"`     // quantas guardar
	Dir      string        `yaml:"dir"`      // "" = <data_dir>/backups
	Full     bool          `yaml:"full"`     // inclui o histórico de consultas
}

type History struct {
	StoreQueries   bool          `yaml:"store_queries"`   // grava cada consulta (os resumos são sempre gravados)
	Retention      time.Duration `yaml:"retention"`       // das consultas detalhadas
	StatsRetention time.Duration `yaml:"stats_retention"` // dos resumos por minuto/hora
}

// Security são os valores iniciais das detecções; depois de salvas pelo
// painel, valem as do painel.
type Security struct {
	DGA             bool          `yaml:"dga"`
	Tunnel          bool          `yaml:"tunnel"`
	NRD             bool          `yaml:"nrd"`
	NRDAction       string        `yaml:"nrd_action"` // alert ou block
	NRDMaxAge       time.Duration `yaml:"nrd_max_age"`
	NewDeviceAlerts bool          `yaml:"new_device_alerts"`
	AutoIsolate     []string      `yaml:"auto_isolate"` // threat_blocked, dga, dns_tunnel, nrd
	IgnoreDomains   []string      `yaml:"ignore_domains"`
}

// DHCP é o servidor DHCPv4 opcional. Desligue o DHCP do roteador antes de ligar.
type DHCP struct {
	Enabled    bool          `yaml:"enabled"`
	Interface  string        `yaml:"interface"`   // ex.: eth0
	RangeStart string        `yaml:"range_start"` // ex.: 192.168.1.100
	RangeEnd   string        `yaml:"range_end"`
	Subnet     string        `yaml:"subnet"` // vazio = a da interface
	Router     []string      `yaml:"router"` // vazio = gateway padrão desta máquina
	DNS        []string      `yaml:"dns"`    // vazio = esta máquina
	Domain     string        `yaml:"domain"`
	LeaseTime  time.Duration `yaml:"lease_time"`
}

// AD liga a integração com o Active Directory (Windows; Samba AD compatível).
type AD struct {
	Enabled          bool     `yaml:"enabled"`
	URL              string   `yaml:"url"`                // ldaps://dc01.empresa.local
	BaseDN           string   `yaml:"base_dn"`            // vazio = descoberto
	BindUser         string   `yaml:"bind_user"`          // svc-heimdall@empresa.local
	BindPasswordFile string   `yaml:"bind_password_file"` // a senha fica num arquivo, nunca aqui
	CAFile           string   `yaml:"ca_file"`
	InsecureTLS      bool     `yaml:"insecure_tls"`
	Write            bool     `yaml:"write"` // libera alterações (exige MFA no painel)
	UserOUs          []string `yaml:"user_ous"`
	ManagedGroups    []string `yaml:"managed_groups"`
	DNSZones         []string `yaml:"dns_zones"`
	Login            ADLogin  `yaml:"login"`
}

// ADLogin libera a entrada no painel com as contas do AD; o papel vem do
// primeiro grupo que casar (admin, depois operator, depois viewer).
type ADLogin struct {
	Enabled        bool     `yaml:"enabled"`
	AdminGroups    []string `yaml:"admin_groups"`
	OperatorGroups []string `yaml:"operator_groups"`
	ViewerGroups   []string `yaml:"viewer_groups"`
	RequireMFA     bool     `yaml:"require_mfa"` // padrão true
}

// HA liga a replicação entre nós: um principal e réplicas.
type HA struct {
	Role        string `yaml:"role"`         // "" (nó único), primary ou replica
	SyncToken   string `yaml:"sync_token"`   // segredo compartilhado, o mesmo em todos os nós
	PrimaryURL  string `yaml:"primary_url"`  // réplica: URL da API do principal
	InsecureTLS bool   `yaml:"insecure_tls"` // réplica: aceita certificado autoassinado do principal
}

type Export struct {
	File    string `yaml:"file"`    // JSON por linha, para o agente do Wazuh
	Syslog  string `yaml:"syslog"`  // udp://host:514 ou tcp://host:514
	Queries string `yaml:"queries"` // none, blocked ou all (além dos alertas)
}

type Log struct {
	Level   string `yaml:"level"`   // debug, info, warn, error
	Queries bool   `yaml:"queries"` // registra cada consulta no log
}

// DefaultAllowedNetworks são as redes privadas: o HeimdallDNS não deve ser
// um resolvedor aberto para a internet.
var DefaultAllowedNetworks = []string{
	"127.0.0.0/8", "::1/128",
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"100.64.0.0/10", "169.254.0.0/16",
	"fc00::/7", "fe80::/10",
}

func Default() *Config {
	return &Config{
		DNS: DNS{
			Listen:    []string{":53"},
			BlockMode: BlockNull,
			BlockTTL:  10,
		},
		Upstream: Upstream{
			Servers: []string{
				"https://cloudflare-dns.com/dns-query",
				"tls://dns.quad9.net",
			},
			Bootstrap:      []string{"1.1.1.1:53", "9.9.9.9:53"},
			Mode:           UpstreamFastest,
			Timeout:        3 * time.Second,
			HealthInterval: 30 * time.Second,
		},
		Cache: Cache{
			Size:       20000,
			MaxTTL:     86400,
			ServeStale: time.Hour,
		},
		Filter: Filter{
			Lists: []List{{
				Name: "StevenBlack Unified",
				URL:  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
			}},
			UpdateInterval: 24 * time.Hour,
		},
		Clients: Clients{
			PTRServer:        "auto",
			IsolateMode:      BlockRefused,
			NeighborInterval: time.Minute,
			VendorDBMaxAge:   30 * 24 * time.Hour,
		},
		API: API{Listen: "127.0.0.1:8053"},
		Security: Security{
			DGA: true, Tunnel: true, NRD: true, NRDAction: "alert", NRDMaxAge: 30 * 24 * time.Hour,
			NewDeviceAlerts: true,
		},
		Export: Export{Queries: "none"},
		DHCP:   DHCP{Domain: "lan", LeaseTime: 24 * time.Hour},
		History: History{
			StoreQueries:   true,
			Retention:      7 * 24 * time.Hour,
			StatsRetention: 90 * 24 * time.Hour,
		},
		Backup:  Backup{Interval: 24 * time.Hour, Keep: 7},
		AD:      AD{Login: ADLogin{RequireMFA: true}},
		DataDir: "/var/lib/heimdalldns",
		Log:     Log{Level: "info"},
	}
}

// Load lê o arquivo YAML por cima dos valores padrão.
func Load(path string) (*Config, error) {
	cfg := Default()
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	// Arquivo vazio (io.EOF) mantém os padrões.
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, cfg.Validate()
}

func (c *Config) Validate() error {
	var errs []error
	if l := c.AD.Login; l.Enabled && (!c.AD.Enabled || len(l.AdminGroups)+len(l.OperatorGroups)+len(l.ViewerGroups) == 0) {
		errs = append(errs, errors.New("ad.login: precisa de ad.enabled e de ao menos um grupo (admin_groups, operator_groups ou viewer_groups)"))
	}
	if c.Backup.Interval < 0 || (c.Backup.Interval > 0 && c.Backup.Interval < time.Hour) {
		errs = append(errs, errors.New("backup.interval: use 0 (desligado) ou 1h ou mais"))
	}
	if c.Backup.Keep < 1 {
		c.Backup.Keep = 1
	}
	if len(c.DNS.Listen) == 0 {
		errs = append(errs, errors.New("dns.listen: informe ao menos um endereço"))
	}
	switch c.DNS.BlockMode {
	case BlockNull, BlockNXDomain, BlockRefused, BlockDrop:
	default:
		errs = append(errs, fmt.Errorf("dns.block_mode %q: use null, nxdomain, refused ou drop", c.DNS.BlockMode))
	}
	switch c.Clients.IsolateMode {
	case BlockNull, BlockNXDomain, BlockRefused, BlockDrop:
	default:
		errs = append(errs, fmt.Errorf("clients.isolate_mode %q: use null, nxdomain, refused ou drop", c.Clients.IsolateMode))
	}
	if (c.DNS.TLSCert == "") != (c.DNS.TLSKey == "") {
		errs = append(errs, errors.New("dns.tls_cert e dns.tls_key vão juntos"))
	}
	needCert := len(c.DNS.DoTListen) > 0 || (c.DNS.DoHListen != "" && !c.DNS.DoHPlainHTTP)
	if needCert && c.DNS.TLSCert == "" && !c.DNS.ACME {
		errs = append(errs, errors.New("dns.dot_listen/doh_listen precisam de dns.tls_cert/tls_key ou dns.acme"))
	}
	if c.DNS.ACME && c.DNS.PublicHost == "" {
		errs = append(errs, errors.New("dns.acme precisa de dns.public_host"))
	}
	if c.API.TLSCert != "auto" && (c.API.TLSCert == "") != (c.API.TLSKey == "") {
		errs = append(errs, errors.New("api.tls_cert e api.tls_key vão juntos"))
	}
	if c.DHCP.Enabled {
		if c.DHCP.Interface == "" {
			errs = append(errs, errors.New("dhcp.interface: informe a interface (ex.: eth0)"))
		}
		for _, v := range []string{c.DHCP.RangeStart, c.DHCP.RangeEnd} {
			if a, err := netip.ParseAddr(v); err != nil || !a.Is4() {
				errs = append(errs, fmt.Errorf("dhcp: range_start/range_end precisam ser IPv4 (%q)", v))
			}
		}
	}
	if c.AD.Enabled {
		if c.AD.URL == "" || c.AD.BindUser == "" || c.AD.BindPasswordFile == "" {
			errs = append(errs, errors.New("ad: informe url, bind_user e bind_password_file"))
		}
		if c.AD.Write && len(c.AD.UserOUs)+len(c.AD.ManagedGroups)+len(c.AD.DNSZones) == 0 {
			errs = append(errs, errors.New("ad.write sem user_ous, managed_groups nem dns_zones não libera nada"))
		}
	}
	switch c.HA.Role {
	case "":
	case "primary", "replica":
		if len(c.HA.SyncToken) < 16 {
			errs = append(errs, errors.New("ha.sync_token: use um segredo de pelo menos 16 caracteres (o mesmo nos dois nós)"))
		}
		if c.HA.Role == "replica" && c.HA.PrimaryURL == "" {
			errs = append(errs, errors.New("ha.primary_url: informe a URL da API do principal"))
		}
		if c.API.Listen == "" {
			errs = append(errs, errors.New("ha precisa da API ligada (api.listen)"))
		}
	default:
		errs = append(errs, fmt.Errorf(`ha.role %q: use "primary" ou "replica"`, c.HA.Role))
	}
	if c.History.Retention <= 0 || c.History.StatsRetention <= 0 {
		errs = append(errs, errors.New("history.retention e history.stats_retention devem ser positivos"))
	}
	if _, err := c.AllowedPrefixes(); err != nil {
		errs = append(errs, err)
	}
	if len(c.Upstream.Servers) == 0 {
		errs = append(errs, errors.New("upstream.servers: informe ao menos um servidor"))
	}
	switch c.Upstream.Mode {
	case UpstreamFastest, UpstreamParallel, UpstreamFailover:
	default:
		errs = append(errs, fmt.Errorf("upstream.mode %q: use fastest, parallel ou failover", c.Upstream.Mode))
	}
	if c.Upstream.Timeout <= 0 {
		errs = append(errs, errors.New("upstream.timeout deve ser positivo"))
	}
	if c.Cache.MaxTTL != 0 && c.Cache.MinTTL > c.Cache.MaxTTL {
		errs = append(errs, errors.New("cache.min_ttl maior que cache.max_ttl"))
	}
	if _, err := c.LocalAddrs(); err != nil {
		errs = append(errs, err)
	}
	for i, l := range c.Filter.Lists {
		if l.URL == "" {
			errs = append(errs, fmt.Errorf("filter.lists[%d]: url vazia", i))
		}
		if l.Category != "" && l.Category != "threat" {
			errs = append(errs, fmt.Errorf(`filter.lists[%d]: category %q; use "threat" ou deixe vazio`, i, l.Category))
		}
	}
	return errors.Join(errs...)
}

func (c *Config) AllowedPrefixes() ([]netip.Prefix, error) {
	nets := c.DNS.AllowedNetworks
	if len(nets) == 0 {
		nets = DefaultAllowedNetworks
	}
	out := make([]netip.Prefix, 0, len(nets))
	for _, n := range nets {
		if !strings.Contains(n, "/") {
			a, err := netip.ParseAddr(n)
			if err != nil {
				return nil, fmt.Errorf("dns.allowed_networks: %q inválido", n)
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(n)
		if err != nil {
			return nil, fmt.Errorf("dns.allowed_networks: %q inválido", n)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// LocalAddrs devolve os registros locais com nomes normalizados (FQDN, minúsculo).
func (c *Config) LocalAddrs() (map[string][]netip.Addr, error) {
	out := make(map[string][]netip.Addr, len(c.LocalRecords))
	for name, ips := range c.LocalRecords {
		fq := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), ".")) + "."
		for _, ip := range ips {
			a, err := netip.ParseAddr(strings.TrimSpace(ip))
			if err != nil {
				return nil, fmt.Errorf("local_records[%s]: IP %q inválido", name, ip)
			}
			out[fq] = append(out[fq], a.Unmap())
		}
	}
	return out, nil
}
