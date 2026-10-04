// Package ad integra o HeimdallDNS ao Active Directory por LDAPS: consulta
// usuários, grupos e computadores e, se liberado, cria e altera usuários,
// grupos e registros DNS integrados ao AD.
//
// O alvo principal é o AD do Windows; o Samba AD é compatível. Só usa o que
// os dois falam igual: LDAP com TLS, unicodePwd para senha e os objetos
// dnsNode (MS-DNSP) para o DNS.
//
// Segurança: a conta de serviço deve ter só a delegação necessária (as OUs e
// grupos liberados), nunca Domain Admins. Mesmo assim, o código recusa mexer
// em contas e grupos privilegiados.
package ad

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type Options struct {
	URL          string // ldaps://dc01.empresa.local ou ldap://… (com StartTLS obrigatório)
	BaseDN       string // vazio = defaultNamingContext do rootDSE
	BindUser     string // UPN (svc@empresa.local) ou DN da conta de serviço
	BindPassword string
	CAFile       string // CA que assinou o certificado do DC; vazio = CAs do sistema
	InsecureTLS  bool   // só laboratório
	Timeout      time.Duration

	Write         bool     // libera criação e alteração
	UserOUs       []string // OUs (DN) onde usuários podem ser criados e alterados
	ManagedGroups []string // grupos (nome ou DN) que podem ganhar e perder membros
	DNSZones      []string // zonas DNS do AD que podem ser alteradas
	Logger        *slog.Logger
}

// Grupos que nunca são alterados nem têm membros alterados por aqui.
var privilegedGroups = []string{
	"domain admins", "enterprise admins", "schema admins", "administrators", "account operators",
	"backup operators", "server operators", "print operators", "group policy creator owners",
	"dnsadmins", "cert publishers", "enterprise key admins", "key admins", "domain controllers",
	"read-only domain controllers", "enterprise read-only domain controllers", "protected users",
	"replicator", "incoming forest trust builders", "domain computers",
}

type Client struct {
	opts Options
	tls  *tls.Config
	log  *slog.Logger

	mu     sync.Mutex
	base   string
	forest string
	info   *Info
}

func New(o Options) (*Client, error) {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	u, err := url.Parse(o.URL)
	if err != nil || (u.Scheme != "ldaps" && u.Scheme != "ldap") || u.Hostname() == "" {
		return nil, errors.New("ad.url: use ldaps://servidor (ou ldap://servidor, que exige StartTLS)")
	}
	if o.BindUser == "" || o.BindPassword == "" {
		return nil, errors.New("ad: informe bind_user e a senha (bind_password_file)")
	}
	cfg := &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12, InsecureSkipVerify: o.InsecureTLS}
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ad.ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ad.ca_file: nenhum certificado PEM válido")
		}
		cfg.RootCAs = pool
	}
	return &Client{opts: o, tls: cfg, log: o.Logger, base: o.BaseDN}, nil
}

// Policy é o que a configuração libera para alteração.
type Policy struct {
	UserOUs       []string `json:"user_ous"`
	ManagedGroups []string `json:"managed_groups"`
	DNSZones      []string `json:"dns_zones"`
}

func (c *Client) Policy() Policy {
	nz := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		return slices.Clone(s)
	}
	return Policy{UserOUs: nz(c.opts.UserOUs), ManagedGroups: nz(c.opts.ManagedGroups), DNSZones: nz(c.opts.DNSZones)}
}

// conn abre uma conexão autenticada e sempre criptografada.
func (c *Client) conn() (*ldap.Conn, error) {
	l, err := ldap.DialURL(c.opts.URL, ldap.DialWithTLSConfig(c.tls))
	if err != nil {
		return nil, fmt.Errorf("conectando ao AD: %w", err)
	}
	l.SetTimeout(c.opts.Timeout)
	if strings.HasPrefix(c.opts.URL, "ldap://") {
		if err := l.StartTLS(c.tls); err != nil {
			l.Close()
			return nil, fmt.Errorf("StartTLS (o HeimdallDNS não usa LDAP sem criptografia): %w", err)
		}
	}
	if err := l.Bind(c.opts.BindUser, c.opts.BindPassword); err != nil {
		l.Close()
		return nil, fmt.Errorf("autenticando no AD: %w", err)
	}
	return l, nil
}

// Info resume o domínio (rootDSE).
type Info struct {
	BaseDN       string `json:"base_dn"`
	ForestDN     string `json:"forest_dn"`
	DNSHostName  string `json:"dns_host_name"`
	Domain       string `json:"domain"`
	Vendor       string `json:"vendor"` // "Microsoft" ou "Samba"
	FunctionalLv int    `json:"functional_level"`
	Write        bool   `json:"write"`
}

func dnToDomain(dn string) string {
	var parts []string
	for _, rdn := range strings.Split(dn, ",") {
		if k, v, ok := strings.Cut(strings.TrimSpace(rdn), "="); ok && strings.EqualFold(k, "dc") {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, ".")
}

// Check lê o rootDSE (e descobre a base, se não configurada).
func (c *Client) Check(ctx context.Context) (Info, error) {
	l, err := c.conn()
	if err != nil {
		return Info{}, err
	}
	defer l.Close()
	return c.check(l)
}

func (c *Client) check(l *ldap.Conn) (Info, error) {
	c.mu.Lock()
	if c.info != nil {
		i := *c.info
		c.mu.Unlock()
		return i, nil
	}
	c.mu.Unlock()
	r, err := l.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", []string{"defaultNamingContext", "rootDomainNamingContext", "dnsHostName",
			"domainFunctionality", "vendorName"}, nil))
	if err != nil || len(r.Entries) == 0 {
		return Info{}, fmt.Errorf("lendo o rootDSE: %w", err)
	}
	e := r.Entries[0]
	base := c.opts.BaseDN
	if base == "" {
		base = e.GetAttributeValue("defaultNamingContext")
	}
	fl, _ := strconv.Atoi(e.GetAttributeValue("domainFunctionality"))
	vendor := "Microsoft"
	if v := e.GetAttributeValue("vendorName"); strings.Contains(strings.ToLower(v), "samba") {
		vendor = "Samba"
	}
	i := Info{BaseDN: base, ForestDN: e.GetAttributeValue("rootDomainNamingContext"), DNSHostName: e.GetAttributeValue("dnsHostName"),
		Domain: dnToDomain(base), Vendor: vendor, FunctionalLv: fl, Write: c.opts.Write}
	c.mu.Lock()
	c.info, c.base, c.forest = &i, i.BaseDN, i.ForestDN
	c.mu.Unlock()
	return i, nil
}

func (c *Client) baseDN(l *ldap.Conn) (string, error) {
	i, err := c.check(l)
	return i.BaseDN, err
}

// search faz busca paginada (o AD limita 1000 por página).
func search(l *ldap.Conn, base, filter string, attrs []string, limit int) ([]*ldap.Entry, error) {
	req := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, limit, 0, false, filter, attrs, nil)
	r, err := l.SearchWithPaging(req, 500)
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return nil, err
	}
	if r == nil {
		return nil, nil
	}
	return r.Entries, nil
}

// --- usuários ---

type User struct {
	DN          string    `json:"dn"`
	SAM         string    `json:"sam"`
	UPN         string    `json:"upn,omitempty"`
	DisplayName string    `json:"display_name,omitempty"`
	GivenName   string    `json:"given_name,omitempty"`
	Surname     string    `json:"surname,omitempty"`
	Mail        string    `json:"mail,omitempty"`
	Title       string    `json:"title,omitempty"`
	Department  string    `json:"department,omitempty"`
	Description string    `json:"description,omitempty"`
	Enabled     bool      `json:"enabled"`
	Locked      bool      `json:"locked"`
	Privileged  bool      `json:"privileged"`
	Manageable  bool      `json:"manageable"` // pode ser alterado por aqui
	LastLogon   time.Time `json:"last_logon,omitzero"`
	PwdLastSet  time.Time `json:"pwd_last_set,omitzero"`
	Created     time.Time `json:"created,omitzero"`
	Groups      []string  `json:"groups"`
}

var userAttrs = []string{"distinguishedName", "sAMAccountName", "userPrincipalName", "displayName", "givenName", "sn",
	"mail", "title", "department", "description", "userAccountControl", "lockoutTime", "lastLogonTimestamp",
	"pwdLastSet", "whenCreated", "memberOf", "adminCount"}

const (
	uacDisabled      = 0x2
	uacNormalAccount = 0x200
)

// fileTime converte o FILETIME do AD (100 ns desde 1601).
func fileTime(s string) time.Time {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v <= 0 || v == 0x7FFFFFFFFFFFFFFF {
		return time.Time{}
	}
	return time.Unix(0, (v-116444736000000000)*100)
}

func genTime(s string) time.Time {
	t, err := time.Parse("20060102150405.0Z", s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func cnOf(dn string) string {
	first, _, _ := strings.Cut(dn, ",")
	_, v, ok := strings.Cut(first, "=")
	if !ok {
		return dn
	}
	return v
}

func isPrivilegedGroup(name string) bool {
	return slices.Contains(privilegedGroups, strings.ToLower(name))
}

func (c *Client) toUser(e *ldap.Entry) User {
	uac, _ := strconv.Atoi(e.GetAttributeValue("userAccountControl"))
	lock, _ := strconv.ParseInt(e.GetAttributeValue("lockoutTime"), 10, 64)
	u := User{
		DN: e.DN, SAM: e.GetAttributeValue("sAMAccountName"), UPN: e.GetAttributeValue("userPrincipalName"),
		DisplayName: e.GetAttributeValue("displayName"), GivenName: e.GetAttributeValue("givenName"),
		Surname: e.GetAttributeValue("sn"), Mail: e.GetAttributeValue("mail"), Title: e.GetAttributeValue("title"),
		Department: e.GetAttributeValue("department"), Description: e.GetAttributeValue("description"),
		Enabled: uac&uacDisabled == 0, Locked: lock > 0,
		Privileged: e.GetAttributeValue("adminCount") == "1",
		LastLogon:  fileTime(e.GetAttributeValue("lastLogonTimestamp")),
		PwdLastSet: fileTime(e.GetAttributeValue("pwdLastSet")),
		Created:    genTime(e.GetAttributeValue("whenCreated")),
		Groups:     []string{},
	}
	for _, g := range e.GetAttributeValues("memberOf") {
		name := cnOf(g)
		u.Groups = append(u.Groups, name)
		if isPrivilegedGroup(name) {
			u.Privileged = true
		}
	}
	slices.Sort(u.Groups)
	u.Manageable = c.opts.Write && !u.Privileged && c.inUserOUs(u.DN)
	return u
}

// inUserOUs diz se o DN está dentro de uma das OUs liberadas.
func (c *Client) inUserOUs(dn string) bool {
	d := strings.ToLower(strings.ReplaceAll(dn, ", ", ","))
	for _, ou := range c.opts.UserOUs {
		o := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(ou), ", ", ","))
		if o != "" && (d == o || strings.HasSuffix(d, ","+o)) {
			return true
		}
	}
	return false
}

// Users busca por login, nome, e-mail ou UPN.
func (c *Client) Users(ctx context.Context, q string, limit int) ([]User, error) {
	l, err := c.conn()
	if err != nil {
		return nil, err
	}
	defer l.Close()
	base, err := c.baseDN(l)
	if err != nil {
		return nil, err
	}
	f := "(&(objectCategory=person)(objectClass=user))"
	if q = strings.TrimSpace(q); q != "" {
		e := ldap.EscapeFilter(q)
		f = fmt.Sprintf("(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=*%s*)(displayName=*%s*)(mail=*%s*)(userPrincipalName=*%s*)))", e, e, e, e)
	}
	es, err := search(l, base, f, userAttrs, max(1, min(limit, 1000)))
	if err != nil {
		return nil, err
	}
	out := make([]User, 0, len(es))
	for _, e := range es {
		out = append(out, c.toUser(e))
	}
	slices.SortFunc(out, func(a, b User) int { return strings.Compare(strings.ToLower(a.SAM), strings.ToLower(b.SAM)) })
	return out, nil
}

func (c *Client) findUser(l *ldap.Conn, sam string) (User, error) {
	base, err := c.baseDN(l)
	if err != nil {
		return User{}, err
	}
	es, err := search(l, base, fmt.Sprintf("(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s))", ldap.EscapeFilter(sam)), userAttrs, 2)
	if err != nil {
		return User{}, err
	}
	if len(es) != 1 {
		return User{}, fmt.Errorf("usuário %q não encontrado", sam)
	}
	return c.toUser(es[0]), nil
}

func (c *Client) User(ctx context.Context, sam string) (User, error) {
	l, err := c.conn()
	if err != nil {
		return User{}, err
	}
	defer l.Close()
	return c.findUser(l, sam)
}

// --- grupos ---

type Group struct {
	DN          string `json:"dn"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Members     int    `json:"members"`
	Privileged  bool   `json:"privileged"`
	Managed     bool   `json:"managed"` // pode ganhar e perder membros por aqui
}

func (c *Client) toGroup(e *ldap.Entry) Group {
	g := Group{DN: e.DN, Name: e.GetAttributeValue("cn"), Description: e.GetAttributeValue("description"),
		Members: len(e.GetAttributeValues("member"))}
	g.Privileged = isPrivilegedGroup(g.Name) || e.GetAttributeValue("adminCount") == "1"
	g.Managed = c.opts.Write && !g.Privileged && c.groupAllowed(g)
	return g
}

func (c *Client) groupAllowed(g Group) bool {
	for _, m := range c.opts.ManagedGroups {
		m = strings.TrimSpace(m)
		if strings.EqualFold(m, g.Name) || strings.EqualFold(strings.ReplaceAll(m, ", ", ","), strings.ReplaceAll(g.DN, ", ", ",")) {
			return true
		}
	}
	return false
}

func (c *Client) Groups(ctx context.Context, q string, limit int) ([]Group, error) {
	l, err := c.conn()
	if err != nil {
		return nil, err
	}
	defer l.Close()
	base, err := c.baseDN(l)
	if err != nil {
		return nil, err
	}
	f := "(objectClass=group)"
	if q = strings.TrimSpace(q); q != "" {
		f = fmt.Sprintf("(&(objectClass=group)(|(cn=*%s*)(description=*%s*)))", ldap.EscapeFilter(q), ldap.EscapeFilter(q))
	}
	es, err := search(l, base, f, []string{"cn", "description", "member", "adminCount"}, max(1, min(limit, 1000)))
	if err != nil {
		return nil, err
	}
	out := make([]Group, 0, len(es))
	for _, e := range es {
		out = append(out, c.toGroup(e))
	}
	slices.SortFunc(out, func(a, b Group) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	return out, nil
}

func (c *Client) findGroup(l *ldap.Conn, name string) (Group, []string, error) {
	base, err := c.baseDN(l)
	if err != nil {
		return Group{}, nil, err
	}
	f := fmt.Sprintf("(&(objectClass=group)(cn=%s))", ldap.EscapeFilter(name))
	if strings.Contains(name, "=") {
		f = fmt.Sprintf("(&(objectClass=group)(distinguishedName=%s))", ldap.EscapeFilter(name))
	}
	es, err := search(l, base, f, []string{"cn", "description", "member", "adminCount"}, 2)
	if err != nil {
		return Group{}, nil, err
	}
	if len(es) != 1 {
		return Group{}, nil, fmt.Errorf("grupo %q não encontrado", name)
	}
	return c.toGroup(es[0]), es[0].GetAttributeValues("member"), nil
}

// GroupMembers devolve o grupo e os nomes dos membros.
func (c *Client) GroupMembers(ctx context.Context, name string) (Group, []string, error) {
	l, err := c.conn()
	if err != nil {
		return Group{}, nil, err
	}
	defer l.Close()
	g, members, err := c.findGroup(l, name)
	if err != nil {
		return g, nil, err
	}
	names := make([]string, len(members))
	for i, m := range members {
		names[i] = cnOf(m)
	}
	slices.Sort(names)
	return g, names, nil
}

// --- computadores ---

type Computer struct {
	DN          string    `json:"dn"`
	Name        string    `json:"name"`
	DNSHostName string    `json:"dns_host_name,omitempty"`
	OS          string    `json:"os,omitempty"`
	OSVersion   string    `json:"os_version,omitempty"`
	Description string    `json:"description,omitempty"`
	Enabled     bool      `json:"enabled"`
	LastLogon   time.Time `json:"last_logon,omitzero"`
	OU          string    `json:"ou"`
}

// ComputerByHost acha o computador do AD pelo nome do aparelho (PTR ou DHCP).
func (c *Client) ComputerByHost(ctx context.Context, host string) (*Computer, error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return nil, nil
	}
	short, _, _ := strings.Cut(host, ".")
	l, err := c.conn()
	if err != nil {
		return nil, err
	}
	defer l.Close()
	base, err := c.baseDN(l)
	if err != nil {
		return nil, err
	}
	f := fmt.Sprintf("(&(objectClass=computer)(|(dNSHostName=%s)(cn=%s)))", ldap.EscapeFilter(host), ldap.EscapeFilter(short))
	es, err := search(l, base, f, []string{"cn", "dNSHostName", "operatingSystem", "operatingSystemVersion",
		"description", "userAccountControl", "lastLogonTimestamp"}, 2)
	if err != nil || len(es) == 0 {
		return nil, err
	}
	e := es[0]
	uac, _ := strconv.Atoi(e.GetAttributeValue("userAccountControl"))
	_, ou, _ := strings.Cut(e.DN, ",")
	return &Computer{DN: e.DN, Name: e.GetAttributeValue("cn"), DNSHostName: e.GetAttributeValue("dNSHostName"),
		OS: e.GetAttributeValue("operatingSystem"), OSVersion: e.GetAttributeValue("operatingSystemVersion"),
		Description: e.GetAttributeValue("description"), Enabled: uac&uacDisabled == 0,
		LastLogon: fileTime(e.GetAttributeValue("lastLogonTimestamp")), OU: ou}, nil
}
