package ad

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Tipos de registro (os mesmos números do DNS).
const (
	typeA     = 1
	typeNS    = 2
	typeCNAME = 5
	typeSOA   = 6
	typePTR   = 12
	typeTXT   = 16
	typeAAAA  = 28
	typeSRV   = 33
)

var typeNames = map[uint16]string{typeA: "A", typeNS: "NS", typeCNAME: "CNAME", typeSOA: "SOA", typePTR: "PTR",
	typeTXT: "TXT", typeAAAA: "AAAA", typeSRV: "SRV"}

// Zone é uma zona DNS integrada ao AD.
type Zone struct {
	Name     string `json:"name"`
	DN       string `json:"dn"`
	Location string `json:"location"` // DomainDnsZones, ForestDnsZones ou System (zonas antigas)
	Editable bool   `json:"editable"`
}

// Record é um registro de uma zona.
type Record struct {
	Name   string `json:"name"` // relativo à zona ("@" = a própria zona)
	Type   string `json:"type"`
	TTL    uint32 `json:"ttl"`
	Data   string `json:"data"`
	Static bool   `json:"static"` // sem carimbo de tempo (não some na limpeza automática)
	// Protected: raiz da zona, registros de serviço do AD e nomes dos
	// controladores de domínio; o HeimdallDNS nunca altera esses.
	Protected bool `json:"protected"`
}

// reservedNames são nós que o próprio AD cria em toda zona integrada.
var reservedNames = map[string]bool{"domaindnszones": true, "forestdnszones": true, "gc": true}

// protectedNames devolve os nomes relativos à zona que não podem ser
// alterados: os reservados e os nomes dos controladores de domínio
// (apagar o A de um DC quebra a localização do domínio).
func (c *Client) protectedNames(l *ldap.Conn, z Zone) (map[string]bool, error) {
	out := maps.Clone(reservedNames)
	base, err := c.baseDN(l)
	if err != nil {
		return nil, err
	}
	// 0x2000 = SERVER_TRUST_ACCOUNT (controlador de domínio)
	dcs, err := search(l, base, "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
		[]string{"dNSHostName"}, 0)
	if err != nil {
		return nil, err
	}
	suffix := "." + strings.ToLower(z.Name)
	for _, e := range dcs {
		h := strings.ToLower(e.GetAttributeValue("dNSHostName"))
		if rel, ok := strings.CutSuffix(h, suffix); ok && rel != "" {
			out[rel] = true
		}
	}
	return out, nil
}

func isProtected(name string, prot map[string]bool) bool {
	n := strings.ToLower(name)
	return n == "@" || strings.HasPrefix(n, "_") || strings.Contains(n, "._") || prot[n]
}

// zoneBases são os lugares onde o AD guarda zonas DNS.
func zoneBases(base, forest string) map[string]string {
	return map[string]string{
		"DomainDnsZones": "DC=DomainDnsZones," + base,
		"ForestDnsZones": "DC=ForestDnsZones," + forest,
		"System":         "CN=MicrosoftDNS,CN=System," + base,
	}
}

func (c *Client) zoneEditable(name string) bool {
	if !c.opts.Write {
		return false
	}
	for _, z := range c.opts.DNSZones {
		if strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(z), "."), name) {
			return true
		}
	}
	return false
}

// Zones lista as zonas (sem as internas do AD).
func (c *Client) Zones(ctx context.Context) ([]Zone, error) {
	l, err := c.conn()
	if err != nil {
		return nil, err
	}
	defer l.Close()
	return c.zones(l)
}

func (c *Client) zones(l *ldap.Conn) ([]Zone, error) {
	info, err := c.check(l)
	if err != nil {
		return nil, err
	}
	var out []Zone
	for loc, b := range zoneBases(info.BaseDN, info.ForestDN) {
		es, err := search(l, b, "(objectClass=dnsZone)", []string{"name"}, 1000)
		if err != nil {
			if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
				continue // essa partição não existe neste domínio
			}
			return nil, err
		}
		for _, e := range es {
			n := e.GetAttributeValue("name")
			if n == "RootDNSServers" || strings.HasPrefix(n, "..") {
				continue
			}
			out = append(out, Zone{Name: n, DN: e.DN, Location: loc, Editable: c.zoneEditable(n) && !strings.HasPrefix(n, "_msdcs")})
		}
	}
	slices.SortFunc(out, func(a, b Zone) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

func (c *Client) zone(l *ldap.Conn, name string) (Zone, error) {
	zs, err := c.zones(l)
	if err != nil {
		return Zone{}, err
	}
	for _, z := range zs {
		if strings.EqualFold(z.Name, strings.TrimSuffix(name, ".")) {
			return z, nil
		}
	}
	return Zone{}, fmt.Errorf("zona %q não encontrada no AD", name)
}

// Records lista os registros da zona.
func (c *Client) Records(ctx context.Context, zoneName string) ([]Record, error) {
	l, err := c.conn()
	if err != nil {
		return nil, err
	}
	defer l.Close()
	z, err := c.zone(l, zoneName)
	if err != nil {
		return nil, err
	}
	req := ldap.NewSearchRequest(z.DN, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=dnsNode)", []string{"name", "dnsRecord", "dNSTombstoned"}, nil)
	r, err := l.SearchWithPaging(req, 500)
	if err != nil {
		return nil, err
	}
	prot, err := c.protectedNames(l, z)
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, e := range r.Entries {
		if strings.EqualFold(e.GetAttributeValue("dNSTombstoned"), "TRUE") {
			continue
		}
		name := e.GetAttributeValue("name")
		for _, raw := range e.GetRawAttributeValues("dnsRecord") {
			if rec, ok := decodeRecord(raw); ok {
				rec.Name = name
				rec.Protected = !z.Editable || isProtected(name, prot)
				out = append(out, rec)
			}
		}
	}
	slices.SortFunc(out, func(a, b Record) int {
		if d := strings.Compare(a.Name, b.Name); d != 0 {
			return d
		}
		return strings.Compare(a.Type, b.Type)
	})
	return out, nil
}

// --- formato binário dos registros (MS-DNSP 2.3.2.2, DNS_RPC_RECORD) ---

const recordHeader = 24

func encodeRecord(typ uint16, data []byte, ttl, serial uint32) []byte {
	b := make([]byte, recordHeader+len(data))
	binary.LittleEndian.PutUint16(b[0:], uint16(len(data)))
	binary.LittleEndian.PutUint16(b[2:], typ)
	b[4] = 5    // versão
	b[5] = 0xF0 // rank: dado da zona
	binary.LittleEndian.PutUint32(b[8:], serial)
	binary.BigEndian.PutUint32(b[12:], ttl) // o TTL vai em ordem de rede
	// b[16:20] reservado, b[20:24] carimbo de tempo = 0 (registro estático)
	copy(b[recordHeader:], data)
	return b
}

// encodeName monta o DNS_COUNT_NAME: tamanho, quantidade de rótulos e os
// rótulos com prefixo de tamanho, terminados em zero.
func encodeName(fqdn string) ([]byte, error) {
	labels := strings.Split(strings.TrimSuffix(fqdn, "."), ".")
	raw := []byte{}
	for _, lb := range labels {
		if lb == "" || len(lb) > 63 {
			return nil, fmt.Errorf("nome inválido: %q", fqdn)
		}
		raw = append(raw, byte(len(lb)))
		raw = append(raw, lb...)
	}
	raw = append(raw, 0)
	if len(raw) > 255 {
		return nil, fmt.Errorf("nome longo demais: %q", fqdn)
	}
	return append([]byte{byte(len(raw)), byte(len(labels))}, raw...), nil
}

func decodeName(d []byte) (string, bool) {
	if len(d) < 2 || int(d[0])+2 > len(d) {
		return "", false
	}
	raw := d[2 : 2+int(d[0])]
	var parts []string
	for i := 0; i < len(raw) && raw[i] != 0; {
		n := int(raw[i])
		if i+1+n > len(raw) {
			return "", false
		}
		parts = append(parts, string(raw[i+1:i+1+n]))
		i += 1 + n
	}
	return strings.Join(parts, ".") + ".", true
}

func decodeRecord(b []byte) (Record, bool) {
	if len(b) < recordHeader {
		return Record{}, false
	}
	n := int(binary.LittleEndian.Uint16(b[0:]))
	typ := binary.LittleEndian.Uint16(b[2:])
	if len(b) < recordHeader+n {
		return Record{}, false
	}
	d := b[recordHeader : recordHeader+n]
	rec := Record{Type: typeNames[typ], TTL: binary.BigEndian.Uint32(b[12:]), Static: binary.LittleEndian.Uint32(b[20:]) == 0}
	if rec.Type == "" {
		rec.Type = fmt.Sprintf("TYPE%d", typ)
	}
	switch typ {
	case typeA:
		if a, ok := netip.AddrFromSlice(d); ok && len(d) == 4 {
			rec.Data = a.String()
		}
	case typeAAAA:
		if a, ok := netip.AddrFromSlice(d); ok && len(d) == 16 {
			rec.Data = a.String()
		}
	case typeCNAME, typePTR, typeNS:
		rec.Data, _ = decodeName(d)
	case typeSRV:
		if len(d) > 6 {
			name, _ := decodeName(d[6:])
			rec.Data = fmt.Sprintf("%d %d %d %s", binary.BigEndian.Uint16(d[0:]), binary.BigEndian.Uint16(d[2:]),
				binary.BigEndian.Uint16(d[4:]), name)
		}
	case typeSOA:
		rec.Data = "(SOA)"
	default:
		rec.Data = fmt.Sprintf("%x", d)
	}
	return rec, true
}

// --- alterações ---

// RecordChange é o pedido de criar ou apagar um registro.
type RecordChange struct {
	Zone  string `json:"zone"`
	Name  string `json:"name"` // relativo à zona
	Type  string `json:"type"` // A, AAAA, CNAME ou PTR
	Data  string `json:"data"`
	TTL   uint32 `json:"ttl"`
	Write bool   `json:"-"`
}

func validRelName(n string) error {
	if n == "" || n == "@" {
		return errors.New("informe o nome do registro (a raiz da zona não é alterada por aqui)")
	}
	for _, lb := range strings.Split(n, ".") {
		if lb == "" || len(lb) > 63 {
			return fmt.Errorf("nome inválido: %q", n)
		}
		if strings.HasPrefix(lb, "_") {
			return errors.New("registros de serviço do AD (_ldap, _kerberos…) não são alterados por aqui")
		}
		for _, r := range strings.ToLower(lb) {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return fmt.Errorf("nome inválido: %q", n)
			}
		}
	}
	return nil
}

func recordData(typ, data string) (uint16, []byte, error) {
	switch strings.ToUpper(typ) {
	case "A", "AAAA":
		a, err := netip.ParseAddr(strings.TrimSpace(data))
		if err != nil {
			return 0, nil, fmt.Errorf("IP inválido: %q", data)
		}
		if strings.EqualFold(typ, "A") {
			if !a.Is4() {
				return 0, nil, errors.New("registro A precisa de IPv4")
			}
			b := a.As4()
			return typeA, b[:], nil
		}
		if !a.Is6() || a.Is4In6() {
			return 0, nil, errors.New("registro AAAA precisa de IPv6")
		}
		b := a.As16()
		return typeAAAA, b[:], nil
	case "CNAME", "PTR":
		name, err := encodeName(strings.ToLower(strings.TrimSpace(data)))
		if err != nil {
			return 0, nil, err
		}
		if strings.EqualFold(typ, "CNAME") {
			return typeCNAME, name, nil
		}
		return typePTR, name, nil
	}
	return 0, nil, errors.New("tipos permitidos: A, AAAA, CNAME e PTR")
}

func (c *Client) nodeForChange(l *ldap.Conn, rc RecordChange) (Zone, string, error) {
	if err := c.mustWrite(); err != nil {
		return Zone{}, "", err
	}
	z, err := c.zone(l, rc.Zone)
	if err != nil {
		return z, "", err
	}
	if !z.Editable {
		return z, "", fmt.Errorf("a zona %s não está liberada (ad.dns_zones)", z.Name)
	}
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rc.Name), "."+z.Name))
	if err := validRelName(name); err != nil {
		return z, "", err
	}
	prot, err := c.protectedNames(l, z)
	if err != nil {
		return z, "", err
	}
	if isProtected(name, prot) {
		return z, "", fmt.Errorf("%s.%s é um registro de infraestrutura do AD e não é alterado por aqui", name, z.Name)
	}
	return z, name, nil
}

// AddRecord cria o registro (e o nó, se for o primeiro registro do nome).
func (c *Client) AddRecord(ctx context.Context, rc RecordChange) error {
	l, err := c.conn()
	if err != nil {
		return err
	}
	defer l.Close()
	z, name, err := c.nodeForChange(l, rc)
	if err != nil {
		return err
	}
	typ, data, err := recordData(rc.Type, rc.Data)
	if err != nil {
		return err
	}
	if rc.TTL == 0 {
		rc.TTL = 3600
	}
	val := string(encodeRecord(typ, data, rc.TTL, 1))
	dn := fmt.Sprintf("DC=%s,%s", ldap.EscapeDN(name), z.DN)
	r, err := l.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=dnsNode)", []string{"dnsRecord", "dNSTombstoned"}, nil))
	switch {
	case ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject):
		add := ldap.NewAddRequest(dn, nil)
		add.Attribute("objectClass", []string{"top", "dnsNode"})
		add.Attribute("dnsRecord", []string{val})
		return l.Add(add)
	case err != nil:
		return err
	}
	e := r.Entries[0]
	tomb := strings.EqualFold(e.GetAttributeValue("dNSTombstoned"), "TRUE")
	for _, raw := range e.GetRawAttributeValues("dnsRecord") {
		old, ok := decodeRecord(raw)
		if !ok || tomb {
			continue
		}
		if typ == typeCNAME && old.Type != "CNAME" || typ != typeCNAME && old.Type == "CNAME" {
			return fmt.Errorf("%s já tem registro %s: CNAME não convive com outros tipos", name, old.Type)
		}
		if newRec, _ := decodeRecord([]byte(val)); old.Type == newRec.Type && strings.EqualFold(old.Data, newRec.Data) {
			return fmt.Errorf("o registro %s %s %s já existe", name, old.Type, old.Data)
		}
	}
	mod := ldap.NewModifyRequest(dn, nil)
	if tomb { // nó apagado (tombstone): reaproveita
		mod.Replace("dnsRecord", []string{val})
		mod.Replace("dNSTombstoned", []string{"FALSE"})
	} else {
		mod.Add("dnsRecord", []string{val})
	}
	return l.Modify(mod)
}

// DeleteRecord apaga um valor; se for o último do nome, apaga o nó.
func (c *Client) DeleteRecord(ctx context.Context, rc RecordChange) error {
	l, err := c.conn()
	if err != nil {
		return err
	}
	defer l.Close()
	z, name, err := c.nodeForChange(l, rc)
	if err != nil {
		return err
	}
	dn := fmt.Sprintf("DC=%s,%s", ldap.EscapeDN(name), z.DN)
	r, err := l.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=dnsNode)", []string{"dnsRecord"}, nil))
	if err != nil {
		return fmt.Errorf("registro %s não encontrado: %w", name, err)
	}
	raws := r.Entries[0].GetRawAttributeValues("dnsRecord")
	var match []byte
	for _, raw := range raws {
		old, ok := decodeRecord(raw)
		want := strings.ToLower(strings.TrimSpace(rc.Data))
		if (old.Type == "CNAME" || old.Type == "PTR") && !strings.HasSuffix(want, ".") {
			want += "."
		}
		if ok && strings.EqualFold(old.Type, rc.Type) && strings.EqualFold(old.Data, want) {
			match = raw
		}
	}
	if match == nil {
		return fmt.Errorf("não há registro %s %s %s", name, rc.Type, rc.Data)
	}
	if len(raws) == 1 {
		return l.Del(ldap.NewDelRequest(dn, nil))
	}
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Delete("dnsRecord", []string{string(match)})
	return l.Modify(mod)
}
