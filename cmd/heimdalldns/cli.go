package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/ugoneiva/HeimdallDNS/internal/clients"
	"github.com/ugoneiva/HeimdallDNS/internal/filter"
)

var commands = map[string]bool{
	"status": true, "clients": true, "client": true, "name": true, "isolate": true,
	"release": true, "rules": true, "forget": true, "services": true, "passwd": true, "mfa-off": true,
}

func isCommand(s string) bool { return commands[s] }

type cli struct {
	base  string
	token string
	http  *http.Client
}

func runCLI(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfig, "arquivo de configuração YAML")
	apiURL := fs.String("api", "", "URL da API (padrão: api.listen da configuração)")
	token := fs.String("token", "", "token da API (padrão: api.token ou <data_dir>/api.token)")
	mode := fs.String("mode", "", "isolate: null, nxdomain, refused ou drop")
	reason := fs.String("reason", "", "isolate: motivo")
	except := fs.String("except", "", "isolate: domínios liberados, separados por vírgula")
	deny := fs.String("deny", "", "rules: regras de bloqueio do dispositivo (\"\" limpa)")
	allow := fs.String("allow", "", "rules: exceções do dispositivo (\"\" limpa)")
	global := fs.Bool("global", true, "rules: aplica também as listas globais")
	jsonOut := fs.Bool("json", false, "saída em JSON")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}

	c, err := newCLI(*cfgPath, flagSet(fs, "config"), *apiURL, *token)
	if err != nil {
		return err
	}
	need := func(n int, uso string) error {
		if len(pos) < n {
			return fmt.Errorf("uso: heimdalldns %s %s", cmd, uso)
		}
		return nil
	}
	ref := func() string { return url.PathEscape(pos[0]) }

	switch cmd {
	case "status":
		var st map[string]any
		if err := c.do("GET", "/api/status", nil, &st); err != nil {
			return err
		}
		return printJSON(st)
	case "clients":
		var list []clients.View
		if err := c.do("GET", "/api/clients", nil, &list); err != nil {
			return err
		}
		if *jsonOut {
			return printJSON(list)
		}
		printClients(list)
		return nil
	case "client":
		if err := need(1, "<ref>"); err != nil {
			return err
		}
		return c.show("GET", "/api/clients/"+ref(), nil)
	case "name":
		if err := need(2, "<ref> <nome>"); err != nil {
			return err
		}
		return c.show("PATCH", "/api/clients/"+ref(), map[string]any{"name": strings.Join(pos[1:], " ")})
	case "isolate":
		if err := need(1, "<ref> [-mode m] [-reason texto] [-except dom1,dom2]"); err != nil {
			return err
		}
		return c.show("POST", "/api/clients/"+ref()+"/isolate", map[string]any{
			"mode": *mode, "reason": *reason, "exceptions": splitList(*except),
		})
	case "release":
		if err := need(1, "<ref>"); err != nil {
			return err
		}
		return c.show("POST", "/api/clients/"+ref()+"/release", nil)
	case "rules":
		if err := need(1, "<ref> [-deny r1,r2] [-allow r1,r2] [-global=false]"); err != nil {
			return err
		}
		body := map[string]any{}
		if flagSet(fs, "deny") {
			body["deny"] = splitList(*deny)
		}
		if flagSet(fs, "allow") {
			body["allow"] = splitList(*allow)
		}
		if flagSet(fs, "global") {
			body["skip_global_lists"] = !*global
		}
		return c.show("PATCH", "/api/clients/"+ref(), body)
	case "forget":
		if err := need(1, "<ref>"); err != nil {
			return err
		}
		if err := c.do("DELETE", "/api/clients/"+ref(), nil, nil); err != nil {
			return err
		}
		fmt.Println("dispositivo esquecido")
		return nil
	case "passwd":
		pw, err := readNewPassword()
		if err != nil {
			return err
		}
		if err := c.do("POST", "/api/auth/password", map[string]string{"password": pw}, nil); err != nil {
			return err
		}
		fmt.Println("senha do painel alterada; as sessões abertas foram encerradas")
		return nil
	case "mfa-off":
		if err := c.do("POST", "/api/auth/mfa/disable", map[string]string{}, nil); err != nil {
			return err
		}
		fmt.Println("verificação em duas etapas desligada; ligue de novo pelo painel")
		return nil
	case "services":
		var out struct {
			Services []filter.Service `json:"services"`
		}
		if err := c.do("GET", "/api/services", nil, &out); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "REGRA\tSERVIÇO\tGRUPO")
		for _, s := range out.Services {
			fmt.Fprintf(tw, "service:%s\t%s\tservice:%s\n", s.ID, s.Name, s.Group)
		}
		return tw.Flush()
	}
	return fmt.Errorf("comando desconhecido: %s", cmd)
}

// parseInterspersed aceita opções antes ou depois dos argumentos posicionais.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func newCLI(cfgPath string, explicit bool, apiURL, token string) (*cli, error) {
	cfg, _, err := loadConfig(cfgPath, explicit)
	if err != nil {
		return nil, err
	}
	if apiURL == "" {
		if cfg.API.Listen == "" {
			return nil, errors.New("a API está desligada (api.listen vazio)")
		}
		host := cfg.API.Listen
		if strings.HasPrefix(host, ":") || strings.HasPrefix(host, "0.0.0.0:") {
			host = "127.0.0.1:" + host[strings.LastIndexByte(host, ':')+1:]
		}
		apiURL = "http://" + host
		if cfg.API.TLSCert != "" {
			apiURL = "https://" + host
		}
	}
	if token == "" {
		token = cfg.API.Token
	}
	if token == "" {
		b, err := os.ReadFile(filepath.Join(cfg.DataDir, "api.token"))
		if err != nil {
			return nil, fmt.Errorf("lendo o token da API (rode com sudo ou use -token): %w", err)
		}
		token = strings.TrimSpace(string(b))
	}
	hc := &http.Client{Timeout: 10 * time.Second}
	// No próprio servidor, aceita o certificado autoassinado (o nome dele
	// raramente é 127.0.0.1); fora do loopback, valida normalmente.
	if u, err := url.Parse(apiURL); err == nil && u.Scheme == "https" {
		if ip, err := netip.ParseAddr(u.Hostname()); (err == nil && ip.IsLoopback()) || u.Hostname() == "localhost" {
			hc.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		}
	}
	return &cli{base: strings.TrimSuffix(apiURL, "/"), token: token, http: hc}, nil
}

func (c *cli) do(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("servidor fora do ar? %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return errors.New(e.Error)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// show executa e imprime o dispositivo resultante.
func (c *cli) show(method, path string, body any) error {
	var v clients.View
	if err := c.do(method, path, body, &v); err != nil {
		return err
	}
	printClient(v)
	return nil
}

func printClients(list []clients.View) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNOME\tIP\tMAC\tFABRICANTE\tCONSULTAS\tBLOQ.\tVISTO\tESTADO")
	for _, v := range list {
		ip := ""
		if len(v.IPs) > 0 {
			ip = v.IPs[0].String()
			if len(v.IPs) > 1 {
				ip += fmt.Sprintf(" (+%d)", len(v.IPs)-1)
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\n", v.ID, v.Display, ip, dash(v.MAC),
			dash(truncate(v.Vendor, 28)), v.Queries, v.Blocked, ago(v.LastSeen), state(v))
	}
	tw.Flush()
}

func printClient(v clients.View) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	ips := make([]string, len(v.IPs))
	for i, ip := range v.IPs {
		ips[i] = ip.String()
	}
	s := v.Settings
	rows := [][2]string{
		{"ID", v.ID}, {"Nome", v.Display}, {"Nome reverso", dash(v.Hostname)},
		{"IPs", strings.Join(ips, ", ")}, {"MAC", dash(v.MAC)}, {"Fabricante", dash(v.Vendor)},
		{"Primeira vez", v.FirstSeen.Format("02/01/2006 15:04:05")},
		{"Última vez", v.LastSeen.Format("02/01/2006 15:04:05") + " (" + ago(v.LastSeen) + ")"},
		{"Consultas", fmt.Sprint(v.Queries)}, {"Bloqueadas", fmt.Sprint(v.Blocked)},
		{"Estado", state(v)},
	}
	if s.Isolated {
		rows = append(rows, [2]string{"Isolado desde", s.IsolatedAt.Format("02/01/2006 15:04:05")})
		if s.IsolateReason != "" {
			rows = append(rows, [2]string{"Motivo", s.IsolateReason})
		}
		if len(s.Exceptions) > 0 {
			rows = append(rows, [2]string{"Liberados", strings.Join(s.Exceptions, ", ")})
		}
	}
	if len(s.Deny) > 0 {
		rows = append(rows, [2]string{"Bloqueios próprios", strings.Join(s.Deny, ", ")})
	}
	if len(s.Allow) > 0 {
		rows = append(rows, [2]string{"Exceções próprias", strings.Join(s.Allow, ", ")})
	}
	if s.SkipGlobalLists {
		rows = append(rows, [2]string{"Listas globais", "não aplicadas"})
	}
	for _, r := range rows {
		fmt.Fprintf(tw, "%s:\t%s\n", r[0], r[1])
	}
	tw.Flush()
}

func state(v clients.View) string {
	if v.Settings.Isolated {
		m := v.Settings.IsolateMode
		if m == "" {
			m = "padrão"
		}
		return "ISOLADO (" + m + ")"
	}
	if len(v.Settings.Deny)+len(v.Settings.Allow) > 0 || v.Settings.SkipGlobalLists {
		return "regras próprias"
	}
	return "normal"
}

func ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("há %ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("há %dmin", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("há %dh", int(d.Hours()))
	}
	return fmt.Sprintf("há %dd", int(d.Hours()/24))
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func splitList(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// readNewPassword pede a senha duas vezes sem mostrar no terminal.
func readNewPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 1024))
		return strings.TrimRight(string(b), "\r\n"), err
	}
	fmt.Fprint(os.Stderr, "Nova senha do painel: ")
	a, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "Repita a senha: ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(a) != string(b) {
		return "", errors.New("as senhas não conferem")
	}
	return string(a), nil
}
