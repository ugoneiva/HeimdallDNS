package console

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/ugoneiva/HeimdallDNS/internal/clients"
)

// Template é um modelo de política que o MSP aplica em vários clientes de uma
// vez. Aplicar só acrescenta e atualiza: nada que o cliente já tem é apagado
// (listas e regras próprias dele continuam).
type Template struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Lists       []TemplateList `json:"lists,omitempty"`     // acrescentadas se faltarem
	Deny        []string       `json:"deny,omitempty"`      // somadas às regras do cliente
	Allow       []string       `json:"allow,omitempty"`     // idem
	Upstreams   []string       `json:"upstreams,omitempty"` // se houver, substituem os do cliente
	Mode        string         `json:"mode,omitempty"`
	// Security sobrepõe só as chaves informadas (ex.: {"dga": true,
	// "auto_isolate": ["threat_blocked"]}).
	Security map[string]any  `json:"security,omitempty"`
	Groups   []clients.Group `json:"groups,omitempty"` // criados ou atualizados pelo nome
}

type TemplateList struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Category string `json:"category,omitempty"`
}

// ApplyResult é o que aconteceu num cliente.
type ApplyResult struct {
	TenantID   string   `json:"tenant_id"`
	TenantName string   `json:"tenant_name"`
	OK         bool     `json:"ok"`
	Changes    []string `json:"changes"`
	Error      string   `json:"error,omitempty"`
}

// ValidateTemplate confere o que dá para conferir sem falar com os clientes.
func ValidateTemplate(t Template) error {
	if strings.TrimSpace(t.Name) == "" {
		return errors.New("dê um nome ao modelo")
	}
	for _, l := range t.Lists {
		if !strings.HasPrefix(l.URL, "http://") && !strings.HasPrefix(l.URL, "https://") {
			return fmt.Errorf("lista %q: use uma URL http(s)", l.URL)
		}
	}
	// Os ids dos grupos são de cada cliente: valida com ids provisórios.
	gs := slices.Clone(t.Groups)
	for i := range gs {
		gs[i].ID = fmt.Sprintf("modelo-%d", i)
	}
	if err := clients.ValidateGroups(gs); err != nil {
		return err
	}
	return nil
}

func (c *Console) send(ctx context.Context, t Tenant, method, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(t.URL, "/")+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+t.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client(t.InsecureTLS).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 500))
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s %s: %s", method, path, e.Error)
		}
		return fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(out)
}

// Apply aplica o modelo nos clientes escolhidos, em paralelo.
func (c *Console) Apply(ctx context.Context, tpl Template, tenantIDs []string) []ApplyResult {
	c.mu.Lock()
	var ts []Tenant
	for _, id := range tenantIDs {
		if t, ok := c.tenants[id]; ok {
			ts = append(ts, t)
		}
	}
	c.mu.Unlock()
	out := make([]ApplyResult, len(ts))
	var wg sync.WaitGroup
	for i, t := range ts {
		wg.Go(func() {
			r := ApplyResult{TenantID: t.ID, TenantName: t.Name, Changes: []string{}}
			if err := c.applyOne(ctx, t, tpl, &r); err != nil {
				r.Error = err.Error()
			} else {
				r.OK = true
			}
			out[i] = r
		})
	}
	wg.Wait()
	select {
	case c.wake <- struct{}{}: // relê os clientes para o painel mostrar o efeito
	default:
	}
	return out
}

func (c *Console) applyOne(ctx context.Context, t Tenant, tpl Template, r *ApplyResult) error {
	if len(tpl.Lists) > 0 {
		var have []struct {
			URL string `json:"url"`
		}
		if err := c.send(ctx, t, "GET", "/api/lists", nil, &have); err != nil {
			return err
		}
		for _, l := range tpl.Lists {
			if slices.ContainsFunc(have, func(h struct {
				URL string `json:"url"`
			}) bool {
				return h.URL == l.URL
			}) {
				continue
			}
			if err := c.send(ctx, t, "POST", "/api/lists", l, nil); err != nil {
				return err
			}
			r.Changes = append(r.Changes, "lista "+l.Name)
		}
	}
	if len(tpl.Deny)+len(tpl.Allow) > 0 {
		var rules struct {
			Allow []string `json:"allow"`
			Deny  []string `json:"deny"`
		}
		if err := c.send(ctx, t, "GET", "/api/rules", nil, &rules); err != nil {
			return err
		}
		n := 0
		merge := func(cur, add []string) []string {
			for _, x := range add {
				if !slices.Contains(cur, x) {
					cur = append(cur, x)
					n++
				}
			}
			return cur
		}
		rules.Deny, rules.Allow = merge(rules.Deny, tpl.Deny), merge(rules.Allow, tpl.Allow)
		if n > 0 {
			if err := c.send(ctx, t, "PUT", "/api/rules", rules, nil); err != nil {
				return err
			}
			r.Changes = append(r.Changes, fmt.Sprintf("%d regras", n))
		}
	}
	if len(tpl.Upstreams) > 0 {
		mode := tpl.Mode
		if mode == "" {
			mode = "fastest"
		}
		if err := c.send(ctx, t, "PUT", "/api/dns/upstream", map[string]any{"servers": tpl.Upstreams, "mode": mode}, nil); err != nil {
			return err
		}
		r.Changes = append(r.Changes, "upstreams")
	}
	if len(tpl.Security) > 0 {
		var cur map[string]any
		if err := c.send(ctx, t, "GET", "/api/security/settings", nil, &cur); err != nil {
			return err
		}
		for k, v := range tpl.Security {
			cur[k] = v
		}
		if err := c.send(ctx, t, "PUT", "/api/security/settings", cur, nil); err != nil {
			return err
		}
		r.Changes = append(r.Changes, "segurança")
	}
	if len(tpl.Groups) > 0 {
		var cur []clients.Group
		if err := c.send(ctx, t, "GET", "/api/groups", nil, &cur); err != nil {
			return err
		}
		for _, g := range tpl.Groups {
			i := slices.IndexFunc(cur, func(x clients.Group) bool { return strings.EqualFold(x.Name, g.Name) })
			if i >= 0 {
				g.ID = cur[i].ID // mantém os aparelhos que já estão no grupo
				cur[i] = g
			} else {
				g.ID = ""
				cur = append(cur, g)
			}
			r.Changes = append(r.Changes, "grupo "+g.Name)
		}
		if err := c.send(ctx, t, "PUT", "/api/groups", map[string]any{"groups": cur}, nil); err != nil {
			return err
		}
	}
	return nil
}
