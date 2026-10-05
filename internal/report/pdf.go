// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package report

import (
	"bytes"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
	"golang.org/x/image/font/gofont/gobold"
	"golang.org/x/image/font/gofont/goregular"
)

// Cores do relatório (impresso em fundo branco; o ciano é o do painel).
var (
	cInk     = rgb{17, 24, 39}
	cInk2    = rgb{75, 85, 99}
	cMuted   = rgb{140, 148, 160}
	cLine    = rgb{226, 230, 236}
	cAccent  = rgb{8, 145, 178}
	cAccentL = rgb{165, 222, 236}
	cBlock   = rgb{208, 59, 84}
	cHigh    = rgb{230, 120, 40}
	cMedium  = rgb{214, 168, 30}
	cLow     = rgb{90, 140, 200}
	cNavy    = rgb{11, 18, 32}
)

type rgb struct{ r, g, b int }

const (
	pageW  = 210.0
	margin = 16.0
	inner  = pageW - 2*margin
)

var kindLabel = map[string]string{
	"threat_blocked": "Ameaça bloqueada",
	"dga":            "Nomes aleatórios (DGA)",
	"dns_tunnel":     "Túnel por DNS",
	"nrd":            "Domínio recém-registrado",
	"new_device":     "Dispositivo novo",
	"query_flood":    "Excesso de consultas",
}

var sevLabel = map[string]string{"critical": "Crítica", "high": "Alta", "medium": "Média", "low": "Baixa"}
var sevColor = map[string]rgb{"critical": cBlock, "high": cHigh, "medium": cMedium, "low": cLow}

// Render desenha o PDF.
func Render(d *Data) ([]byte, error) {
	p := fpdf.New("P", "mm", "A4", "")
	p.AddUTF8FontFromBytes("go", "", goregular.TTF)
	p.AddUTF8FontFromBytes("go", "B", gobold.TTF)
	p.SetMargins(margin, margin, margin)
	p.SetAutoPageBreak(true, 18)
	p.SetTitle(d.Title, true)
	p.SetAuthor("HeimdallDNS", true)
	p.SetCreator("HeimdallDNS "+d.Version, true)
	p.SetCreationDate(d.Generated)
	p.SetFooterFunc(func() {
		p.SetY(-12)
		font(p, "", 7.5, cMuted)
		p.CellFormat(inner/2, 5, "HeimdallDNS · "+d.Node+" · gerado em "+d.Generated.Format("02/01/2006 15:04"), "", 0, "L", false, 0, "")
		p.CellFormat(inner/2, 5, fmt.Sprintf("página %d", p.PageNo()), "", 0, "R", false, 0, "")
	})
	p.AddPage()

	header(p, d)
	kpis(p, d)
	section(p, "Consultas por dia")
	chart(p, d.Days)
	twoTables(p, d)
	alerts(p, d)

	var buf bytes.Buffer
	if err := p.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func font(p *fpdf.Fpdf, style string, size float64, c rgb) {
	p.SetFont("go", style, size)
	p.SetTextColor(c.r, c.g, c.b)
}

func fill(p *fpdf.Fpdf, c rgb) { p.SetFillColor(c.r, c.g, c.b) }
func draw(p *fpdf.Fpdf, c rgb) { p.SetDrawColor(c.r, c.g, c.b) }

// header: faixa escura com o emblema (escudo, arco da Bifröst e o olho do
// guardião), o título e o período.
func header(p *fpdf.Fpdf, d *Data) {
	fill(p, cNavy)
	p.Rect(0, 0, pageW, 38, "F")
	// Emblema.
	cx, cy := margin+9.0, 19.0
	fill(p, rgb{18, 32, 52})
	draw(p, cAccent)
	p.SetLineWidth(0.6)
	shield := []fpdf.PointType{{X: cx - 8, Y: cy - 10}, {X: cx + 8, Y: cy - 10}, {X: cx + 8, Y: cy}, {X: cx, Y: cy + 11}, {X: cx - 8, Y: cy}}
	p.Polygon(shield, "FD")
	for i, c := range []rgb{{239, 68, 68}, {234, 179, 8}, {34, 197, 94}, {34, 211, 238}} {
		draw(p, c)
		p.SetLineWidth(0.5)
		r := 6.2 - float64(i)*1.0
		p.Arc(cx, cy+2, r, r, 0, 0, 180, "D")
	}
	fill(p, rgb{34, 211, 238})
	p.Ellipse(cx, cy+1.4, 1.6, 1.1, 0, "F")

	p.SetXY(margin+22, 9)
	font(p, "B", 17, rgb{240, 246, 252})
	p.CellFormat(0, 8, d.Title, "", 1, "L", false, 0, "")
	p.SetX(margin + 22)
	font(p, "", 9.5, rgb{170, 190, 210})
	period := d.From.Format("02/01/2006") + " a " + d.To.Add(-time.Second).Format("02/01/2006")
	p.CellFormat(0, 6, "Período: "+period+"  ·  Servidor: "+d.Node, "", 1, "L", false, 0, "")
	p.SetX(margin + 22)
	font(p, "", 8, cAccentL)
	p.CellFormat(0, 5, "HeimdallDNS — o guardião da sua rede", "", 1, "L", false, 0, "")
	p.SetY(46)
}

func pct(a, b int64) string {
	if b == 0 {
		return "0%"
	}
	return fmt.Sprintf("%.1f%%", float64(a)*100/float64(b))
}

// num escreve com separador de milhar (1.234.567).
func num(n int64) string {
	s := fmt.Sprint(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var out []string
	for len(s) > 3 {
		out = append([]string{s[len(s)-3:]}, out...)
		s = s[:len(s)-3]
	}
	out = append([]string{s}, out...)
	r := strings.Join(out, ".")
	if neg {
		return "-" + r
	}
	return r
}

// kpis: os números principais em cartões.
func kpis(p *fpdf.Fpdf, d *Data) {
	type kpi struct{ label, value, note string }
	items := []kpi{
		{"Consultas", num(d.Total), fmt.Sprintf("%s por dia", num(d.Total/int64(max(len(d.Days), 1))))},
		{"Bloqueadas", num(d.Blocked + d.Isolated), pct(d.Blocked+d.Isolated, d.Total) + " do total"},
		{"Dispositivos", num(int64(d.Devices)), "ativos no período"},
		{"Alertas", num(int64(d.AlertTotal)), fmt.Sprintf("%d críticos/altos", d.AlertsBy["critical"]+d.AlertsBy["high"])},
	}
	gap := 4.0
	w := (inner - gap*3) / 4
	y := p.GetY()
	for i, k := range items {
		x := margin + float64(i)*(w+gap)
		fill(p, rgb{246, 248, 251})
		draw(p, cLine)
		p.SetLineWidth(0.2)
		p.RoundedRect(x, y, w, 22, 2.5, "1234", "FD")
		fill(p, cAccent)
		p.Rect(x, y+3, 1.2, 16, "F")
		p.SetXY(x+4, y+3)
		font(p, "", 8, cInk2)
		p.CellFormat(w-6, 4, k.label, "", 2, "L", false, 0, "")
		p.SetX(x + 4)
		font(p, "B", 15, cInk)
		p.CellFormat(w-6, 8, k.value, "", 2, "L", false, 0, "")
		p.SetX(x + 4)
		font(p, "", 7, cMuted)
		p.CellFormat(w-6, 4, k.note, "", 0, "L", false, 0, "")
	}
	p.SetY(y + 26)
	font(p, "", 8, cInk2)
	line := fmt.Sprintf("Respondidas do cache: %s  ·  Encaminhadas: %s (média %.0f ms)  ·  Falhas do upstream: %s",
		pct(d.Cached, d.Total), num(d.Forwarded), d.AvgMS, num(d.Errors))
	p.CellFormat(inner, 5, line, "", 1, "L", false, 0, "")
	p.Ln(2)
}

func section(p *fpdf.Fpdf, title string) {
	p.Ln(3)
	font(p, "B", 11.5, cInk)
	p.CellFormat(inner, 7, title, "", 1, "L", false, 0, "")
	draw(p, cAccent)
	p.SetLineWidth(0.5)
	y := p.GetY()
	p.Line(margin, y, margin+14, y)
	p.Ln(3)
}

// chart: barras empilhadas por dia (liberadas em ciano, bloqueadas em
// vermelho), com legenda e um eixo só.
func chart(p *fpdf.Fpdf, days []Day) {
	h := 46.0
	axisW := 14.0
	x0, y0 := margin+axisW, p.GetY()+2
	w := inner - axisW
	var peak int64 = 1
	for _, d := range days {
		peak = max(peak, d.Total)
	}
	top := niceCeil(float64(peak))
	// Grade e escala.
	font(p, "", 6.5, cMuted)
	for i := 0; i <= 4; i++ {
		v := top * float64(i) / 4
		y := y0 + h - h*float64(i)/4
		draw(p, cLine)
		p.SetLineWidth(0.15)
		p.Line(x0, y, x0+w, y)
		p.SetXY(margin, y-2)
		p.CellFormat(axisW-2, 4, short(v), "", 0, "R", false, 0, "")
	}
	n := len(days)
	if n == 0 {
		return
	}
	slot := w / float64(n)
	bw := math.Min(slot*0.62, 14)
	for i, d := range days {
		bx := x0 + float64(i)*slot + (slot-bw)/2
		allowed := d.Total - d.Blocked
		ha := h * float64(allowed) / top
		hb := h * float64(d.Blocked) / top
		fill(p, cAccent)
		if ha > 0 {
			p.Rect(bx, y0+h-ha, bw, ha, "F")
		}
		fill(p, cBlock)
		if hb > 0 {
			p.Rect(bx, y0+h-ha-hb-0.4, bw, hb, "F") // 0,4 mm de respiro entre as partes
		}
		// Rótulo do dia (todos na semana; um a cada 5 no mês).
		if n <= 10 || i%5 == 0 || i == n-1 {
			font(p, "", 6.5, cInk2)
			label := d.Date.Format("02/01")
			if n <= 7 {
				label = weekday(d.Date) + " " + label
			}
			p.SetXY(x0+float64(i)*slot-2, y0+h+1)
			p.CellFormat(slot+4, 4, label, "", 0, "C", false, 0, "")
		}
	}
	// Legenda.
	ly := y0 + h + 7
	legend := func(x float64, c rgb, text string) float64 {
		fill(p, c)
		p.Rect(x, ly+1, 3, 3, "F")
		p.SetXY(x+4, ly)
		font(p, "", 7.5, cInk2)
		tw := p.GetStringWidth(text) + 2
		p.CellFormat(tw, 5, text, "", 0, "L", false, 0, "")
		return x + 4 + tw + 4
	}
	lx := legend(x0, cAccent, "Liberadas")
	legend(lx, cBlock, "Bloqueadas (listas, filtro web e isolamento)")
	p.SetY(ly + 7)
}

func weekday(t time.Time) string {
	return [...]string{"dom", "seg", "ter", "qua", "qui", "sex", "sáb"}[t.Weekday()]
}

func niceCeil(v float64) float64 {
	if v <= 4 {
		return 4
	}
	exp := math.Pow(10, math.Floor(math.Log10(v)))
	for _, m := range []float64{1, 2, 2.5, 5, 10} {
		if m*exp >= v {
			return m * exp
		}
	}
	return 10 * exp
}

func short(v float64) string {
	switch {
	case v >= 1e6:
		return strings.TrimSuffix(fmt.Sprintf("%.1f", v/1e6), ".0") + " mi"
	case v >= 1e3:
		return strings.TrimSuffix(fmt.Sprintf("%.1f", v/1e3), ".0") + " mil"
	}
	return fmt.Sprintf("%.0f", v)
}

// twoTables: domínios mais bloqueados e aparelhos mais ativos, lado a lado.
func twoTables(p *fpdf.Fpdf, d *Data) {
	section(p, "Mais bloqueados e mais ativos")
	gap := 6.0
	w := (inner - gap) / 2
	y := p.GetY()
	var dom [][]string
	for _, r := range d.TopBlocked {
		dom = append(dom, []string{r.Key, num(r.Count)})
	}
	var cli [][]string
	for _, c := range d.TopClients {
		cli = append(cli, []string{c.Name, num(c.Queries), pct(c.Blocked, c.Queries)})
	}
	y1 := table(p, margin, y, w, []string{"Domínio bloqueado", "Vezes"}, []float64{0.75, 0.25}, dom)
	y2 := table(p, margin+w+gap, y, w, []string{"Dispositivo", "Consultas", "Bloq."}, []float64{0.56, 0.26, 0.18}, cli)
	p.SetY(max(y1, y2) + 2)
}

// table desenha uma tabela simples e devolve onde terminou.
func table(p *fpdf.Fpdf, x, y, w float64, head []string, cols []float64, rows [][]string) float64 {
	rowH := 5.6
	p.SetXY(x, y)
	font(p, "B", 7.5, cInk2)
	for i, h := range head {
		align := "L"
		if i > 0 {
			align = "R"
		}
		p.CellFormat(w*cols[i], rowH, h, "B", 0, align, false, 0, "")
	}
	y += rowH
	if len(rows) == 0 {
		p.SetXY(x, y+1)
		font(p, "", 8, cMuted)
		p.CellFormat(w, rowH, "Nada no período.", "", 0, "L", false, 0, "")
		return y + rowH + 2
	}
	draw(p, cLine)
	p.SetLineWidth(0.15)
	for ri, r := range rows {
		if ri%2 == 1 {
			fill(p, rgb{247, 249, 251})
			p.Rect(x, y, w, rowH, "F")
		}
		p.SetXY(x, y)
		for i, v := range r {
			cw := w * cols[i]
			align := "L"
			if i > 0 {
				align = "R"
				font(p, "", 8, cInk2)
			} else {
				font(p, "", 8, cInk)
				v = fit(p, v, cw-1)
			}
			p.CellFormat(cw, rowH, v, "", 0, align, false, 0, "")
		}
		y += rowH
	}
	return y
}

// fit corta o texto com reticências para caber na largura.
func fit(p *fpdf.Fpdf, s string, w float64) string {
	if p.GetStringWidth(s) <= w {
		return s
	}
	r := []rune(s)
	for len(r) > 1 && p.GetStringWidth(string(r)+"…") > w {
		r = r[:len(r)-1]
	}
	return string(r) + "…"
}

// alerts: totais por gravidade e tipo e a lista dos mais graves.
func alerts(p *fpdf.Fpdf, d *Data) {
	section(p, "Alertas de segurança")
	if d.AlertTotal == 0 {
		font(p, "", 9, cInk2)
		p.MultiCell(inner, 5, "Nenhum alerta no período. O guardião não viu ameaças, nomes aleatórios, túneis nem domínios recém-registrados.", "", "L", false)
		return
	}
	// Faixa com a contagem por gravidade (rótulo + número; nunca só cor).
	x := margin
	y := p.GetY()
	for _, s := range []string{"critical", "high", "medium", "low"} {
		c := sevColor[s]
		fill(p, c)
		p.RoundedRect(x, y, 2.6, 2.6, 0.6, "1234", "F")
		p.SetXY(x+3.6, y-1)
		font(p, "", 8.5, cInk2)
		t := fmt.Sprintf("%s: %d", sevLabel[s], d.AlertsBy[s])
		tw := p.GetStringWidth(t) + 2
		p.CellFormat(tw, 5, t, "", 0, "L", false, 0, "")
		x += 3.6 + tw + 6
	}
	p.SetY(y + 6)
	var kinds []string
	for k, n := range d.AlertKinds {
		label := kindLabel[k]
		if label == "" {
			label = k
		}
		kinds = append(kinds, fmt.Sprintf("%s (%d)", label, n))
	}
	font(p, "", 8, cInk2)
	slices.Sort(kinds)
	p.MultiCell(inner, 4.5, "Por tipo: "+strings.Join(kinds, " · "), "", "L", false)
	p.Ln(2)
	var rows [][]string
	for _, e := range d.Alerts {
		what := e.Domain
		if what == "" {
			what = e.ClientIP
		}
		label := kindLabel[e.Kind]
		if label == "" {
			label = e.Kind
		}
		rows = append(rows, []string{label + " — " + what, sevLabel[e.Severity], e.FirstSeen.Format("02/01 15:04"), num(int64(e.Count))})
	}
	if p.GetY() > 230 {
		p.AddPage()
	}
	table(p, margin, p.GetY(), inner, []string{"Alerta", "Gravidade", "Primeiro", "Vezes"}, []float64{0.58, 0.14, 0.16, 0.12}, rows)
}
