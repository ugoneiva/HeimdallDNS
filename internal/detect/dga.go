package detect

import (
	"math"
	"strings"
)

// Pares de letras comuns em inglês e português. Nomes gerados por algoritmo
// (DGA) usam muitos pares que quase nunca aparecem em palavras.
var commonBigrams = func() map[string]bool {
	const list = "th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta la ns di fo ho pe ec pr no ct us ac ot il tr ly nc et ut ss so rs un lo wa ge ie wh ee wi em ad ol rt po we na ul ni ts mo ow pa im mi ai sh ir su id os iv ia am fi ci vi pl ig tu ev ld ry mp fe bl ab gh ty op wo sa ay ex ke fr oo av ag if ap gr od bo sp rd do uc bu ei ov by rm ep tt oc fa ef cu rn sc gi da yo cr cl du ga qu ue ff ba ey ls va um pp ua up lu go ht ru ug ds lt pi rc rr eg au ck ew mu br bi pt ak pu ui rg ib tl ny ki rk ys ob mm fu ph og ms ye ud mb ip ub oi rl gu dr hr cc tw ft wn nu af hu nn eo vo rv nf xp gn sm fl iz ok nl my gl aw ju oa sy sl ps jo lf nv je nk kn gs dy hy ze ks xt bs ik dd cy rp sk xi ws lv dl rf eu wr xa ja za ao lh nh oe oa ua ui eu ix ox ax ex iz az oz uz zo zu ze za sa so su vo va gu go ga gi ge bo bu bi be ba ka ko ku ke ki ya yu ye yo"
	m := map[string]bool{}
	for _, b := range strings.Fields(list) {
		m[b] = true
	}
	return m
}()

func isVowel(c byte) bool { return strings.IndexByte("aeiouy", c) >= 0 }

// entropy é a entropia de Shannon (bits por caractere).
func entropy(s string) float64 {
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	h, n := 0.0, float64(len(s))
	for _, f := range freq {
		if f > 0 {
			p := float64(f) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// DGAScore pontua o quanto um rótulo parece gerado por algoritmo. Recebe só o
// rótulo registrado (o "exemplo" de exemplo.com.br). Acima de dgaThreshold é
// suspeito. Sozinha, a pontuação erra; o detector só alerta quando um mesmo
// dispositivo junta vários nomes suspeitos que NÃO existem (NXDOMAIN), que é
// o comportamento de um malware procurando o servidor de comando.
func DGAScore(label string) float64 {
	n := len(label)
	if n < 8 || strings.HasPrefix(label, "xn--") {
		return 0
	}
	letters, vowels, digits, run, maxRun := 0, 0, 0, 0, 0
	for i := 0; i < n; i++ {
		c := label[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
			run = 0
		case c >= 'a' && c <= 'z':
			letters++
			if isVowel(c) {
				vowels++
				run = 0
			} else {
				run++
				maxRun = max(maxRun, run)
			}
		default:
			run = 0
		}
	}
	rare, pairs := 0, 0
	for i := 0; i+1 < n; i++ {
		a, b := label[i], label[i+1]
		if a < 'a' || a > 'z' || b < 'a' || b > 'z' {
			continue
		}
		pairs++
		if !commonBigrams[label[i:i+2]] {
			rare++
		}
	}

	score := 0.0
	if h := entropy(label); h > 3.0 {
		score += min(2, (h-3.0)*2) // 3.5 bits → 1 ponto
	}
	if letters > 0 {
		if v := float64(vowels) / float64(letters); v < 0.3 {
			score += (0.3 - v) * 5
		}
	}
	if d := float64(digits) / float64(n); d > 0.15 && d < 0.85 { // letras e dígitos misturados
		score += 1
	}
	if maxRun >= 4 {
		score += 0.5 * float64(maxRun-3)
	}
	if pairs > 0 {
		if r := float64(rare) / float64(pairs); r > 0.3 {
			score += (r - 0.3) * 4
		}
	}
	if n >= 16 {
		score += 0.5
	}
	if n >= 12 && digits > 0 && digits < n && strings.Trim(label, "0123456789abcdef") == "" {
		score += 1 // parece um hash em hexadecimal
	}
	return score
}

const dgaThreshold = 2.5

// LooksGenerated diz se o rótulo parece gerado por algoritmo.
func LooksGenerated(label string) bool { return DGAScore(label) >= dgaThreshold }
