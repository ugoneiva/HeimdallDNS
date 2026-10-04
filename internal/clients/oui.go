package clients

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ManufURL é a base de fabricantes do Wireshark (IEEE OUI, MA-M e MA-S).
const ManufURL = "https://www.wireshark.org/download/automated/data/manuf"

// PrivateMAC é o "fabricante" de um MAC aleatório (celulares e notebooks com
// endereço privado por rede): o bit "administrado localmente" está ligado.
const PrivateMAC = "MAC privado (aleatório)"

// OUI traduz o prefixo do MAC no fabricante. Os blocos de 24, 28 e 36 bits
// ficam em mapas separados; vale o prefixo mais longo.
type OUI struct {
	byBits map[int]map[uint64]string
}

func ParseOUI(r io.Reader) (*OUI, error) {
	db := &OUI{byBits: map[int]map[uint64]string{24: {}, 28: {}, 36: {}}}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 2 {
			continue
		}
		prefix, bits := strings.TrimSpace(f[0]), 24
		if i := strings.IndexByte(prefix, '/'); i >= 0 {
			n, err := strconv.Atoi(prefix[i+1:])
			if err != nil {
				continue
			}
			prefix, bits = prefix[:i], n
		}
		m, ok := db.byBits[bits]
		if !ok {
			continue
		}
		var v uint64
		nbytes := 0
		for _, h := range strings.Split(prefix, ":") {
			b, err := strconv.ParseUint(h, 16, 8)
			if err != nil {
				nbytes = -1
				break
			}
			v = v<<8 | b
			nbytes++
		}
		if nbytes < 3 {
			continue
		}
		v = (v << (8 * (6 - nbytes))) >> (48 - bits) // alinha em 48 bits e corta no prefixo
		name := strings.TrimSpace(f[1])
		if len(f) >= 3 && strings.TrimSpace(f[2]) != "" {
			name = strings.TrimSpace(f[2])
		}
		m[v] = name
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(db.byBits[24]) == 0 {
		return nil, fmt.Errorf("base de fabricantes vazia")
	}
	return db, nil
}

// Lookup devolve o fabricante do MAC ("aa:bb:cc:dd:ee:ff"), ou "" se não souber.
func (db *OUI) Lookup(mac string) string {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return ""
	}
	var v uint64
	for _, b := range hw {
		v = v<<8 | uint64(b)
	}
	if db != nil {
		for _, bits := range []int{36, 28, 24} {
			if name, ok := db.byBits[bits][v>>(48-bits)]; ok {
				return name
			}
		}
	}
	if hw[0]&0x02 != 0 {
		return PrivateMAC
	}
	return ""
}

// LoadOUI lê a base local; se não existir ou tiver mais de maxAge, baixa de novo.
// Sem rede, fica com a cópia antiga (se houver).
func LoadOUI(ctx context.Context, path string, maxAge time.Duration) (*OUI, error) {
	fi, err := os.Stat(path)
	if err != nil || time.Since(fi.ModTime()) > maxAge {
		if derr := downloadFile(ctx, ManufURL, path); derr != nil && err != nil {
			return nil, derr
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseOUI(f)
}

func downloadFile(ctx context.Context, url, dst string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "HeimdallDNS")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %s", url, resp.Status)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".baixando-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = io.Copy(tmp, io.LimitReader(resp.Body, 32<<20))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}
