// Package oui maps MAC addresses to their vendor using the IEEE MA-L
// registry embedded in the binary.
package oui

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"strings"
	"sync"
)

//go:embed oui.tsv.gz
var table []byte

var (
	once    sync.Once
	vendors map[string]string // "BC2411" → organisation
)

func load() {
	vendors = make(map[string]string, 40000)
	zr, err := gzip.NewReader(bytes.NewReader(table))
	if err != nil {
		return
	}
	defer zr.Close()
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "\t")
		if ok && len(k) == 6 {
			vendors[strings.ToUpper(k)] = strings.TrimSpace(v)
		}
	}
}

// Normalize returns the MAC as lower-case "aa:bb:cc:dd:ee:ff", or "" if s is
// not a 48-bit address (separators ':' '-' or none are accepted).
func Normalize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer(":", "", "-", "", ".", "").Replace(s)
	if len(s) != 12 {
		return ""
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ""
		}
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(s[i : i+2])
	}
	return b.String()
}

// IsRandom reports whether the "locally administered" bit is set: such
// addresses are not assigned by a vendor (private addresses of phones and
// laptops, virtual NICs).
func IsRandom(mac string) bool {
	mac = Normalize(mac)
	if mac == "" {
		return false
	}
	hi := hexVal(mac[0])<<4 | hexVal(mac[1])
	return hi&0x02 != 0
}

func hexVal(c byte) int {
	if c >= 'a' {
		return int(c-'a') + 10
	}
	return int(c - '0')
}

// Lookup returns the vendor of a MAC address. For a locally administered
// (random) address the vendor is empty and random is true.
func Lookup(mac string) (vendor string, random bool) {
	mac = Normalize(mac)
	if mac == "" {
		return "", false
	}
	if IsRandom(mac) {
		return "", true
	}
	once.Do(load)
	return vendors[strings.ToUpper(strings.ReplaceAll(mac[:8], ":", ""))], false
}
