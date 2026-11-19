// Package dnsname gives the controller a DNS name (hestia.home) through the
// AdGuard Home found in the network: connection with a pinned certificate,
// plan → apply → verify (with rollback), and a read-only watcher.
package dnsname

import (
	"errors"
	"sort"
	"strings"

	"github.com/uxerror/hestia/internal/integrations/adguard"
)

// FallbackZone is the zone used when AdGuard has no rewrites to learn it from.
const FallbackZone = "home"

// DefaultLabel is the host part of the default name.
const DefaultLabel = "hestia"

// NormalizeDomain lower-cases the name, drops a trailing dot and checks it is
// a plain DNS name: letters, digits and hyphens in labels, at most 253
// characters, no wildcard.
func NormalizeDomain(s string) (string, error) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if d == "" {
		return "", errors.New("введите имя")
	}
	if len(d) > 253 {
		return "", errors.New("имя длиннее 253 символов")
	}
	if strings.Contains(d, "*") {
		return "", errors.New("имя не может содержать *")
	}
	for _, l := range strings.Split(d, ".") {
		if l == "" {
			return "", errors.New("пустая часть имени между точками")
		}
		if len(l) > 63 {
			return "", errors.New("часть имени длиннее 63 символов")
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return "", errors.New("часть имени не может начинаться или заканчиваться дефисом")
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("в имени допустимы только латинские буквы, цифры, дефис и точки")
			}
		}
	}
	return d, nil
}

// DefaultZone is the most frequent suffix of the rewrites shaped
// "<name>.<zone>". Wildcards and names without a dot are ignored; ties go to
// the alphabetically first zone; no data gives "home".
func DefaultZone(list []adguard.Rewrite) string {
	count := map[string]int{}
	for _, r := range list {
		d := strings.ToLower(strings.TrimSuffix(r.Domain, "."))
		if d == "" || strings.Contains(d, "*") {
			continue
		}
		_, zone, ok := strings.Cut(d, ".")
		if !ok || zone == "" {
			continue
		}
		count[zone]++
	}
	if len(count) == 0 {
		return FallbackZone
	}
	zones := make([]string, 0, len(count))
	for z := range count {
		zones = append(zones, z)
	}
	sort.Slice(zones, func(i, j int) bool {
		if count[zones[i]] != count[zones[j]] {
			return count[zones[i]] > count[zones[j]]
		}
		return zones[i] < zones[j]
	})
	return zones[0]
}

// DefaultDomain is "hestia.<zone>".
func DefaultDomain(list []adguard.Rewrite) string { return DefaultLabel + "." + DefaultZone(list) }

// coveringWildcards returns the wildcard rewrites that match domain
// ("*.home" covers "hestia.home" and "a.b.home").
func coveringWildcards(list []adguard.Rewrite, domain string) []adguard.Rewrite {
	var out []adguard.Rewrite
	for _, r := range list {
		d := strings.ToLower(r.Domain)
		if strings.HasPrefix(d, "*.") && strings.HasSuffix(domain, d[1:]) {
			out = append(out, r)
		}
	}
	return out
}
