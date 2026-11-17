// Package version parses and compares Hestia build versions, which come from
// `git describe --tags --always --dirty`: v0.1.0, v0.1.0-5-gabc1234 and the
// same with a -dirty suffix. Anything else (dev, a bare commit hash) is
// "unknown" and cannot be ordered.
package version

import (
	"fmt"
	"regexp"
	"strconv"
)

// V is a parsed version.
type V struct {
	Major, Minor, Patch int
	Commits             int    // commits since the tag (0 for the tag itself)
	Hash                string // abbreviated commit, only when Commits > 0
	Dirty               bool   // built with uncommitted changes
	Raw                 string
}

var re = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)(?:-(\d+)-g([0-9a-f]{4,40}))?(-dirty)?$`)

// Parse parses a version string; ok is false for versions that cannot be
// compared (dev, a bare hash, anything unexpected).
func Parse(s string) (v V, ok bool) {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return V{}, false
	}
	n := func(x string) int {
		i, err := strconv.Atoi(x)
		if err != nil {
			i = 1 << 30 // absurdly large: keep ordering sane instead of failing
		}
		return i
	}
	v = V{Major: n(m[1]), Minor: n(m[2]), Patch: n(m[3]), Hash: m[5], Dirty: m[6] != "", Raw: s}
	if m[4] != "" {
		v.Commits = n(m[4])
	}
	return v, true
}

// Tag reports whether v is exactly a release tag (no commits on top, clean).
func (v V) Tag() bool { return v.Commits == 0 && !v.Dirty }

// Compare orders by (major, minor, patch, commits since tag); the dirty flag
// and the hash do not take part. It returns -1, 0 or 1.
func Compare(a, b V) int {
	for _, p := range [][2]int{{a.Major, b.Major}, {a.Minor, b.Minor}, {a.Patch, b.Patch}, {a.Commits, b.Commits}} {
		if p[0] != p[1] {
			if p[0] < p[1] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// Decision is the verdict on installing candidate over current.
type Decision struct {
	// Allowed is false when the install must be refused (Reason says why).
	Allowed bool
	// Confirm is set when the install is possible only after an explicit
	// confirmation of Warning.
	Confirm bool
	Reason  string
	Warning string
}

// Decide applies the update rules: only a newer version is offered; a
// downgrade is never allowed; an unknown or dirty version needs confirmation.
func Decide(current, candidate string) Decision {
	cur, curOK := Parse(current)
	cand, candOK := Parse(candidate)
	switch {
	case !candOK:
		return Decision{Allowed: true, Confirm: true,
			Warning: fmt.Sprintf("Версия устанавливаемой сборки неизвестна («%s»): сравнить с текущей нельзя.", candidate)}
	case !curOK:
		return Decision{Allowed: true, Confirm: true,
			Warning: fmt.Sprintf("Версия контроллера неизвестна («%s»): сравнить с устанавливаемой нельзя.", current)}
	}
	c := Compare(cur, cand)
	switch {
	case c > 0:
		return Decision{Reason: fmt.Sprintf("Установленная версия (%s) новее предлагаемой (%s): понижение версии запрещено.", current, candidate)}
	case c == 0 && !cand.Dirty:
		return Decision{Reason: fmt.Sprintf("Версия %s уже установлена.", current)}
	}
	d := Decision{Allowed: true}
	if cand.Dirty {
		d.Confirm = true
		d.Warning = fmt.Sprintf("Сборка %s сделана с незакоммиченными изменениями.", candidate)
	}
	return d
}

// Offer reports whether a build is worth offering unprompted: both versions
// are known and candidate is strictly newer.
func Offer(current, candidate string) bool {
	cur, ok1 := Parse(current)
	cand, ok2 := Parse(candidate)
	return ok1 && ok2 && Compare(cur, cand) < 0
}
