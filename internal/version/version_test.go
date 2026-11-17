package version

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in    string
		ok    bool
		want  V
		isTag bool
	}{
		{"v0.1.0", true, V{Major: 0, Minor: 1, Patch: 0}, true},
		{"v1.22.333", true, V{Major: 1, Minor: 22, Patch: 333}, true},
		{"v0.1.0-5-gabc1234", true, V{Minor: 1, Commits: 5, Hash: "abc1234"}, false},
		{"v0.1.0-5-gabc1234-dirty", true, V{Minor: 1, Commits: 5, Hash: "abc1234", Dirty: true}, false},
		{"v0.1.0-dirty", true, V{Minor: 1, Dirty: true}, false},
		{"dev", false, V{}, false},
		{"abc1234", false, V{}, false},
		{"abc1234-dirty", false, V{}, false},
		{"", false, V{}, false},
		{"0.1.0", false, V{}, false},
		{"v0.1", false, V{}, false},
		{"v0.1.0-rc1", false, V{}, false},
		{"v0.1.0-5-gXYZ", false, V{}, false},
	}
	for _, c := range cases {
		got, ok := Parse(c.in)
		if ok != c.ok {
			t.Errorf("%q: ok=%v want %v", c.in, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		c.want.Raw = c.in
		if got != c.want {
			t.Errorf("%q: %+v want %+v", c.in, got, c.want)
		}
		if got.Tag() != c.isTag {
			t.Errorf("%q: Tag()=%v", c.in, got.Tag())
		}
	}
}

func TestCompareAndDecide(t *testing.T) {
	type tc struct {
		cur, cand string
		allowed   bool
		confirm   bool
		offer     bool
	}
	for _, c := range []tc{
		{"v0.1.0", "v0.1.1", true, false, true},
		{"v0.1.9", "v0.2.0", true, false, true},
		{"v0.9.9", "v1.0.0", true, false, true},
		{"v0.1.0", "v0.1.0-5-gabc1234", true, false, true},
		{"v0.1.0-5-gabc1234", "v0.1.0-7-gdef5678", true, false, true},
		{"v0.1.0-5-gabc1234", "v0.1.1", true, false, true},
		{"v0.1.0", "v0.1.0", false, false, false},
		{"v0.1.0-5-gabc1234", "v0.1.0-5-gabc1234", false, false, false},
		{"v0.1.1", "v0.1.0", false, false, false},
		{"v0.1.0-5-gabc1234", "v0.1.0", false, false, false},
		{"v0.2.0", "v0.1.9-40-gabc1234", false, false, false},
		// dirty candidate: same number is a manual install with a warning
		{"v0.1.0-5-gabc1234", "v0.1.0-5-gabc1234-dirty", true, true, false},
		{"v0.1.0-5-gabc1234", "v0.1.0-6-gdef5678-dirty", true, true, true},
		{"v0.1.0-5-gabc1234", "v0.1.0-4-gdef5678-dirty", false, false, false},
		// unknown versions need a confirmation
		{"dev", "v0.1.0", true, true, false},
		{"v0.1.0", "dev", true, true, false},
		{"v0.1.0", "abc1234", true, true, false},
		{"dev", "dev", true, true, false},
	} {
		d := Decide(c.cur, c.cand)
		if d.Allowed != c.allowed || d.Confirm != c.confirm {
			t.Errorf("Decide(%q, %q) = %+v; want allowed=%v confirm=%v", c.cur, c.cand, d, c.allowed, c.confirm)
		}
		if !d.Allowed && d.Reason == "" || d.Confirm && d.Warning == "" {
			t.Errorf("Decide(%q, %q): no explanation: %+v", c.cur, c.cand, d)
		}
		if got := Offer(c.cur, c.cand); got != c.offer {
			t.Errorf("Offer(%q, %q) = %v", c.cur, c.cand, got)
		}
	}
}

func TestCompareIgnoresDirty(t *testing.T) {
	a, _ := Parse("v1.2.3-4-gabcdef0")
	b, _ := Parse("v1.2.3-4-g1234567-dirty")
	if Compare(a, b) != 0 || Compare(b, a) != 0 {
		t.Fatal("same number must compare equal")
	}
}
