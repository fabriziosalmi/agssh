package csp

import "testing"

func contains(vals []string, want string) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}

func TestParse(t *testing.T) {
	if p := Parse(""); p.Present {
		t.Error("empty string must be a not-present policy")
	}
	if p := Parse("   "); p.Present {
		t.Error("whitespace-only must be a not-present policy")
	}
	p := Parse("default-src 'self'; script-src 'self' https://CDN.example.com")
	if !p.Present {
		t.Fatal("non-empty policy must be present")
	}
	if !p.Has("script-src") || !p.Has("DEFAULT-SRC") {
		t.Error("Has must be case-insensitive and find declared directives")
	}
	if p.Has("img-src") {
		t.Error("Has must not report an undeclared directive")
	}
	// hosts are lower-cased on parse so comparisons are stable.
	if v, _ := p.Effective("script-src"); !contains(v, "https://cdn.example.com") {
		t.Errorf("source tokens should be lower-cased, got %v", v)
	}
}

func TestEffectiveFallsBackToDefaultSrc(t *testing.T) {
	p := Parse("default-src 'self'; img-src https://img.example.com")
	// explicit directive wins
	if v, ok := p.Effective("img-src"); !ok || !contains(v, "https://img.example.com") {
		t.Errorf("explicit img-src = %v ok=%v", v, ok)
	}
	// absent directive falls back to default-src (CSP spec semantics)
	if v, ok := p.Effective("font-src"); !ok || !SelfOnly(v) {
		t.Errorf("font-src should fall back to default-src 'self', got %v ok=%v", v, ok)
	}
	// no directive and no default-src => not resolvable
	if _, ok := Parse("script-src 'self'").Effective("img-src"); ok {
		t.Error("Effective must return false when neither the directive nor default-src exists")
	}
}

func TestSelfOnly(t *testing.T) {
	cases := []struct {
		vals []string
		want bool
	}{
		{[]string{"'self'"}, true},
		{[]string{"'none'"}, true},
		{[]string{"'self'", "data:", "blob:"}, true},
		{[]string{"'self'", "https://cdn.jsdelivr.net"}, false}, // third-party host
		{[]string{"https:"}, false},                             // bare scheme = any host
		{[]string{"*"}, false},
		{[]string{"'unsafe-inline'"}, false},
	}
	for _, c := range cases {
		if got := SelfOnly(c.vals); got != c.want {
			t.Errorf("SelfOnly(%v) = %v, want %v", c.vals, got, c.want)
		}
	}
}

func TestHasUnsafe(t *testing.T) {
	cases := []struct {
		vals []string
		want bool
	}{
		{[]string{"'self'", "'unsafe-eval'"}, true},
		{[]string{"'unsafe-inline'"}, true},
		{[]string{"'wasm-unsafe-eval'"}, true},
		{[]string{"*"}, true},
		{[]string{"https:"}, true}, // a bare scheme admits any host
		{[]string{"'self'", "'none'"}, false},
		{[]string{"'self'", "https://api.example.com"}, false}, // a named host is scoped, not "unsafe"
	}
	for _, c := range cases {
		if got := HasUnsafe(c.vals); got != c.want {
			t.Errorf("HasUnsafe(%v) = %v, want %v", c.vals, got, c.want)
		}
	}
}

// The load-bearing AG-NET-01 property: egress is the UNION across all
// fetch-directives, so a third party pulled by img-src is egress even when
// connect-src is locked to 'none'.
func TestThirdPartyEgressIsTheUnion(t *testing.T) {
	p := Parse("default-src 'none'; connect-src 'none'; img-src 'self' https://fonts.gstatic.com")
	leaks := p.ThirdPartyEgressDirectives()
	if !contains(leaks, "img-src") {
		t.Errorf("img-src third-party must be flagged despite connect-src 'none'; leaks=%v", leaks)
	}
	if contains(leaks, "connect-src") {
		t.Errorf("connect-src 'none' must not be flagged; leaks=%v", leaks)
	}

	// A fully locked policy leaks nothing.
	if leaks := Parse("default-src 'none'").ThirdPartyEgressDirectives(); len(leaks) != 0 {
		t.Errorf("default-src 'none' must leak nothing, got %v", leaks)
	}

	// No CSP at all: every fetch-directive is unset with no default-src => wide open.
	if leaks := Parse("").ThirdPartyEgressDirectives(); len(leaks) != len(FetchDirectives) {
		t.Errorf("absent policy must flag every fetch-directive, got %d/%d", len(leaks), len(FetchDirectives))
	}
}

func TestConnectLockedTo(t *testing.T) {
	p := Parse("connect-src 'self' https://api.example.com")
	if ok, bad := p.ConnectLockedTo([]string{"https://api.example.com"}); !ok || len(bad) != 0 {
		t.Errorf("allowlisted origin must be locked, ok=%v bad=%v", ok, bad)
	}
	if ok, bad := p.ConnectLockedTo(nil); ok || !contains(bad, "https://api.example.com") {
		t.Errorf("a non-allowlisted origin must break the lock, ok=%v bad=%v", ok, bad)
	}
	// L0: connect-src 'none' is locked under any (even empty) allowlist.
	if ok, _ := Parse("connect-src 'none'").ConnectLockedTo(nil); !ok {
		t.Error("connect-src 'none' must be locked")
	}
}

func TestDenyByDefault(t *testing.T) {
	if ok, _ := Parse("default-src 'none'").DenyByDefault(); !ok {
		t.Error("default-src 'none' must deny by default")
	}
	if ok, why := Parse("default-src https://example.com").DenyByDefault(); ok || why == "" {
		t.Error("a third-party default-src must not deny by default, with a reason")
	}
	if ok, _ := Parse("script-src 'self'").DenyByDefault(); ok {
		t.Error("absent default-src must not deny by default")
	}
	if ok, _ := Parse("default-src 'self'; script-src 'self' 'unsafe-inline'").DenyByDefault(); ok {
		t.Error("unsafe-inline in script-src must break deny-by-default")
	}
}
