// Package csp parses a Content-Security-Policy string and exposes the
// predicates the standard relies on. Per AG-NET-01, egress is the union of
// ALL fetch-directives, not just connect-src — so the lockdown predicates
// evaluate every directive that can pull a third-party resource.
package csp

import "strings"

// Policy maps lower-cased directive names to their source token lists.
type Policy struct {
	Present    bool
	Directives map[string][]string
}

// FetchDirectives are the directives that can cause network egress.
var FetchDirectives = []string{
	"default-src", "script-src", "script-src-elem", "script-src-attr",
	"style-src", "style-src-elem", "style-src-attr", "img-src", "font-src",
	"connect-src", "media-src", "object-src", "frame-src", "child-src",
	"worker-src", "manifest-src", "prefetch-src",
}

// Parse tokenises a CSP string. An empty string yields a not-present policy.
func Parse(s string) Policy {
	s = strings.TrimSpace(s)
	p := Policy{Directives: map[string][]string{}}
	if s == "" {
		return p
	}
	p.Present = true
	for _, part := range strings.Split(s, ";") {
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		vals := make([]string, 0, len(fields)-1)
		for _, v := range fields[1:] {
			vals = append(vals, strings.ToLower(v))
		}
		p.Directives[name] = vals
	}
	return p
}

func (p Policy) Has(directive string) bool {
	_, ok := p.Directives[strings.ToLower(directive)]
	return ok
}

// Effective returns the source list for a fetch-directive, falling back to
// default-src per the CSP spec when the directive is absent.
func (p Policy) Effective(directive string) ([]string, bool) {
	directive = strings.ToLower(directive)
	if v, ok := p.Directives[directive]; ok {
		return v, true
	}
	if v, ok := p.Directives["default-src"]; ok {
		return v, true
	}
	return nil, false
}

// SelfOnly reports whether a source list permits only first-party / inert
// origins ('self', 'none', data:, blob:) and nothing third-party.
func SelfOnly(vals []string) bool {
	for _, v := range vals {
		switch v {
		case "'none'", "'self'", "data:", "blob:", "mediastream:", "filesystem:":
			continue
		}
		return false // a host, scheme, '*', or an 'unsafe-*' keyword
	}
	return true
}

// HasUnsafe reports use of the dangerous script/style relaxations or wildcard.
func HasUnsafe(vals []string) bool {
	for _, v := range vals {
		switch v {
		case "'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'",
			"'wasm-unsafe-eval'", "*", "http:", "https:", "data:":
			return true
		}
	}
	return false
}

// ThirdPartyEgressDirectives returns the fetch-directives whose effective
// source list admits a third-party origin (the AG-NET-01 union check).
func (p Policy) ThirdPartyEgressDirectives() []string {
	var leaks []string
	for _, d := range FetchDirectives {
		vals, ok := p.Effective(d)
		if !ok {
			// No directive and no default-src => browser default is wide open.
			leaks = append(leaks, d+" (unset, no default-src)")
			continue
		}
		if !SelfOnly(vals) {
			leaks = append(leaks, d)
		}
	}
	return leaks
}

// ConnectLockedTo reports whether connect-src permits only 'none'/'self' plus
// the explicitly allowed origins (used for L0 'none' and L1 scoped egress).
func (p Policy) ConnectLockedTo(allowed []string) (bool, []string) {
	vals, ok := p.Effective("connect-src")
	if !ok {
		return false, []string{"connect-src unset and no default-src"}
	}
	allow := map[string]bool{"'none'": true, "'self'": true}
	for _, a := range allowed {
		allow[strings.ToLower(strings.TrimSpace(a))] = true
	}
	var bad []string
	for _, v := range vals {
		if !allow[v] {
			bad = append(bad, v)
		}
	}
	return len(bad) == 0, bad
}

// DenyByDefault reports whether default-src is 'none'/'self' and script-src
// carries no unsafe relaxation or wildcard.
func (p Policy) DenyByDefault() (bool, string) {
	def, ok := p.Directives["default-src"]
	if !ok {
		return false, "no default-src directive"
	}
	if !SelfOnly(def) {
		return false, "default-src is not 'none'/'self'"
	}
	if sv, ok := p.Directives["script-src"]; ok && HasUnsafe(sv) {
		return false, "script-src permits unsafe-inline/eval/wildcard"
	}
	return true, ""
}

// ReportEndpoints returns any report-uri / report-to targets declared inline.
func (p Policy) ReportEndpoints() []string {
	var out []string
	out = append(out, p.Directives["report-uri"]...)
	out = append(out, p.Directives["report-to"]...)
	return out
}
