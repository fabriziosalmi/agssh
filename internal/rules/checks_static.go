package rules

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/fabriziosalmi/agssh/internal/csp"
	"github.com/fabriziosalmi/agssh/internal/httpx"
	"golang.org/x/net/html"
)

// ---------- shared helpers ----------

func docPolicy(d *httpx.Doc) (pol csp.Policy, viaHeader bool) {
	if h := d.HeaderCSP(); h != "" {
		return csp.Parse(h), true
	}
	if m := d.MetaCSP(); m != "" {
		return csp.Parse(m), false
	}
	return csp.Parse(""), false
}

type htmlEl struct {
	tag  string
	attr map[string]string
}

func collectEls(body []byte, tags ...string) []htmlEl {
	want := map[string]bool{}
	for _, t := range tags {
		want[t] = true
	}
	z := html.NewTokenizer(bytes.NewReader(body))
	var out []htmlEl
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
			name, hasAttr := z.TagName()
			tag := string(name)
			if want[tag] {
				m := map[string]string{}
				for hasAttr {
					k, v, more := z.TagAttr()
					m[strings.ToLower(string(k))] = string(v)
					hasAttr = more
				}
				out = append(out, htmlEl{tag, m})
			}
		}
	}
	return out
}

func isExternal(surfaceURL, ref string) bool {
	ref = strings.TrimSpace(ref)
	if !strings.HasPrefix(strings.ToLower(ref), "http") && !strings.HasPrefix(ref, "//") {
		return false // relative => same-origin
	}
	return !httpx.SameHost(surfaceURL, ref)
}

var (
	analyticsRe = regexp.MustCompile(`googletagmanager|google-analytics|gtag\s*\(|\b_gaq\b|\bG-[A-Z0-9]{10}\b|\bUA-[0-9]{4,}-[0-9]{1,4}\b`)
	fontHostRe  = regexp.MustCompile(`(?i)fonts\.(googleapis|gstatic)\.com`)
	cdnLoaderRe = regexp.MustCompile(`(?i)cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|esm\.sh|skypack\.dev|cdn\.tiny\.cloud|tessdata`)
	maxAgeRe    = regexp.MustCompile(`(?i)max-age\s*=\s*(\d+)`)
)

// ---------- CSP / egress ----------

// AG-NET-01: every fetch-directive except connect-src is first-party only.
func chkSelfHostAll(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	pol, _ := docPolicy(c.Doc)
	if !pol.Present {
		return bad("no CSP", "a CSP locking all fetch-directives to 'self'/'none'")
	}
	var leaks []string
	for _, d := range csp.FetchDirectives {
		if d == "connect-src" {
			continue // governed by AG-NET-04
		}
		if vals, ok := pol.Effective(d); ok && !csp.SelfOnly(vals) {
			leaks = append(leaks, d)
		}
	}
	if len(leaks) > 0 {
		return bad("third-party origins in: "+strings.Join(leaks, ", "), "all fetch-directives 'self'/'none'")
	}
	return okay("no third-party fetch-directive", "")
}

// AG-NET-02: no default CDN loader hosts referenced in the page.
func chkNoCDNLoaders(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	if m := cdnLoaderRe.FindString(string(c.Doc.Body)); m != "" {
		return bad("references CDN loader: "+m, "self-hosted assets only")
	}
	return okay("no public CDN loader references", "")
}

// AG-NET-03: worker-src is first-party only.
func chkWorkerSrc(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	pol, _ := docPolicy(c.Doc)
	if vals, ok := pol.Effective("worker-src"); ok {
		if csp.SelfOnly(vals) {
			return okay("worker-src self-only", "")
		}
		return bad("worker-src allows third-party", "worker-src 'self'/'none'")
	}
	return bad("worker-src and default-src unset", "worker-src 'self'/'none'")
}

// AG-NET-04: connect-src 'none' (L0) or only the declared allow-list (L1).
func chkConnectSrc(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	pol, _ := docPolicy(c.Doc)
	allowed := []string{}
	if c.Level >= 1 { // L1/L2 may scope egress
		allowed = c.Allow.Connect
	}
	ok, badVals := pol.ConnectLockedTo(allowed)
	if ok {
		return okay("connect-src locked", "")
	}
	return bad("connect-src admits: "+strings.Join(badVals, ", "), "connect-src 'none' or declared allow-list only")
}

// AG-NET-06: no <link rel=preconnect|dns-prefetch> to third-party origins.
func chkNoPriming(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	for _, e := range collectEls(c.Doc.Body, "link") {
		rel := strings.ToLower(e.attr["rel"])
		if strings.Contains(rel, "preconnect") || strings.Contains(rel, "dns-prefetch") {
			if isExternal(c.Doc.FinalURL, e.attr["href"]) {
				return bad("primes third-party: "+e.attr["href"], "no third-party preconnect/dns-prefetch")
			}
		}
	}
	return okay("no third-party connection priming", "")
}

// AG-NET-08: any declared CSP report endpoint is same-origin.
func chkReportSameOrigin(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	pol, _ := docPolicy(c.Doc)
	eps := pol.ReportEndpoints()
	for _, ep := range eps {
		if isExternal(c.Doc.FinalURL, ep) {
			return bad("cross-origin report endpoint: "+ep, "same-origin reporting only")
		}
	}
	return okay("reporting same-origin (or none)", "")
}

// AG-NET-09: external target=_blank links must sever window.opener — satisfied
// by rel containing 'noopener' OR 'noreferrer' (noreferrer implies noopener per
// the HTML spec). On privacy surfaces, rel must ALSO contain 'noreferrer'.
func chkNoopener(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	privacy := c.Surface.IsPrivacy()
	for _, e := range collectEls(c.Doc.Body, "a") {
		if !strings.EqualFold(e.attr["target"], "_blank") || !isExternal(c.Doc.FinalURL, e.attr["href"]) {
			continue
		}
		rel := strings.ToLower(e.attr["rel"])
		hasNoopener := strings.Contains(rel, "noopener")
		hasNoreferrer := strings.Contains(rel, "noreferrer")
		if !hasNoopener && !hasNoreferrer {
			return bad("external _blank exposes opener: "+e.attr["href"], "rel contains 'noopener' or 'noreferrer'")
		}
		if privacy && !hasNoreferrer {
			return bad("privacy surface leaks referrer: "+e.attr["href"], "rel also contains 'noreferrer' on privacy surfaces")
		}
	}
	return okay("external _blank links sever the opener (and referrer on privacy surfaces)", "")
}

// AG-CSP-01: a CSP is shipped (header or meta).
func chkCSPPresent(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	pol, viaHeader := docPolicy(c.Doc)
	if !pol.Present {
		return bad("no Content-Security-Policy", "a CSP via HTTP header (Tier A) or meta (Tier B)")
	}
	tier := "Tier B (meta)"
	if viaHeader {
		tier = "Tier A (header)"
	}
	return okay("CSP present — "+tier, "")
}

// AG-CSP-02: deny-by-default; no unsafe relaxations.
func chkDenyDefault(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	pol, _ := docPolicy(c.Doc)
	if !pol.Present {
		return bad("no CSP", "default-src 'none'/'self', no unsafe-inline/eval")
	}
	if ok, why := pol.DenyByDefault(); !ok {
		return bad(why, "default-src 'none'/'self'; no unsafe-inline/eval/wildcard")
	}
	return okay("deny-by-default", "")
}

// AG-CSP-03: clickjacking control is header-delivered (Tier A) or structural
// (Tier D: a stateless surface). Meta frame-ancestors is ineffective.
func chkClickjack(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	if xfo := c.Doc.Header.Get("X-Frame-Options"); xfo != "" {
		return okay("X-Frame-Options header (Tier A): "+xfo, "")
	}
	if h := c.Doc.HeaderCSP(); h != "" {
		if hp := csp.Parse(h); hp.Has("frame-ancestors") {
			return okay("header CSP frame-ancestors (Tier A)", "")
		}
	}
	if c.Surface.Stateless {
		return Outcome{Status: Pass, Evidence: Evidence{
			Observed: "stateless surface (Tier D): no clickjacking impact",
			Detail:   map[string]any{"tier": "D", "compensating": "statelessness"}}}
	}
	return bad("no header-delivered anti-framing; surface not declared stateless",
		"X-Frame-Options or header CSP frame-ancestors (Tier A), or stateless=true (Tier D)")
}

// AG-CSP-05: force HTTPS subresources.
func chkUpgradeInsecure(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	pol, _ := docPolicy(c.Doc)
	if pol.Has("upgrade-insecure-requests") {
		return okay("upgrade-insecure-requests set", "")
	}
	return bad("no upgrade-insecure-requests", "upgrade-insecure-requests, or all sources https")
}

// AG-CSP-06: Trusted Types required for DOM sinks.
func chkTrustedTypes(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	pol, _ := docPolicy(c.Doc)
	if vals, ok := pol.Effective("require-trusted-types-for"); ok {
		for _, v := range vals {
			if v == "'script'" {
				return okay("require-trusted-types-for 'script'", "")
			}
		}
	}
	return bad("Trusted Types not required", "require-trusted-types-for 'script'")
}

// ---------- headers ----------

func chkHSTS(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	h := c.Doc.Header.Get("Strict-Transport-Security")
	if h == "" {
		return bad("no Strict-Transport-Security", "max-age>=31536000")
	}
	m := maxAgeRe.FindStringSubmatch(h)
	if len(m) == 2 {
		if n, _ := strconv.Atoi(m[1]); n >= 31536000 {
			return okay(fmt.Sprintf("HSTS max-age=%d", n), "")
		} else if n == 0 {
			return bad("HSTS max-age=0 (disabled)", "max-age>=31536000")
		} else {
			return bad(fmt.Sprintf("HSTS max-age=%d (too low)", n), "max-age>=31536000")
		}
	}
	return bad("HSTS without parseable max-age", "max-age>=31536000")
}

func chkHSTSScope(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	h := strings.ToLower(c.Doc.Header.Get("Strict-Transport-Security"))
	if h == "" {
		return bad("no HSTS to scope", "HSTS present (see AG-HDR-01)")
	}
	if strings.Contains(h, "preload") && !strings.Contains(h, "includesubdomains") {
		return bad("preload without includeSubDomains", "preload requires includeSubDomains and all subdomains on HTTPS")
	}
	return okay("HSTS scope consistent", "")
}

func chkNosniff(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	if strings.EqualFold(c.Doc.Header.Get("X-Content-Type-Options"), "nosniff") {
		return okay("nosniff", "")
	}
	return bad("X-Content-Type-Options not nosniff", "X-Content-Type-Options: nosniff")
}

func chkXFO(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	if v := c.Doc.Header.Get("X-Frame-Options"); v != "" {
		return okay("X-Frame-Options: "+v, "")
	}
	if h := c.Doc.HeaderCSP(); h != "" && csp.Parse(h).Has("frame-ancestors") {
		return okay("header CSP frame-ancestors", "")
	}
	return bad("no X-Frame-Options / header frame-ancestors", "X-Frame-Options: DENY or header frame-ancestors")
}

func chkReferrer(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	v := strings.ToLower(c.Doc.Header.Get("Referrer-Policy"))
	switch v {
	case "no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin":
		return okay("Referrer-Policy: "+v, "")
	case "":
		return bad("no Referrer-Policy", "no-referrer / same-origin / strict-origin")
	}
	return bad("weak Referrer-Policy: "+v, "no-referrer / same-origin / strict-origin")
}

func chkPermissionsPolicy(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	if c.Doc.Header.Get("Permissions-Policy") != "" {
		return okay("Permissions-Policy set", "")
	}
	return bad("no Permissions-Policy", "Permissions-Policy denying unused features")
}

// AG-HDR-06: cross-origin isolation for threaded WASM (only when applicable).
func chkCOIso(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	coop := strings.ToLower(c.Doc.Header.Get("Cross-Origin-Opener-Policy"))
	coep := strings.ToLower(c.Doc.Header.Get("Cross-Origin-Embedder-Policy"))
	if coop == "same-origin" && (coep == "require-corp" || coep == "credentialless") {
		return okay("COOP/COEP isolated", "")
	}
	return bad(fmt.Sprintf("COOP=%q COEP=%q", coop, coep), "COOP: same-origin + COEP: require-corp")
}

// ---------- privacy ----------

func chkZeroTelemetry(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	if m := analyticsRe.FindString(string(c.Doc.Body)); m != "" {
		return bad("analytics marker present: "+m, "no analytics/telemetry at L0/L1")
	}
	return okay("no analytics markers", "")
}

func chkSelfHostFonts(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	if m := fontHostRe.FindString(string(c.Doc.Body)); m != "" {
		return bad("third-party font host: "+m, "self-hosted fonts only")
	}
	return okay("fonts self-hosted", "")
}

func chkCookieAttrs(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	cookies := c.Doc.Header.Values("Set-Cookie")
	for _, ck := range cookies {
		l := strings.ToLower(ck)
		if !strings.Contains(l, "secure") || !strings.Contains(l, "httponly") || !strings.Contains(l, "samesite") {
			return bad("cookie missing Secure/HttpOnly/SameSite: "+strings.SplitN(ck, ";", 2)[0],
				"Secure; HttpOnly; SameSite on every cookie")
		}
	}
	return okay(fmt.Sprintf("%d cookies, all hardened", len(cookies)), "")
}

func chkEmbedsSandboxed(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	for _, e := range collectEls(c.Doc.Body, "iframe") {
		if _, ok := e.attr["sandbox"]; !ok {
			return bad("iframe without sandbox: "+e.attr["src"], "every iframe carries a restrictive sandbox")
		}
	}
	return okay("iframes sandboxed (or none)", "")
}

// AG-SUP-01: cross-origin subresources carry Subresource Integrity.
func chkSRI(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	for _, e := range collectEls(c.Doc.Body, "script") {
		if isExternal(c.Doc.FinalURL, e.attr["src"]) && strings.TrimSpace(e.attr["integrity"]) == "" {
			return bad("cross-origin script without integrity: "+e.attr["src"], "integrity + crossorigin on every cross-origin subresource")
		}
	}
	for _, e := range collectEls(c.Doc.Body, "link") {
		if strings.Contains(strings.ToLower(e.attr["rel"]), "stylesheet") &&
			isExternal(c.Doc.FinalURL, e.attr["href"]) && strings.TrimSpace(e.attr["integrity"]) == "" {
			return bad("cross-origin stylesheet without integrity: "+e.attr["href"], "integrity on cross-origin stylesheets")
		}
	}
	return okay("cross-origin subresources pinned (or none)", "")
}
