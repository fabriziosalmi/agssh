package rules

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/fabriziosalmi/agssh/internal/csp"
	"github.com/fabriziosalmi/agssh/internal/httpx"
	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"
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

// sameSite reports whether ref sits under the SAME registrable domain (eTLD+1) as the
// surface — the operator's own subdomain, not a third party.
//
// This never changes a verdict: cross-origin egress is still egress, the browser still
// resolves and connects to another host, and at L0 that is a violation either way. It
// changes what the finding SAYS. Reporting `radio.example.org` on `example.org` as a
// "third-party CDN" is simply false, and this text ships in customer-facing reports —
// a reviewer who spots one false statement discounts the whole report.
func sameSite(surfaceURL, ref string) bool {
	hs, ho := httpx.HostOf(surfaceURL), httpx.HostOf(ref)
	if hs == "" || ho == "" {
		return false
	}
	ds, err1 := publicsuffix.EffectiveTLDPlusOne(strings.ToLower(hs))
	do, err2 := publicsuffix.EffectiveTLDPlusOne(strings.ToLower(ho))
	if err1 != nil || err2 != nil {
		return false // unknown suffix (IP literal, intranet name) — don't guess
	}
	return ds == do
}

// embedTags load another BROWSING CONTEXT rather than a subresource of this one: they
// execute in their own origin, are sandbox-able, and CSP governs them through frame-src,
// not script-src. An <iframe src="youtube.com"> on a page whose purpose is embedding a
// video is a different claim from a <script src="cdn"> that runs in this origin — and
// AG-NET-02's own title ("Override library default CDN loaders") is about the latter.
// Both still fail the air-gap requirement; only the wording and the remedy differ.
var embedTags = map[string]bool{"iframe": true, "embed": true, "object": true}

var (
	analyticsRe = regexp.MustCompile(`googletagmanager|google-analytics|gtag\s*\(|\b_gaq\b|\bG-[A-Z0-9]{10}\b|\bUA-[0-9]{4,}-[0-9]{1,4}\b`)
	// fontFaceURLRe matches a CSS url() that points at a font FILE — a real
	// @font-face source, never prose (prose does not write url(…/x.woff2)). The
	// scheme is optional so protocol-relative sources (url(//cdn/x.woff2)) match.
	fontFaceURLRe = regexp.MustCompile(`(?i)url\(\s*['"]?((?:https?:)?//[^)'"\s]+\.(?:woff2?|ttf|otf|eot))`)
	maxAgeRe      = regexp.MustCompile(`(?i)max-age\s*=\s*(\d+)`)
)

// subresourceRefs walks the HTML and returns the (tag, url) pairs of every
// element that can trigger a subresource fetch. Attributes covered:
//
//	<script src>                                  code
//	<link rel=stylesheet|preload|modulepreload|prefetch href>   assets
//	<img src>, <img srcset>                                     images
//	<iframe src>, <embed src>, <object data>                    frames/objects
//	<video src>, <audio src>, <source src>, <track src>         media
//
// The rewrite intentionally does NOT try to enumerate every possible loader
// (no runtime JS analysis) — but it covers the surface a static check can
// meaningfully make claims about, replacing the previous substring blocklist.
func subresourceRefs(body []byte) []struct{ Tag, URL string } {
	tags := []string{"script", "link", "img", "iframe", "embed", "object", "video", "audio", "source", "track"}
	var refs []struct{ Tag, URL string }
	push := func(tag, url string) {
		url = strings.TrimSpace(url)
		if url != "" {
			refs = append(refs, struct{ Tag, URL string }{tag, url})
		}
	}
	for _, e := range collectEls(body, tags...) {
		switch e.tag {
		case "script", "img", "iframe", "embed", "video", "audio", "source", "track":
			push(e.tag, e.attr["src"])
			if e.tag == "img" && e.attr["srcset"] != "" {
				for _, s := range strings.Split(e.attr["srcset"], ",") {
					url := strings.TrimSpace(s)
					if sp := strings.IndexAny(url, " \t"); sp >= 0 {
						url = url[:sp] // strip the descriptor (e.g. "1x")
					}
					push(e.tag, url)
				}
			}
		case "object":
			push(e.tag, e.attr["data"])
		case "link":
			// Only rels that actually fetch a resource.
			if relHas(e.attr["rel"], "stylesheet") ||
				relHas(e.attr["rel"], "modulepreload") ||
				relHas(e.attr["rel"], "preload") ||
				relHas(e.attr["rel"], "prefetch") ||
				relHas(e.attr["rel"], "icon") {
				push(e.tag, e.attr["href"])
			}
		}
	}
	return refs
}

// ---------- CSP / egress ----------

// AG-NET-01: every fetch-directive except connect-src is first-party only.
// A directive that is neither explicitly set nor covered by default-src is a
// leak too — the browser's initial value for most fetch-directives is wide
// open (*), so "unset" is not "safe". connect-src is scoped by AG-NET-04.
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
		vals, ok := pol.Effective(d)
		if !ok {
			leaks = append(leaks, d+" (unset, no default-src)")
			continue
		}
		if !csp.SelfOnly(vals) {
			leaks = append(leaks, d)
		}
	}
	if len(leaks) > 0 {
		return bad("third-party origins in: "+strings.Join(leaks, ", "), "all fetch-directives 'self'/'none'")
	}
	return okay("no third-party fetch-directive", "")
}

// hostAllowed reports whether host is in the allow-list (case-insensitive
// exact match). No wildcard semantics — an allow-list for a security check
// should be explicit.
func hostAllowed(host string, allow []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, a := range allow {
		if strings.ToLower(strings.TrimSpace(a)) == host {
			return true
		}
	}
	return false
}

// AG-NET-02: no external subresource loaders. The previous implementation
// substring-matched seven CDN hostnames against the raw body — false-positive
// on prose ("do not use cdn.jsdelivr.net"), false-negative on every CDN not
// in the hardcoded list, and blind to runtime-injected URLs. Replaced with an
// HTML-aware enumerator of every element that triggers a subresource fetch:
// any cross-origin URL is a leak.
//
// Level gate: at L0 (strict air-gap) zero external subresources tolerated. At
// L1+ (scoped egress) manifest.Allow.Subresources may exempt specific hosts.
func chkNoCDNLoaders(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	allow := []string(nil)
	if c.Level >= 1 {
		allow = c.Allow.Subresources
	}
	for _, r := range subresourceRefs(c.Doc.Body) {
		if !isExternal(c.Doc.FinalURL, r.URL) {
			continue
		}
		if hostAllowed(httpx.HostOf(r.URL), allow) {
			continue
		}
		kind, remedy := "subresource", "self-hosted assets only (or an explicit allow.subresources entry at L1+)"
		if embedTags[r.Tag] {
			kind = "document embed"
			remedy = "self-host the embedded document, or declare its host in allow.subresources at L1+"
		}
		party := "third-party"
		if sameSite(c.Doc.FinalURL, r.URL) {
			party = "cross-origin same-site (own registrable domain)"
			remedy = "serve it same-origin, or declare the subdomain in allow.subresources at L1+"
		}
		return bad(party+" "+kind+" <"+r.Tag+">: "+r.URL, remedy)
	}
	return okay("no external subresource loaders", "")
}

// AG-NET-03: worker-src is first-party only. Per CSP L3 §6.1 worker-src falls
// back to child-src, then script-src, then default-src — NOT straight to
// default-src. A policy like `default-src 'none'; script-src https://cdn.evil`
// resolves worker-src to script-src (third-party), which the plain Effective()
// would miss.
func chkWorkerSrc(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	pol, _ := docPolicy(c.Doc)
	if vals, ok := pol.EffectiveWithFallback("worker-src"); ok {
		if csp.SelfOnly(vals) {
			return okay("worker-src self-only", "")
		}
		return bad("worker-src allows third-party (via spec fallback chain)", "worker-src 'self'/'none'")
	}
	return bad("worker-src unresolvable: neither worker-src, child-src, script-src, nor default-src is set", "worker-src 'self'/'none'")
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

// relHas reports whether the space-separated rel token list contains want as
// a whole token (not a substring). Case-insensitive per the HTML rel spec.
func relHas(rel, want string) bool {
	want = strings.ToLower(want)
	for _, t := range strings.Fields(strings.ToLower(rel)) {
		if t == want {
			return true
		}
	}
	return false
}

// parseLinkHeader extracts (uri, rel) pairs from RFC 8288 Link headers. Each
// header value may carry multiple comma-separated links. Missing quotes on
// rel are tolerated ('rel=preconnect' and 'rel="preconnect"' both match).
func parseLinkHeader(vals []string) []struct{ URI, Rel string } {
	var out []struct{ URI, Rel string }
	for _, v := range vals {
		for _, link := range splitLinkValue(v) {
			link = strings.TrimSpace(link)
			if !strings.HasPrefix(link, "<") {
				continue
			}
			end := strings.Index(link, ">")
			if end < 0 {
				continue
			}
			uri := link[1:end]
			var rel string
			for _, param := range strings.Split(link[end+1:], ";") {
				param = strings.TrimSpace(param)
				const p = "rel="
				if strings.HasPrefix(strings.ToLower(param), p) {
					rel = strings.Trim(param[len(p):], `"'`)
					break
				}
			}
			out = append(out, struct{ URI, Rel string }{uri, rel})
		}
	}
	return out
}

// splitLinkValue splits a Link header value on commas outside <...>.
func splitLinkValue(v string) []string {
	var out []string
	depth := 0
	start := 0
	for i, r := range v {
		switch r {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				out = append(out, v[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, v[start:])
	return out
}

// AG-NET-06: no priming of third-party origins. Priming can be delivered via
// <link rel=preconnect|dns-prefetch> in the HTML body OR via the HTTP Link
// header (RFC 8288). Missing the header-delivered form is a real bypass: a
// server can prime any origin without touching the HTML.
func chkNoPriming(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	for _, e := range collectEls(c.Doc.Body, "link") {
		rel := e.attr["rel"]
		if relHas(rel, "preconnect") || relHas(rel, "dns-prefetch") {
			if isExternal(c.Doc.FinalURL, e.attr["href"]) {
				return bad("primes third-party (HTML): "+e.attr["href"], "no third-party preconnect/dns-prefetch")
			}
		}
	}
	for _, link := range parseLinkHeader(c.Doc.Header.Values("Link")) {
		if relHas(link.Rel, "preconnect") || relHas(link.Rel, "dns-prefetch") {
			if isExternal(c.Doc.FinalURL, link.URI) {
				return bad("primes third-party (Link header): "+link.URI, "no third-party preconnect/dns-prefetch")
			}
		}
	}
	return okay("no third-party connection priming", "")
}

// reportingEndpoints walks the three places a browser reads endpoint URLs:
//
//  1. CSP `report-uri` — a list of URLs directly. (Legacy but widely deployed.)
//  2. HTTP `Reporting-Endpoints` header — key=url pairs (structured-fields).
//  3. HTTP `Report-To` header — JSON with `endpoints:[{url:...}]` per group.
//
// CSP `report-to <group>` is a NAME, not a URL, and cannot itself be judged
// same-origin — its URLs live in (2) or (3). Prior implementation treated
// group names as URLs, which is a silent bypass: an external endpoint declared
// under Reporting-Endpoints was never inspected.
func reportingEndpoints(pol csp.Policy, h http.Header) []string {
	var eps []string
	// (1) report-uri values ARE URLs.
	eps = append(eps, pol.Directives["report-uri"]...)
	// (2) Reporting-Endpoints: name="uri", name2="uri2"
	for _, v := range h.Values("Reporting-Endpoints") {
		for _, pair := range splitTopLevel(v, ',') {
			if eq := strings.Index(pair, "="); eq >= 0 {
				uri := strings.Trim(strings.TrimSpace(pair[eq+1:]), `"'`)
				if uri != "" {
					eps = append(eps, uri)
				}
			}
		}
	}
	// (3) Report-To: JSON groups; endpoints[].url
	for _, v := range h.Values("Report-To") {
		for _, group := range splitTopLevel(v, ',') {
			var g struct {
				Endpoints []struct {
					URL string `json:"url"`
				} `json:"endpoints"`
			}
			if err := json.Unmarshal([]byte(strings.TrimSpace(group)), &g); err != nil {
				continue
			}
			for _, e := range g.Endpoints {
				if e.URL != "" {
					eps = append(eps, e.URL)
				}
			}
		}
	}
	return eps
}

// splitTopLevel splits s on sep at depth 0 (not inside {…} or [...]).
func splitTopLevel(s string, sep rune) []string {
	var out []string
	depth := 0
	start := 0
	for i, r := range s {
		switch r {
		case '{', '[':
			depth++
		case '}', ']':
			if depth > 0 {
				depth--
			}
		case sep:
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

// AG-NET-08: every declared reporting endpoint is same-origin. Considers
// CSP report-uri (URLs), the Reporting-Endpoints header, and the legacy
// Report-To header. The CSP `report-to` directive carries GROUP NAMES that
// resolve via those headers — it is not treated as a URL source.
func chkReportSameOrigin(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	pol, _ := docPolicy(c.Doc)
	for _, ep := range reportingEndpoints(pol, c.Doc.Header) {
		if isExternal(c.Doc.FinalURL, ep) {
			return bad("cross-origin report endpoint: "+ep, "same-origin reporting only")
		}
	}
	return okay("reporting same-origin (or none)", "")
}

// AG-NET-09: external target=_blank openers must sever window.opener —
// satisfied by rel containing 'noopener' OR 'noreferrer' (noreferrer implies
// noopener per the HTML spec). On privacy surfaces, rel must ALSO contain
// 'noreferrer'. Applies to <a> AND <form> — form submissions with target=_blank
// leak window.opener via the same mechanism (HTML §form-submission-algorithm).
func chkNoopener(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	privacy := c.Surface.IsPrivacy()

	// hrefAttr returns the URL-carrying attribute for each opener element.
	hrefAttr := func(tag string) string {
		if tag == "form" {
			return "action"
		}
		return "href"
	}

	for _, e := range collectEls(c.Doc.Body, "a", "form") {
		href := e.attr[hrefAttr(e.tag)]
		if !strings.EqualFold(e.attr["target"], "_blank") || !isExternal(c.Doc.FinalURL, href) {
			continue
		}
		rel := e.attr["rel"]
		hasNoopener := relHas(rel, "noopener")
		hasNoreferrer := relHas(rel, "noreferrer")
		if !hasNoopener && !hasNoreferrer {
			return bad("external _blank exposes opener ("+e.tag+"): "+href, "rel contains 'noopener' or 'noreferrer'")
		}
		if privacy && !hasNoreferrer {
			return bad("privacy surface leaks referrer ("+e.tag+"): "+href, "rel also contains 'noreferrer' on privacy surfaces")
		}
	}
	return okay("external _blank openers sever the opener (and referrer on privacy surfaces)", "")
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

// chkSelfHostFonts (AG-PRV-03) flags fonts loaded from a third party. It is
// HTML-aware: it inspects the actual font-loading constructs — a stylesheet /
// preconnect to a known font CDN, a cross-origin `<link rel=preload as=font>`,
// and `@font-face` src URLs pointing at a cross-origin font file — rather than
// substring-matching the body (which false-positived on any page whose prose
// merely mentions a font host, e.g. the AGSSH standard document itself).
func chkSelfHostFonts(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	surfaceHost := httpx.HostOf(c.Doc.FinalURL)
	// hostOf tolerates protocol-relative refs (//host/…), which HostOf alone
	// reports as an empty host — otherwise a scheme-relative font CDN slips past.
	hostOf := func(u string) string {
		if strings.HasPrefix(strings.TrimSpace(u), "//") {
			u = "https:" + strings.TrimSpace(u)
		}
		return httpx.HostOf(u)
	}
	for _, e := range collectEls(c.Doc.Body, "link") {
		href := e.attr["href"]
		if href == "" {
			continue
		}
		host := hostOf(href)
		rel := e.attr["rel"]
		switch {
		case relHas(rel, "stylesheet") && isFontProvider(host):
			return bad("third-party font stylesheet: "+href, "self-hosted fonts only")
		case (relHas(rel, "preconnect") || relHas(rel, "dns-prefetch")) && isFontProvider(host):
			return bad("preconnect to third-party font host: "+host, "self-hosted fonts only")
		case relHas(rel, "preload") && strings.EqualFold(e.attr["as"], "font") && host != "" && host != surfaceHost:
			return bad("preloaded cross-origin font: "+href, "self-hosted fonts only")
		}
	}
	for _, m := range fontFaceURLRe.FindAllStringSubmatch(string(c.Doc.Body), -1) {
		if host := hostOf(m[1]); host != "" && host != surfaceHost {
			return bad("@font-face from third party: "+m[1], "self-hosted fonts only")
		}
	}
	return okay("fonts self-hosted", "")
}

// isFontProvider reports whether host is a well-known third-party font CDN.
func isFontProvider(host string) bool {
	host = strings.ToLower(host)
	for _, p := range []string{
		"fonts.googleapis.com", "fonts.gstatic.com", "fonts.bunny.net",
		"use.typekit.net", "use.fontawesome.com", "fast.fonts.net", "cloud.typography.com",
	} {
		if host == p || strings.HasSuffix(host, "."+p) {
			return true
		}
	}
	return false
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

// validSRIToken reports whether v is a syntactically valid
// hash-algorithm-base64 SRI token. `integrity` may carry multiple
// space-separated tokens; at least one must be well-formed for the browser to
// enforce.
var sriTokenRe = regexp.MustCompile(`^sha(256|384|512)-[A-Za-z0-9+/]+={0,2}$`)

func hasValidSRIToken(integrity string) bool {
	for _, t := range strings.Fields(strings.TrimSpace(integrity)) {
		if sriTokenRe.MatchString(t) {
			return true
		}
	}
	return false
}

// AG-SUP-01: cross-origin subresources carry ENFORCEABLE Subresource
// Integrity. Enforcement requires all of: (a) a syntactically valid
// integrity token, (b) a `crossorigin` attribute so the browser fetches CORS
// mode and the response is not opaque — without it, the integrity check is
// bypassed and the SRI is decorative.
//
// Coverage: <script src>, <link rel=stylesheet>, <link rel=modulepreload>,
// <link rel=preload as=script|style>.
func chkSRI(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	type sub struct {
		kind, url, integrity, crossorigin string
	}
	var subs []sub

	for _, e := range collectEls(c.Doc.Body, "script") {
		if src := e.attr["src"]; src != "" && isExternal(c.Doc.FinalURL, src) {
			subs = append(subs, sub{"script", src, e.attr["integrity"], e.attr["crossorigin"]})
		}
	}
	for _, e := range collectEls(c.Doc.Body, "link") {
		rel := e.attr["rel"]
		href := e.attr["href"]
		if href == "" || !isExternal(c.Doc.FinalURL, href) {
			continue
		}
		switch {
		case relHas(rel, "stylesheet"):
			subs = append(subs, sub{"stylesheet", href, e.attr["integrity"], e.attr["crossorigin"]})
		case relHas(rel, "modulepreload"):
			subs = append(subs, sub{"modulepreload", href, e.attr["integrity"], e.attr["crossorigin"]})
		case relHas(rel, "preload"):
			// preload only carries SRI meaningfully for script/style.
			switch strings.ToLower(e.attr["as"]) {
			case "script", "style":
				subs = append(subs, sub{"preload-" + e.attr["as"], href, e.attr["integrity"], e.attr["crossorigin"]})
			}
		}
	}

	for _, s := range subs {
		if !hasValidSRIToken(s.integrity) {
			return bad("cross-origin "+s.kind+" without valid integrity: "+s.url,
				"integrity=sha{256,384,512}-<base64> + crossorigin on every cross-origin subresource")
		}
		if strings.TrimSpace(s.crossorigin) == "" {
			return bad("cross-origin "+s.kind+" has integrity but no crossorigin attr (SRI is inert without CORS mode): "+s.url,
				"integrity + crossorigin=anonymous (or use-credentials)")
		}
	}
	return okay("cross-origin subresources pinned with enforceable SRI (or none)", "")
}
