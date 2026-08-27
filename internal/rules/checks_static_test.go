package rules

import (
	"context"
	"strings"
	"testing"

	"github.com/fabriziosalmi/agssh/internal/httpx"
	"github.com/fabriziosalmi/agssh/internal/manifest"
)

// hardened is a response that should satisfy the header-family checks.
var hardenedHeaders = map[string]string{
	"Content-Security-Policy":   "default-src 'none'; connect-src 'none'; require-trusted-types-for 'script'; upgrade-insecure-requests",
	"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	"X-Content-Type-Options":    "nosniff",
	"X-Frame-Options":           "DENY",
	"Referrer-Policy":           "no-referrer",
	"Permissions-Policy":        "geolocation=()",
}

func TestStaticCheckersInconclusiveWithoutDoc(t *testing.T) {
	for name, fn := range map[string]Checker{
		"csp": chkCSPPresent, "hsts": chkHSTS, "nosniff": chkNosniff, "sri": chkSRI,
	} {
		if out := fn(context.Background(), &CheckCtx{}); out.Status != Inconclusive {
			t.Errorf("%s with no Doc: got %s, want INCONCLUSIVE (fail-closed)", name, out.Status)
		}
	}
}

func TestChkCSPPresent(t *testing.T) {
	if out := chkCSPPresent(context.Background(), &CheckCtx{Doc: newDoc(200, "", map[string]string{"Content-Security-Policy": "default-src 'none'"})}); out.Status != Pass {
		t.Errorf("header CSP: got %s, want PASS", out.Status)
	}
	metaBody := `<meta http-equiv="Content-Security-Policy" content="default-src 'none'">`
	if out := chkCSPPresent(context.Background(), &CheckCtx{Doc: newDoc(200, metaBody, nil)}); out.Status != Pass {
		t.Errorf("meta CSP: got %s, want PASS", out.Status)
	}
	if out := chkCSPPresent(context.Background(), &CheckCtx{Doc: newDoc(200, "<html></html>", nil)}); out.Status != Fail {
		t.Errorf("no CSP: got %s, want FAIL", out.Status)
	}
}

func TestChkHSTS(t *testing.T) {
	cases := []struct {
		hdr  string
		want Status
	}{
		{"max-age=31536000", Pass},
		{"max-age=100", Fail},
		{"max-age=0", Fail},
		{"", Fail},
	}
	for _, tc := range cases {
		h := map[string]string{}
		if tc.hdr != "" {
			h["Strict-Transport-Security"] = tc.hdr
		}
		if out := chkHSTS(context.Background(), &CheckCtx{Doc: newDoc(200, "", h)}); out.Status != tc.want {
			t.Errorf("HSTS %q: got %s, want %s", tc.hdr, out.Status, tc.want)
		}
	}
}

func TestChkNosniffAndReferrer(t *testing.T) {
	if out := chkNosniff(context.Background(), &CheckCtx{Doc: newDoc(200, "", map[string]string{"X-Content-Type-Options": "nosniff"})}); out.Status != Pass {
		t.Errorf("nosniff present: want PASS, got %s", out.Status)
	}
	if out := chkNosniff(context.Background(), &CheckCtx{Doc: newDoc(200, "", nil)}); out.Status != Fail {
		t.Errorf("nosniff absent: want FAIL, got %s", out.Status)
	}
	if out := chkReferrer(context.Background(), &CheckCtx{Doc: newDoc(200, "", map[string]string{"Referrer-Policy": "unsafe-url"})}); out.Status != Fail {
		t.Errorf("weak referrer: want FAIL, got %s", out.Status)
	}
	if out := chkReferrer(context.Background(), &CheckCtx{Doc: newDoc(200, "", map[string]string{"Referrer-Policy": "no-referrer"})}); out.Status != Pass {
		t.Errorf("strong referrer: want PASS, got %s", out.Status)
	}
}

func TestChkNoopenerPrivacy(t *testing.T) {
	surf := func(body string, privacy bool) *CheckCtx {
		return &CheckCtx{
			Surface: manifest.Surface{URL: "https://me.test", Kind: "site", PrivacySurface: privacy},
			Doc:     docFinal("https://me.test", body),
		}
	}
	ext := `<a target="_blank" href="https://evil.example/x">x</a>`
	if out := chkNoopener(context.Background(), surf(ext, false)); out.Status != Fail {
		t.Errorf("external _blank without rel: want FAIL, got %s", out.Status)
	}
	okBody := `<a target="_blank" rel="noopener" href="https://evil.example/x">x</a>`
	if out := chkNoopener(context.Background(), surf(okBody, false)); out.Status != Pass {
		t.Errorf("noopener present (non-privacy): want PASS, got %s", out.Status)
	}
	// On a privacy surface, noopener alone is insufficient — needs noreferrer.
	if out := chkNoopener(context.Background(), surf(okBody, true)); out.Status != Fail {
		t.Errorf("privacy surface needs noreferrer: want FAIL, got %s", out.Status)
	}
}

func TestChkSRI(t *testing.T) {
	body := `<script src="https://cdn.evil/x.js"></script>`
	if out := chkSRI(context.Background(), &CheckCtx{Doc: docFinal("https://me.test", body)}); out.Status != Fail {
		t.Errorf("cross-origin script without integrity: want FAIL, got %s", out.Status)
	}
	// integrity present AND crossorigin present => enforceable SRI => PASS
	okBody := `<script src="https://cdn.evil/x.js" integrity="sha384-abc" crossorigin="anonymous"></script>`
	if out := chkSRI(context.Background(), &CheckCtx{Doc: docFinal("https://me.test", okBody)}); out.Status != Pass {
		t.Errorf("cross-origin script with integrity+crossorigin: want PASS, got %s", out.Status)
	}
	// integrity present, crossorigin MISSING => browser treats response as opaque
	// => SRI is inert => FAIL. This is the load-bearing correction.
	noCORS := `<script src="https://cdn.evil/x.js" integrity="sha384-abc"></script>`
	if out := chkSRI(context.Background(), &CheckCtx{Doc: docFinal("https://me.test", noCORS)}); out.Status != Fail {
		t.Errorf("cross-origin script with integrity but no crossorigin: want FAIL (inert SRI), got %s", out.Status)
	}
	rel := `<script src="/local.js"></script>`
	if out := chkSRI(context.Background(), &CheckCtx{Doc: docFinal("https://me.test", rel)}); out.Status != Pass {
		t.Errorf("same-origin script: want PASS, got %s", out.Status)
	}
}

// AG-SUP-01 must reject malformed integrity tokens (a `sha1-` prefix, a random
// non-sha* string) even if a `crossorigin` attribute is present. Browsers
// silently ignore unrecognized algorithms, which would leave SRI unenforced.
func TestChkSRIRejectsMalformedIntegrity(t *testing.T) {
	body := `<script src="https://cdn.evil/x.js" integrity="foo" crossorigin="anonymous"></script>`
	if out := chkSRI(context.Background(), &CheckCtx{Doc: docFinal("https://me.test", body)}); out.Status != Fail {
		t.Errorf("integrity='foo' must FAIL, got %s", out.Status)
	}
	sha1 := `<script src="https://cdn.evil/x.js" integrity="sha1-abcdef" crossorigin="anonymous"></script>`
	if out := chkSRI(context.Background(), &CheckCtx{Doc: docFinal("https://me.test", sha1)}); out.Status != Fail {
		t.Errorf("sha1- prefix (browser-ignored) must FAIL, got %s", out.Status)
	}
	// Multi-token integrity — at least one well-formed token is enough for the browser.
	multi := `<script src="https://cdn.evil/x.js" integrity="sha1-broken sha384-Yr8asdf++/base64=" crossorigin="anonymous"></script>`
	if out := chkSRI(context.Background(), &CheckCtx{Doc: docFinal("https://me.test", multi)}); out.Status != Pass {
		t.Errorf("multi-token integrity with one valid sha384: want PASS, got %s", out.Status)
	}
}

// AG-SUP-01 must also cover <link rel=modulepreload> and <link rel=preload as=script|style>
// (both fetch executable code cross-origin; SRI applies).
func TestChkSRIModulepreloadAndPreload(t *testing.T) {
	// modulepreload cross-origin without integrity => FAIL
	body := `<link rel="modulepreload" href="https://cdn.evil/x.js">`
	if out := chkSRI(context.Background(), &CheckCtx{Doc: docFinal("https://me.test", body)}); out.Status != Fail {
		t.Errorf("cross-origin modulepreload without integrity: got %s, want FAIL", out.Status)
	}
	// preload as=script without integrity => FAIL
	body2 := `<link rel="preload" as="script" href="https://cdn.evil/x.js">`
	if out := chkSRI(context.Background(), &CheckCtx{Doc: docFinal("https://me.test", body2)}); out.Status != Fail {
		t.Errorf("cross-origin preload as=script without integrity: got %s, want FAIL", out.Status)
	}
	// preload as=image is not a code sink and is out of scope for SRI => PASS
	body3 := `<link rel="preload" as="image" href="https://cdn.evil/x.png">`
	if out := chkSRI(context.Background(), &CheckCtx{Doc: docFinal("https://me.test", body3)}); out.Status != Pass {
		t.Errorf("cross-origin preload as=image is out of scope: got %s, want PASS", out.Status)
	}
}

func TestChkCookieAttrs(t *testing.T) {
	good := newDoc(200, "", nil)
	good.Header.Add("Set-Cookie", "sid=1; Secure; HttpOnly; SameSite=Strict")
	if out := chkCookieAttrs(context.Background(), &CheckCtx{Doc: good}); out.Status != Pass {
		t.Errorf("hardened cookie: want PASS, got %s", out.Status)
	}
	weak := newDoc(200, "", nil)
	weak.Header.Add("Set-Cookie", "sid=1; Path=/")
	if out := chkCookieAttrs(context.Background(), &CheckCtx{Doc: weak}); out.Status != Fail {
		t.Errorf("weak cookie: want FAIL, got %s", out.Status)
	}
}

func TestChkSelfHostFonts(t *testing.T) {
	surf := "https://example.org/"
	cases := []struct {
		name, body string
		want       Status
	}{
		// The regression: prose that merely NAMES a font host (as the AGSSH
		// standard document does when describing this very rule) must PASS.
		{"prose mentions the font host", `<pre>zero fonts.googleapis.com / fonts.gstatic.com references</pre>` +
			`<div>Self-host WOFF2 files in @font-face with font-src 'self'.</div>`, Pass},
		{"third-party font stylesheet", `<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter">`, Fail},
		{"protocol-relative font stylesheet", `<link rel="stylesheet" href="//fonts.googleapis.com/css2?family=Inter">`, Fail},
		{"protocol-relative @font-face file", `<style>@font-face{src:url(//cdn.other.com/x.woff2)}</style>`, Fail},
		{"preconnect to a font CDN", `<link rel="preconnect" href="https://fonts.gstatic.com">`, Fail},
		{"cross-origin @font-face file", `<style>@font-face{font-family:x;src:url(https://cdn.other.com/x.woff2)}</style>`, Fail},
		{"cross-origin preloaded font", `<link rel="preload" as="font" href="https://cdn.other.com/x.woff2" crossorigin>`, Fail},
		{"self-hosted fonts are fine", `<link rel="stylesheet" href="/style.css"><style>@font-face{src:url(/fonts/x.woff2)}</style>`, Pass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if out := chkSelfHostFonts(context.Background(), &CheckCtx{Doc: docFinal(surf, tc.body)}); out.Status != tc.want {
				t.Errorf("got %s (%s), want %s", out.Status, out.Err, tc.want)
			}
		})
	}
}

func TestHardenedSurfacePassesHeaderFamily(t *testing.T) {
	doc := newDoc(200, "", hardenedHeaders)
	c := &CheckCtx{Doc: doc, Surface: manifest.Surface{URL: "https://me.test"}}
	for name, fn := range map[string]Checker{
		"nosniff": chkNosniff, "xfo": chkXFO, "referrer": chkReferrer,
		"permissions": chkPermissionsPolicy, "hsts": chkHSTS, "csp": chkCSPPresent,
		"deny-default": chkDenyDefault, "trusted-types": chkTrustedTypes, "upgrade": chkUpgradeInsecure,
	} {
		if out := fn(context.Background(), c); out.Status != Pass {
			t.Errorf("%s on hardened surface: got %s (%s), want PASS", name, out.Status, out.Evidence.Observed)
		}
	}
}

// ---- AG-NET-02 finding accuracy (2026-07-23 review round) ----
//
// Seven CRIT advisories in one queue said "third-party CDN" for, among others, a site's
// OWN radio subdomain and for YouTube/Twitch iframes on pages that exist to embed them.
// The verdicts were right; the sentences were not. These pin the wording.

func netFindingFor(t *testing.T, surface, body string) Outcome {
	t.Helper()
	doc := &httpx.Doc{FinalURL: surface, Body: []byte(body)}
	return chkNoCDNLoaders(context.Background(), &CheckCtx{Doc: doc, Level: 0})
}

func TestNoCDNLoaders_OwnSubdomainIsNotThirdParty(t *testing.T) {
	out := netFindingFor(t, "https://freeundergroundtekno.org/radio/",
		`<audio src="https://radio.freeundergroundtekno.org/stream"></audio>`)
	if out.Status != Fail {
		t.Fatalf("cross-origin egress must still FAIL at L0, got %s", out.Status)
	}
	if strings.Contains(out.Evidence.Observed, "third-party") {
		t.Errorf("own subdomain reported as third-party: %q", out.Evidence.Observed)
	}
	if !strings.Contains(out.Evidence.Observed, "same-site") {
		t.Errorf("want a same-site finding, got %q", out.Evidence.Observed)
	}
}

func TestNoCDNLoaders_GenuineThirdPartyStillSaysThirdParty(t *testing.T) {
	out := netFindingFor(t, "https://example.org/", `<script src="https://cdn.jsdelivr.net/x.js"></script>`)
	if out.Status != Fail || !strings.Contains(out.Evidence.Observed, "third-party") {
		t.Fatalf("want a third-party FAIL, got %s %q", out.Status, out.Evidence.Observed)
	}
	if !strings.Contains(out.Evidence.Observed, "subresource") {
		t.Errorf("a <script src> is a subresource, got %q", out.Evidence.Observed)
	}
}

func TestNoCDNLoaders_IframeIsReportedAsADocumentEmbed(t *testing.T) {
	out := netFindingFor(t, "https://audiolibri.org/", `<iframe src="https://www.youtube.com/embed/x"></iframe>`)
	if out.Status != Fail {
		t.Fatalf("want FAIL, got %s", out.Status)
	}
	if !strings.Contains(out.Evidence.Observed, "document embed") {
		t.Errorf("an <iframe> is a document embed, not a subresource: %q", out.Evidence.Observed)
	}
}

func TestSameSite(t *testing.T) {
	cases := []struct {
		surface, ref string
		want         bool
	}{
		{"https://example.org/", "https://radio.example.org/s", true},
		{"https://www.example.org/", "https://cdn.example.org/x.js", true},
		{"https://example.org/", "https://example.com/x.js", false},
		{"https://example.co.uk/", "https://cdn.example.co.uk/x.js", true},
		{"https://example.co.uk/", "https://evil.co.uk/x.js", false}, // co.uk is a public suffix
		{"https://192.168.0.1/", "https://192.168.0.2/x.js", false},  // IP literals: don't guess
	}
	for _, c := range cases {
		if got := sameSite(c.surface, c.ref); got != c.want {
			t.Errorf("sameSite(%q, %q) = %v, want %v", c.surface, c.ref, got, c.want)
		}
	}
}

// TestChkZeroTelemetryHostBased pins RUN-02: AG-PRV-01 flags a third-party
// analytics host only when the HTML actually REFERENCES it in a resource-loading
// attribute — never on prose/code that merely mentions analytics. The prose case
// is the exact false positive the old substring regex produced on agssh's own
// audience (privacy tools and docs about removing trackers).
func TestChkZeroTelemetryHostBased(t *testing.T) {
	ctx := func(body string) *CheckCtx {
		return &CheckCtx{Doc: &httpx.Doc{FinalURL: "https://me.test/", Body: []byte(body)}}
	}
	mustFail := []struct{ name, body string }{
		{"plausible", `<script src="https://plausible.io/js/script.js"></script>`},
		{"GA4 loader", `<script src="https://www.googletagmanager.com/gtag/js?id=G-ABCDEFGHIJ"></script>`},
		{"cloudflare insights (protocol-relative)", `<script src="//static.cloudflareinsights.com/beacon.min.js"></script>`},
		{"mixpanel", `<script src="https://cdn.mxpnl.com/libs/mixpanel-2-latest.min.js"></script>`},
		{"hotjar via preload link", `<link rel="preload" as="script" href="https://static.hotjar.com/c/hotjar-123.js">`},
		{"posthog", `<script src="https://us.i.posthog.com/static/array.js"></script>`},
	}
	for _, c := range mustFail {
		if out := chkZeroTelemetry(context.Background(), ctx(c.body)); out.Status != Fail {
			t.Errorf("%s: got %s, want FAIL", c.name, out.Status)
		}
	}
	mustPass := []struct{ name, body string }{
		// THE false-positive guard: analytics named in prose/code, none loaded.
		{"prose about removing GA", `<article><h1>We removed Google Analytics</h1>` +
			`<p>The old <code>gtag()</code> snippet used a <code>UA-12345-1</code> property; ` +
			`we deleted analytics.js. Unrelated: G-quadruplex DNA folds under stress.</p></article>`},
		{"clean first-party page", `<script src="/app.js"></script><link rel="stylesheet" href="/style.css">`},
		{"legit non-analytics CDN", `<script src="https://cdn.jsdelivr.net/npm/thing/dist.js"></script>`},
		{"first-party subdomain asset", `<script src="https://cdn.me.test/app.js"></script>`},
		// Deliberately excluded from the catalog (shared with a functional load):
		// the FB JS SDK / Login on connect.facebook.net must NOT false-FAIL.
		{"facebook SDK (functional, excluded)", `<script src="https://connect.facebook.net/en_US/sdk.js"></script>`},
		{"intercom support widget (excluded)", `<script src="https://widget.intercom.io/widget/abc"></script>`},
	}
	for _, c := range mustPass {
		if out := chkZeroTelemetry(context.Background(), ctx(c.body)); out.Status != Pass {
			t.Errorf("%s: got %s (%s), want PASS", c.name, out.Status, out.Evidence.Observed)
		}
	}
}
