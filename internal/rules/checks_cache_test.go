package rules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fabriziosalmi/agssh/internal/httpx"
)

const (
	longImmutable = "public, max-age=31536000, immutable"
	revalidate    = "public, max-age=600, must-revalidate"
)

func TestClassifyAsset(t *testing.T) {
	cases := map[string]assetClass{
		// content-hashed: the standard's /_astro/ example, hex digests, Rollup/Vite base64url
		"/_astro/index.css":                            assetHashed,
		"/assets/main.3f2a1b9c.js":                     assetHashed,
		"/static/js/main.3f2a1b9c4d5e6f70.chunk.js":    assetHashed,
		"/_next/static/chunks/app-1234abcd5678ef90.js": assetHashed,
		"/assets/index-B1x2Y3z4.js":                    assetHashed,
		"/assets/index-BWq_3K-c.js":                    assetHashed,
		// plainly unhashed: lowercase words / short tokens, no query
		"/agssh-std.css":          assetUnhashed,
		"/badge.svg":              assetUnhashed,
		"/js/jquery-3.7.1.min.js": assetUnhashed,
		"/favicon.ico":            assetUnhashed,
		"/stylesheet.css":         assetUnhashed,
		"/fonts/Inter-Bold.woff2": assetUnhashed,
		"/fonts/Obviously.woff2":  assetUnhashed,
		"/Logo.png":               assetUnhashed,
		// cannot tell: fail-closed
		"/style.css?v=3f2a1b9c":     assetUnknown,
		"/build-20240101.js":        assetUnknown,
		"/assets/index-k1b2c3d4.js": assetUnknown,
		"/assets/index-AbC-dEfG.js": assetUnknown, // digitless digest split by '-'
		"/assets/app_main.js":       assetUnknown,
		"/main.Kx92.js":             assetUnknown,
	}
	for p, want := range cases {
		u, _ := url.Parse("https://example.test" + p)
		if got := classifyAsset(u); got != want {
			t.Errorf("classifyAsset(%s) = %d, want %d", p, got, want)
		}
	}
}

func TestCacheControlClasses(t *testing.T) {
	doc := map[string]cacheClass{
		"no-cache":                            cacheShort,
		"no-store":                            cacheShort,
		"max-age=0, must-revalidate":          cacheShort,
		"public, max-age=31536000, immutable": cacheLong,
		"max-age=63072000":                    cacheLong,
		"no-cache, immutable":                 cacheLong, // immutable on a document is never short
		"public, max-age=600":                 cacheUndecided,
		"":                                    cacheUndecided,
	}
	for h, want := range doc {
		if got := documentCacheClass(h); got != want {
			t.Errorf("documentCacheClass(%q) = %d, want %d", h, got, want)
		}
	}
	asset := map[string]bool{
		longImmutable:                                   true,
		"Public, Max-Age=63072000, Immutable":           true,
		"max-age=31536000, immutable":                   false, // public required by the rule text
		"public, max-age=31536000":                      false,
		"public, max-age=600, immutable":                false,
		"public, max-age=31536000, immutable, no-cache": false,
		"": false,
	}
	for h, want := range asset {
		if got := assetLongImmutable(h); got != want {
			t.Errorf("assetLongImmutable(%q) = %v, want %v", h, got, want)
		}
	}
}

// cacheSurface serves an HTML document with docCC and assets with per-path
// Cache-Control headers (a missing path is a 404).
func cacheSurface(t *testing.T, body, docCC string, assets map[string]string) *CheckCtx {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cc, ok := assets[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", cc)
		_, _ = w.Write([]byte("x"))
	}))
	t.Cleanup(srv.Close)
	d := docFinal(srv.URL+"/", body)
	if docCC != "" {
		d.Header.Set("Cache-Control", docCC)
	}
	return &CheckCtx{Doc: d, HTTP: httpx.New(5 * time.Second)}
}

const cachePage = `<html><head>
<link rel="stylesheet" href="/agssh-std.css">
<script type="module" src="/assets/index-B1x2Y3z4.js"></script>
<script src="https://cdn.example.org/lib.abcdef12.js"></script>
<img src="data:image/png;base64,AAAA">
</head></html>`

func TestCacheDisciplineVerdicts(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		body   string
		docCC  string
		assets map[string]string
		want   Status
	}{
		{"hashed asset long-cached, document no-cache", cachePage, "no-cache",
			map[string]string{"/agssh-std.css": revalidate, "/assets/index-B1x2Y3z4.js": longImmutable}, Pass},
		{"hashed asset short-cached", cachePage, "no-cache",
			map[string]string{"/agssh-std.css": revalidate, "/assets/index-B1x2Y3z4.js": revalidate}, Fail},
		{"hashed asset without public", cachePage, "no-cache",
			map[string]string{"/assets/index-B1x2Y3z4.js": "max-age=31536000, immutable"}, Fail},
		{"document long-cached", cachePage, "public, max-age=31536000, immutable",
			map[string]string{"/assets/index-B1x2Y3z4.js": longImmutable}, Fail},
		{"document lifetime not provably short", cachePage, revalidate,
			map[string]string{"/assets/index-B1x2Y3z4.js": longImmutable}, Inconclusive},
		{"document has no Cache-Control", cachePage, "",
			map[string]string{"/assets/index-B1x2Y3z4.js": longImmutable}, Inconclusive},
		{"hashed asset missing (404)", cachePage, "no-cache", map[string]string{}, Inconclusive},
		{"unclassifiable asset short-cached", `<script src="/main.Kx92.js"></script>`, "no-cache",
			map[string]string{"/main.Kx92.js": revalidate}, Inconclusive},
		{"unclassifiable asset long-cached", `<script src="/main.Kx92.js"></script>`, "no-cache",
			map[string]string{"/main.Kx92.js": longImmutable}, Pass},
		{"no hashed assets, document no-store", `<link rel="icon" href="/favicon.ico">`, "no-store",
			map[string]string{}, Pass},
	}
	for _, tc := range cases {
		out := chkCacheDiscipline(ctx, cacheSurface(t, tc.body, tc.docCC, tc.assets))
		if out.Status != tc.want {
			t.Errorf("%s: got %s (%s%s), want %s", tc.name, out.Status, out.Evidence.Observed, out.Err, tc.want)
		}
	}
}

func TestCacheDisciplineFailClosed(t *testing.T) {
	ctx := context.Background()
	if out := chkCacheDiscipline(ctx, &CheckCtx{}); out.Status != Inconclusive {
		t.Errorf("no document: got %s, want INCONCLUSIVE", out.Status)
	}
	// A hashed asset the runner cannot fetch is unproven, never a vacuous PASS.
	d := docFinal("https://surface.test/", cachePage)
	d.Header.Set("Cache-Control", "no-cache")
	out := chkCacheDiscipline(ctx, &CheckCtx{Doc: d})
	if out.Status != Inconclusive || !strings.Contains(out.Err, "no HTTP client") {
		t.Errorf("no HTTP client: got %s (%s), want INCONCLUSIVE", out.Status, out.Err)
	}
	// Cross-origin subresources are not this surface's to cache: the CDN script in
	// cachePage is never fetched (the test server would 404 it as unknown).
	c := cacheSurface(t, `<script src="https://cdn.example.org/lib.abcdef12.js"></script>`, "no-cache", map[string]string{})
	if out := chkCacheDiscipline(ctx, c); out.Status != Pass {
		t.Errorf("cross-origin only: got %s (%s), want PASS", out.Status, out.Err)
	}
}

// The registry binds AG-HDR-07 to the checker, not to a todo() stub: a provably
// conformant surface must come back PASS through the registered Check.
func TestCacheDisciplineRegistered(t *testing.T) {
	for _, r := range All() {
		if r.ID != "AG-HDR-07" {
			continue
		}
		c := cacheSurface(t, cachePage, "no-cache",
			map[string]string{"/agssh-std.css": revalidate, "/assets/index-B1x2Y3z4.js": longImmutable})
		if out := r.Check(context.Background(), c); out.Status != Pass {
			t.Fatalf("AG-HDR-07 via registry: got %s (%s), want PASS", out.Status, out.Err)
		}
		return
	}
	t.Fatal("AG-HDR-07 not registered")
}
