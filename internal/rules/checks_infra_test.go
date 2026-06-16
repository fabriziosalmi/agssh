package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fabriziosalmi/agssh/internal/manifest"
	"github.com/miekg/dns"
)

func TestChkPinnedDeps(t *testing.T) {
	write := func(name, content string) string {
		d := t.TempDir()
		if err := os.WriteFile(filepath.Join(d, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return d
	}
	cases := []struct {
		name string
		dir  string
		want Status
	}{
		{"npm with integrity", write("package-lock.json", `{"packages":{"node_modules/x":{"integrity":"sha512-aa"}}}`), Pass},
		{"npm without integrity", write("package-lock.json", `{"packages":{"node_modules/x":{"version":"1"}}}`), Fail},
		{"go.sum presence suffices", write("go.sum", "example.com/x v1.0.0 h1:aa=\n"), Pass},
		{"no lockfile", t.TempDir(), Inconclusive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if out := chkPinnedDeps(t.Context(), &CheckCtx{RepoDir: tc.dir}); out.Status != tc.want {
				t.Errorf("got %s, want %s", out.Status, tc.want)
			}
		})
	}
}

func TestParseOSVResults(t *testing.T) {
	oneVuln := `{"results":[{"packages":[{"vulnerabilities":[{"id":"GHSA-xxxx"},{"id":"GHSA-xxxx"},{"id":"CVE-2026-1"}]}]}]}`
	clean := `{"results":[]}`

	if n, ids, ok := parseOSVResults([]byte(oneVuln)); !ok || n != 2 || len(ids) != 2 {
		t.Errorf("oneVuln: ok=%v n=%d ids=%v, want ok=true n=2 (deduped)", ok, n, ids)
	}
	if n, _, ok := parseOSVResults([]byte(clean)); !ok || n != 0 {
		t.Errorf("clean: ok=%v n=%d, want ok=true n=0", ok, n)
	}
	if _, _, ok := parseOSVResults([]byte("")); ok {
		t.Errorf("empty output: want ok=false (scan error, not clean)")
	}
	if _, _, ok := parseOSVResults([]byte("panic: boom\n")); ok {
		t.Errorf("non-JSON: want ok=false")
	}
}

func TestTakeoverFingerprintAndProvider(t *testing.T) {
	if sig, ok := takeoverFingerprint("<h1>There isn't a GitHub Pages site here.</h1>"); !ok || sig == "" {
		t.Errorf("GitHub Pages body: want a match, got ok=%v sig=%q", ok, sig)
	}
	if _, ok := takeoverFingerprint("<html><body>Welcome</body></html>"); ok {
		t.Errorf("benign body: want no match")
	}
	if name, ok := takeoverProvider("foo.github.io."); !ok || name == "" {
		t.Errorf("github.io target: want provider, got ok=%v name=%q", ok, name)
	}
	if _, ok := takeoverProvider("www.example.com."); ok {
		t.Errorf("plain host: want no provider")
	}
}

func TestEffectiveResolver(t *testing.T) {
	if got := effectiveResolver("8.8.8.8"); got != "8.8.8.8:53" {
		t.Errorf("bare host: got %q, want 8.8.8.8:53", got)
	}
	if got := effectiveResolver("1.2.3.4:5353"); got != "1.2.3.4:5353" {
		t.Errorf("host:port: got %q, want unchanged", got)
	}
}

func TestSurfaceAddr(t *testing.T) {
	cases := map[string]string{
		"https://example.com":          "example.com:443",
		"https://example.com:8443/x":   "example.com:8443",
		"https://127.0.0.1:55":         "127.0.0.1:55",
		"http://docs.example.org/path": "docs.example.org:443",
	}
	for in, want := range cases {
		if got := surfaceAddr(in); got != want {
			t.Errorf("surfaceAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestChkCAA(t *testing.T) {
	withCAA := dnsTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeCAA {
			rr, _ := dns.NewRR(`example.test. 3600 IN CAA 0 issue "letsencrypt.org"`)
			answer(w, r, dns.RcodeSuccess, rr)
			return
		}
		answer(w, r, dns.RcodeSuccess)
	})
	noCAA := dnsTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) { answer(w, r, dns.RcodeSuccess) })

	if out := chkCAA(t.Context(), &CheckCtx{Zone: "example.test", Resolver: withCAA}); out.Status != Pass {
		t.Errorf("zone with CAA: got %s (%s), want PASS", out.Status, out.Err)
	}
	if out := chkCAA(t.Context(), &CheckCtx{Zone: "example.test", Resolver: noCAA}); out.Status != Fail {
		t.Errorf("zone without CAA: got %s, want FAIL", out.Status)
	}
	if out := chkCAA(t.Context(), &CheckCtx{Zone: ""}); out.Status != Inconclusive {
		t.Errorf("no zone: got %s, want INCONCLUSIVE", out.Status)
	}
}

func TestChkDangling(t *testing.T) {
	// app.example.test -> bar.unclaimed.test (does not resolve) => classic dangling.
	nx := dnsTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		switch {
		case q.Qtype == dns.TypeCNAME && q.Name == "app.example.test.":
			rr, _ := dns.NewRR("app.example.test. 300 IN CNAME bar.unclaimed.test.")
			answer(w, r, dns.RcodeSuccess, rr)
		case q.Qtype == dns.TypeA && q.Name == "bar.unclaimed.test.":
			answer(w, r, dns.RcodeNameError) // NXDOMAIN
		default:
			answer(w, r, dns.RcodeSuccess)
		}
	})
	out := chkDangling(t.Context(), &CheckCtx{Surface: manifest.Surface{URL: "https://app.example.test"}, Resolver: nx})
	if out.Status != Fail {
		t.Errorf("dangling (NXDOMAIN target): got %s, want FAIL", out.Status)
	}

	// app.example.test -> foo.github.io (resolves) + unclaimed-page fingerprint
	// in the body => takeover, which the old check missed.
	takeover := dnsTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		switch {
		case q.Qtype == dns.TypeCNAME && q.Name == "app.example.test.":
			rr, _ := dns.NewRR("app.example.test. 300 IN CNAME foo.github.io.")
			answer(w, r, dns.RcodeSuccess, rr)
		case q.Qtype == dns.TypeA && q.Name == "foo.github.io.":
			rr, _ := dns.NewRR("foo.github.io. 300 IN A 185.199.108.153")
			answer(w, r, dns.RcodeSuccess, rr)
		default:
			answer(w, r, dns.RcodeSuccess)
		}
	})
	out = chkDangling(t.Context(), &CheckCtx{
		Surface:  manifest.Surface{URL: "https://app.example.test"},
		Resolver: takeover,
		Doc:      newDoc(404, "<h1>There isn't a GitHub Pages site here.</h1>", nil),
	})
	if out.Status != Fail {
		t.Errorf("resolving-but-unclaimed takeover: got %s, want FAIL", out.Status)
	}
}
