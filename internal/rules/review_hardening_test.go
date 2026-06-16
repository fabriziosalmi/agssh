package rules

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/fabriziosalmi/agssh/internal/manifest"
	"github.com/miekg/dns"
)

// ---- TLS: an ambiguous probe must be INCONCLUSIVE, never PASS ----

func TestChkTLSFloorIndeterminate(t *testing.T) {
	// A raw TCP server that accepts then immediately closes (no TLS records) must
	// not be read as "legacy refused" -> PASS. It is unprovable -> INCONCLUSIVE.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	if out := chkTLSFloor(t.Context(), &CheckCtx{Surface: surfaceURL(ln.Addr().String())}); out.Status != Inconclusive {
		t.Errorf("RST-on-connect server: got %s, want INCONCLUSIVE (not a provable refusal)", out.Status)
	}
}

// ---- IPv6 host/addr parsing ----

func TestHostOnlyAndSurfaceAddrIPv6(t *testing.T) {
	for in, want := range map[string]string{
		"https://[::1]:8443/x":             "::1",
		"https://[2606:4700:4700::1111]/p": "2606:4700:4700::1111",
		"https://example.com:443":          "example.com",
		"example.com":                      "example.com",
	} {
		if got := hostOnly(in); got != want {
			t.Errorf("hostOnly(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"https://[::1]:8443":         "[::1]:8443",
		"https://[2606:4700::1111]":  "[2606:4700::1111]:443",
		"https://example.com":        "example.com:443",
		"https://example.com:8443/x": "example.com:8443",
	} {
		if got := surfaceAddr(in); got != want {
			t.Errorf("surfaceAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---- AG-SUP-02: lockfile markers across ecosystems ----

func TestChkPinnedDepsMarkers(t *testing.T) {
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
		{"poetry content-hash only", write("poetry.lock", "[metadata]\ncontent-hash = \"abc123\"\n"), Fail},
		{"poetry file hash", write("poetry.lock", "[[package.files]]\nhash = \"sha256:deadbeef\"\n"), Pass},
		{"yarn berry checksum", write("yarn.lock", "\"pkg@npm:1.0.0\":\n  checksum: 9bf2a\n"), Pass},
		{"empty go.sum", write("go.sum", "   \n"), Inconclusive},
		{"populated go.sum", write("go.sum", "example.com/x v1 h1:aa=\n"), Pass},
		{"cargo checksum", write("Cargo.lock", "[[package]]\nname = \"x\"\nchecksum = \"deadbeef\"\n"), Pass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if out := chkPinnedDeps(t.Context(), &CheckCtx{RepoDir: tc.dir}); out.Status != tc.want {
				t.Errorf("got %s, want %s (%s%s)", out.Status, tc.want, out.Evidence.Observed, out.Err)
			}
		})
	}
}

// ---- osv: IDs reported under groups[].ids must be counted ----

func TestParseOSVResultsGroups(t *testing.T) {
	groupsOnly := `{"results":[{"packages":[{"groups":[{"ids":["GHSA-aaaa","CVE-2026-2"]}]}]}]}`
	if n, _, ok := parseOSVResults([]byte(groupsOnly)); !ok || n != 2 {
		t.Errorf("groups-only: ok=%v n=%d, want ok=true n=2", ok, n)
	}
}

// ---- AG-DNS-03: only takeover-prone providers get the fingerprint check ----

func TestChkDanglingProviderGate(t *testing.T) {
	// app.example.test -> cdn.example.net (ordinary, resolving). Even if the
	// surface body contains a generic phrase, a non-prone provider must PASS.
	srv := dnsTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]
		switch {
		case q.Qtype == dns.TypeCNAME && q.Name == "app.example.test.":
			rr, _ := dns.NewRR("app.example.test. 300 IN CNAME cdn.example.net.")
			answer(w, r, dns.RcodeSuccess, rr)
		case q.Qtype == dns.TypeA && q.Name == "cdn.example.net.":
			rr, _ := dns.NewRR("cdn.example.net. 300 IN A 203.0.113.5")
			answer(w, r, dns.RcodeSuccess, rr)
		default:
			answer(w, r, dns.RcodeSuccess)
		}
	})
	out := chkDangling(t.Context(), &CheckCtx{
		Surface:  manifest.Surface{URL: "https://app.example.test"},
		Resolver: srv,
		Doc:      newDoc(200, "<h1>Repository not found</h1>", nil), // generic phrase, must NOT fail
	})
	if out.Status != Pass {
		t.Errorf("non-prone provider with a generic phrase: got %s, want PASS", out.Status)
	}

	// app.example.test -> foo.github.io (prone), resolves, but NO body available
	// -> fail-closed INCONCLUSIVE, not a silent PASS.
	srv2 := dnsTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
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
		Resolver: srv2,
		Doc:      nil,
	})
	if out.Status != Inconclusive {
		t.Errorf("prone provider, no body to confirm: got %s, want INCONCLUSIVE", out.Status)
	}
}

// ---- AG-CI-05: modern "checks" array + zero-approval review ----

func TestEvalBranchProtectionChecksArray(t *testing.T) {
	checksOnly := `{"required_pull_request_reviews":{"required_approving_review_count":1},"required_status_checks":{"strict":true,"contexts":[],"checks":[{"context":"ci","app_id":-1}]}}`
	if out := evalBranchProtection("main", 200, []byte(checksOnly)); out.Status != Pass {
		t.Errorf("checks[]-populated/contexts empty: got %s, want PASS", out.Status)
	}
	zeroApprovals := `{"required_pull_request_reviews":{"required_approving_review_count":0},"required_status_checks":{"contexts":["ci"]}}`
	if out := evalBranchProtection("main", 200, []byte(zeroApprovals)); out.Status != Fail {
		t.Errorf("0 required approvals: got %s, want FAIL", out.Status)
	}
}

// ---- AG-CI-01: uppercase commit SHAs are valid pins ----

func TestChkPinnedActionsUppercaseSHA(t *testing.T) {
	up := "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@1234567890ABCDEF1234567890ABCDEF12345678\n"
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "ci.yml"), []byte(up), 0o644); err != nil {
		t.Fatal(err)
	}
	if out := chkPinnedActions(t.Context(), &CheckCtx{WorkflowsDir: d}); out.Status != Pass {
		t.Errorf("uppercase SHA pin: got %s, want PASS", out.Status)
	}
}

// ---- AG-CI-02 / AG-CI-03: the exploit patterns the substring check missed ----

func TestChkLeastPrivJobWriteAllUnderTopLevel(t *testing.T) {
	yaml := "permissions:\n  contents: read\njobs:\n  a:\n    steps: [{run: echo}]\n  deploy:\n    permissions: write-all\n    steps: [{run: echo}]\n"
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "ci.yml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	if out := chkLeastPriv(t.Context(), &CheckCtx{WorkflowsDir: d}); out.Status != Fail {
		t.Errorf("job write-all hidden under a top-level block: got %s, want FAIL", out.Status)
	}
}

func TestChkNoUntrustedPrivPatterns(t *testing.T) {
	dir := func(body string) string {
		d := t.TempDir()
		if err := os.WriteFile(filepath.Join(d, "wf.yml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return d
	}
	headRef := "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.head_ref }}\n"
	forkRepo := "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n"
	mergeRef := "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: refs/pull/${{ github.event.number }}/merge\n"
	for name, body := range map[string]string{"head_ref": headRef, "fork repo": forkRepo, "merge ref": mergeRef} {
		t.Run(name, func(t *testing.T) {
			if out := chkNoUntrustedPriv(t.Context(), &CheckCtx{WorkflowsDir: dir(body)}); out.Status != Fail {
				t.Errorf("%s: got %s, want FAIL", name, out.Status)
			}
		})
	}
	notCheckout := "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout-evil@v1\n        with:\n          ref: ${{ github.head_ref }}\n"
	if out := chkNoUntrustedPriv(t.Context(), &CheckCtx{WorkflowsDir: dir(notCheckout)}); out.Status != Pass {
		t.Errorf("typosquat action is not actions/checkout: got %s, want PASS", out.Status)
	}
}

// ---- AG-NET-04 / AG-NET-01: level-gated egress + per-directive scoping ----

func cspDoc(policy string) *CheckCtx {
	return &CheckCtx{Doc: newDoc(200, "", map[string]string{"Content-Security-Policy": policy})}
}

func TestChkConnectSrcLevelGated(t *testing.T) {
	c := cspDoc("default-src 'none'; connect-src https://api.example")
	c.Allow = manifest.Allow{Connect: []string{"https://api.example"}}

	c.Level = manifest.L0 // strict air-gap: the allow-list does NOT apply
	if out := chkConnectSrc(t.Context(), c); out.Status != Fail {
		t.Errorf("L0 must ignore the connect allow-list: got %s, want FAIL", out.Status)
	}
	c.Level = manifest.L1 // scoped egress: the allow-list applies
	if out := chkConnectSrc(t.Context(), c); out.Status != Pass {
		t.Errorf("L1 honors the declared allow-list: got %s, want PASS", out.Status)
	}
}

func TestStaticMustNegatives(t *testing.T) {
	cases := []struct {
		name   string
		fn     Checker
		policy string
		want   Status
	}{
		{"deny-default wildcard", chkDenyDefault, "default-src *", Fail},
		{"deny-default unsafe-inline", chkDenyDefault, "default-src 'self'; script-src 'unsafe-inline'", Fail},
		{"trusted-types absent", chkTrustedTypes, "default-src 'none'", Fail},
		{"upgrade-insecure absent", chkUpgradeInsecure, "default-src 'none'", Fail},
		{"self-host-all leaks img-src", chkSelfHostAll, "default-src 'none'; img-src https://cdn.evil", Fail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if out := tc.fn(t.Context(), cspDoc(tc.policy)); out.Status != tc.want {
				t.Errorf("got %s, want %s", out.Status, tc.want)
			}
		})
	}
}

// ---- AG-PRV-04: the JS->Go JSON contract (exercised without a browser) ----

func TestStorageObsJSONContract(t *testing.T) {
	var got storageObs
	if err := json.Unmarshal([]byte(`{"local":["k1"],"session":["k2"]}`), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Local) != 1 || got.Local[0] != "k1" || len(got.Session) != 1 || got.Session[0] != "k2" {
		t.Fatalf("decoded shape mismatch: %+v", got)
	}
	if storageVerdict([]string{"k1"}, got).Status != Fail {
		t.Error("k2 not allow-listed: want FAIL")
	}
	if storageVerdict([]string{"k1", "k2"}, got).Status != Pass {
		t.Error("both allow-listed: want PASS")
	}
}

func TestServiceWorkerJSONContract(t *testing.T) {
	// The exact shape serviceWorkerJS emits (a JSON-stringified array).
	var regs []swReg
	if err := json.Unmarshal([]byte(`[{"scope":"https://me.test/","script":"https://cdn.evil/sw.js"}]`), &regs); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(regs) != 1 || regs[0].Script != "https://cdn.evil/sw.js" {
		t.Fatalf("decoded shape mismatch: %+v", regs)
	}
	if serviceWorkerVerdict("me.test", regs).Status != Fail {
		t.Error("cross-origin SW script via the JS contract: want FAIL")
	}
}
