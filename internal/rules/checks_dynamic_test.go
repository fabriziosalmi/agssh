package rules

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chromedp/cdproto/audits"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/fabriziosalmi/agssh/internal/manifest"
)

func TestOfflineProofVerdict(t *testing.T) {
	if offlineProofVerdict("me.test", []string{"me.test", ""}, nil).Status != Pass {
		t.Error("only first-party responses: want PASS")
	}
	if offlineProofVerdict("me.test", []string{"me.test", "evil.test"}, nil).Status != Fail {
		t.Error("a third-party response: want FAIL")
	}
}

// A declared host is exempt, an undeclared one still fails, and a sibling
// subdomain of the surface is NOT implicitly first-party (issue #69).
func TestOfflineProofVerdictAllowList(t *testing.T) {
	resp := []string{"me.test", "api.me.test", "fonts.x.test"}
	out := offlineProofVerdict("me.test", resp, []string{"api.me.test"})
	if out.Status != Fail || !strings.Contains(out.Evidence.Observed, "fonts.x.test") || strings.Contains(out.Evidence.Observed, "api.me.test") {
		t.Errorf("allow api.me.test: want FAIL naming only fonts.x.test, got %v / %q", out.Status, out.Evidence.Observed)
	}
	if offlineProofVerdict("me.test", resp, []string{"api.me.test", "fonts.x.test"}).Status != Pass {
		t.Error("every third-party host declared: want PASS")
	}
	if offlineProofVerdict("me.test", []string{"me.test", "api.me.test"}, nil).Status != Fail {
		t.Error("undeclared sibling subdomain: want FAIL")
	}
}

func TestEgressAllowedLevelGating(t *testing.T) {
	c := &CheckCtx{Allow: manifest.Allow{
		Connect: []string{"https://api.me.test"}, Subresources: []string{"cdn.me.test"}, Embeds: []string{"https://yt.test/x"},
	}}
	for lvl, want := range map[manifest.Level]int{manifest.L0: 0, manifest.L1: 2, manifest.L2: 3} {
		c.Level = lvl
		if got := egressAllowed(c); len(got) != want {
			t.Errorf("level %v: egressAllowed = %v, want %d hosts", lvl, got, want)
		}
	}
}

func TestPreConsentVerdict(t *testing.T) {
	if preConsentVerdict([]string{"me.test"}).Status != Pass {
		t.Error("no trackers: want PASS")
	}
	if preConsentVerdict([]string{"www.google-analytics.com"}).Status != Fail {
		t.Error("tracker subdomain pre-consent: want FAIL")
	}
}

// TestEgressCanaryVerdict: PASS only on a CSP block observed for every probe,
// FAIL on any answered probe, INCONCLUSIVE on anything unproven (issue #16).
func TestEgressCanaryVerdict(t *testing.T) {
	blocked := canaryProbe{URL: canaryFetch, CSPBlocked: true}
	answered := canaryProbe{URL: canaryPixel, Answered: true}
	netErr := canaryProbe{URL: canaryBeacon, Failure: "net::ERR_NAME_NOT_RESOLVED"}
	silent := canaryProbe{URL: canaryBeacon}
	cases := []struct {
		name   string
		probes []canaryProbe
		want   Status
	}{
		{"every probe CSP-blocked", []canaryProbe{blocked, blocked, blocked}, Pass},
		{"one probe answered", []canaryProbe{blocked, answered, blocked}, Fail},
		{"answered wins over an unproven probe", []canaryProbe{answered, netErr, silent}, Fail},
		{"no outcome at all (absence is not proof)", []canaryProbe{silent, silent, silent}, Inconclusive},
		{"network error, not a CSP block", []canaryProbe{netErr, netErr, netErr}, Inconclusive},
		{"two blocked, one network error", []canaryProbe{blocked, blocked, netErr}, Inconclusive},
		{"two blocked, one never settled", []canaryProbe{blocked, blocked, silent}, Inconclusive},
		{"non-CSP block reason", []canaryProbe{blocked, blocked, {URL: canaryBeacon, Failure: "inspector"}}, Inconclusive},
		{"no probes", nil, Inconclusive},
	}
	for _, tc := range cases {
		if got := egressCanaryVerdict(tc.probes).Status; got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
}

// TestCanaryObservation feeds synthesized CDP events through netObs: a CSP block
// is proven by loadingFailed{blockedReason: csp} or by an enforced CSP issue, a
// report-only issue proves nothing, and a redirect counts as an answer.
func TestCanaryObservation(t *testing.T) {
	cspIssue := func(u string, reportOnly bool) *audits.EventIssueAdded {
		return &audits.EventIssueAdded{Issue: &audits.InspectorIssue{
			Code: audits.InspectorIssueCodeContentSecurityPolicyIssue,
			Details: &audits.InspectorIssueDetails{ContentSecurityPolicyIssueDetails: &audits.ContentSecurityPolicyIssueDetails{
				BlockedURL: u, ViolatedDirective: "connect-src", IsReportOnly: reportOnly}}}}
	}
	req := func(id, u string) *network.EventRequestWillBeSent {
		return &network.EventRequestWillBeSent{RequestID: network.RequestID(id), Request: &network.Request{URL: u}}
	}

	obs := newObs()
	obs.on(req("1", canaryPixel))
	obs.on(&network.EventLoadingFailed{RequestID: "1", BlockedReason: network.BlockedReasonCsp})
	obs.on(cspIssue(canaryFetch, false))
	obs.on(cspIssue(canaryBeacon, false))
	if out := egressCanaryVerdict(obs.canaryProbes()); out.Status != Pass {
		t.Errorf("every probe blocked (network csp + enforced issues): got %s (%s)", out.Status, out.Err)
	}

	obs = newObs()
	obs.on(req("1", canaryPixel))
	obs.on(&network.EventLoadingFailed{RequestID: "1", BlockedReason: network.BlockedReasonCsp})
	obs.on(cspIssue(canaryFetch, false))
	obs.on(cspIssue(canaryBeacon, true)) // report-only: the probe still goes out
	if out := egressCanaryVerdict(obs.canaryProbes()); out.Status != Inconclusive {
		t.Errorf("report-only issue for the beacon: got %s, want INCONCLUSIVE", out.Status)
	}

	obs = newObs()
	obs.on(cspIssue(canaryFetch, false))
	obs.on(cspIssue(canaryBeacon, false))
	obs.on(req("2", canaryPixel))
	obs.on(&network.EventRequestWillBeSent{RequestID: "2", Request: &network.Request{URL: "http://portal.test/login"},
		RedirectResponse: &network.Response{URL: canaryPixel, Status: 302}})
	obs.on(&network.EventLoadingFailed{RequestID: "2", BlockedReason: network.BlockedReasonCsp})
	if out := egressCanaryVerdict(obs.canaryProbes()); out.Status != Fail {
		t.Errorf("pixel answered with a redirect, then its target CSP-blocked: got %s, want FAIL", out.Status)
	}
}

func TestServiceWorkerVerdict(t *testing.T) {
	self := "me.test"
	if serviceWorkerVerdict(self, nil).Status != Inconclusive {
		t.Error("no SW observed: want INCONCLUSIVE (declared but absent)")
	}
	ok := []swReg{{Scope: "https://me.test/", Script: "https://me.test/sw.js"}}
	if serviceWorkerVerdict(self, ok).Status != Pass {
		t.Error("same-origin SW: want PASS")
	}
	crossScript := []swReg{{Scope: "https://me.test/", Script: "https://cdn.evil/sw.js"}}
	if serviceWorkerVerdict(self, crossScript).Status != Fail {
		t.Error("cross-origin SW script: want FAIL")
	}
	crossScope := []swReg{{Scope: "https://other.test/", Script: "https://me.test/sw.js"}}
	if serviceWorkerVerdict(self, crossScope).Status != Fail {
		t.Error("cross-origin SW scope: want FAIL")
	}
}

func TestStorageVerdict(t *testing.T) {
	allow := []string{"theme"}
	if storageVerdict(allow, storageObs{Local: []string{"theme"}}).Status != Pass {
		t.Error("allow-listed key only: want PASS")
	}
	out := storageVerdict(allow, storageObs{Local: []string{"theme"}, Session: []string{"redux_token"}})
	if out.Status != Fail || !strings.Contains(out.Evidence.Observed, "redux_token") {
		t.Errorf("undeclared key: want FAIL naming redux_token, got %s / %q", out.Status, out.Evidence.Observed)
	}
	if storageVerdict(nil, storageObs{}).Status != Pass {
		t.Error("no storage at all: want PASS")
	}
}

// TestClientStorageIntegration drives a real headless browser when one is
// resolvable (Docker image / local install); it SKIPS in a bare CI runner. The
// pure-verdict tests above carry the hermetic guarantee regardless.
func TestClientStorageIntegration(t *testing.T) {
	chrome := DiscoverTools().Chrome
	if chrome == "" {
		t.Skip("no Chrome/Chromium resolvable; skipping browser integration")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body><script>localStorage.setItem('x','1')</script></body></html>`))
	}))
	defer srv.Close()

	undeclared := chkClientStorage(context.Background(), &CheckCtx{
		Surface: manifest.Surface{URL: srv.URL}, Tools: Toolbox{Chrome: chrome},
	})
	if undeclared.Status != Fail {
		t.Errorf("undeclared localStorage key: got %s (%s), want FAIL", undeclared.Status, undeclared.Err)
	}
	allowed := chkClientStorage(context.Background(), &CheckCtx{
		Surface: manifest.Surface{URL: srv.URL},
		Allow:   manifest.Allow{Storage: []string{"x"}},
		Tools:   Toolbox{Chrome: chrome},
	})
	if allowed.Status != Pass {
		t.Errorf("allow-listed localStorage key: got %s (%s), want PASS", allowed.Status, allowed.Err)
	}
}

// withCanaryNetwork points the headless browser's resolver for the canary host at
// rule (e.g. a local TLS server standing in for a captive portal, or ~NOTFOUND for
// an egress-less runner) for the duration of the test.
func withCanaryNetwork(t *testing.T, rule string) {
	t.Helper()
	prev := extraBrowserFlags
	extraBrowserFlags = []chromedp.ExecAllocatorOption{
		chromedp.Flag("host-resolver-rules", rule),
		chromedp.Flag("ignore-certificate-errors", true),
	}
	t.Cleanup(func() { extraBrowserFlags = prev })
}

// cspPage serves a blank page under the given CSP header (none if hdr is "").
func cspPage(t *testing.T, hdr, policy string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hdr != "" {
			w.Header().Set(hdr, policy)
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body>surface</body></html>`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// TestEgressCanaryIntegration drives the canary in a real headless browser with
// the canary host resolved to a local server (an environment that answers it,
// like a captive portal or transparent proxy) or to nothing (a runner with no
// egress). PASS must come from an observed CSP block, never from the absence of
// a response (issue #16).
func TestEgressCanaryIntegration(t *testing.T) {
	chrome := DiscoverTools().Chrome
	if chrome == "" {
		t.Skip("no Chrome/Chromium resolvable; skipping browser integration")
	}
	portal := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("captive portal"))
	}))
	defer portal.Close()
	_, port, _ := net.SplitHostPort(portal.Listener.Addr().String())
	answers := "MAP " + canaryHost + " 127.0.0.1:" + port
	unreachable := "MAP " + canaryHost + " ~NOTFOUND"
	const csp, ro = "Content-Security-Policy", "Content-Security-Policy-Report-Only"

	cases := []struct {
		name, network, hdr, policy string
		want                       Status
	}{
		{"strict CSP, environment answers the canary", answers, csp, "default-src 'none'", Pass},
		{"strict CSP, canary unreachable", unreachable, csp, "default-src 'none'", Pass},
		{"no CSP, environment answers the canary", answers, "", "", Fail},
		{"img-src admits the canary host", answers, csp, "default-src 'none'; img-src https://" + canaryHost, Fail},
		{"no CSP, canary unreachable", unreachable, "", "", Inconclusive},
		{"report-only CSP, canary unreachable", unreachable, ro, "default-src 'none'", Inconclusive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withCanaryNetwork(t, tc.network)
			out := chkEgressCanary(context.Background(), &CheckCtx{
				Surface: manifest.Surface{URL: cspPage(t, tc.hdr, tc.policy)}, Tools: Toolbox{Chrome: chrome},
			})
			if out.Status != tc.want {
				t.Errorf("got %s (observed %q, err %q), want %s", out.Status, out.Evidence.Observed, out.Err, tc.want)
			}
		})
	}
}

// TestPreConsentVerdictExpandedCatalog pins RUN-03: AG-PRV-02 now flags the wider
// analytics/tracker catalog, not just the original 8 hosts — cloudflareinsights
// (the audiolibri.org repro), plausible, posthog, etc. A first-party or neutral
// host still passes.
func TestPreConsentVerdictExpandedCatalog(t *testing.T) {
	fail := []string{
		"static.cloudflareinsights.com", "plausible.io", "us.i.posthog.com",
		"cdn.mxpnl.com", "static.hotjar.com", "www.clarity.ms", "mc.yandex.ru",
	}
	for _, h := range fail {
		if out := preConsentVerdict([]string{"me.test", h}); out.Status != Fail {
			t.Errorf("pre-consent egress to %s: got %s, want FAIL", h, out.Status)
		}
	}
	pass := [][]string{
		{"me.test"}, {"cdn.me.test", "fonts-but-first-party.me.test"}, {},
	}
	for _, hs := range pass {
		if out := preConsentVerdict(hs); out.Status != Pass {
			t.Errorf("%v: got %s, want PASS", hs, out.Status)
		}
	}
}
