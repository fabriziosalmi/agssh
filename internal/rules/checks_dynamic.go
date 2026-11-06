package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/audits"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

// canaryHost is a resolvable but non-allowlisted host. example.com is
// IANA-reserved for exactly this kind of test traffic and carries no payload.
const canaryHost = "example.com"

// The canary fires one probe per egress channel: fetch and sendBeacon are
// governed by connect-src, the pixel by img-src.
const (
	canaryFetch  = "https://" + canaryHost + "/agssh-canary-probe"
	canaryPixel  = "https://" + canaryHost + "/agssh-canary-pixel.png"
	canaryBeacon = "https://" + canaryHost + "/agssh-canary-beacon"
)

var canaryProbeURLs = []string{canaryFetch, canaryPixel, canaryBeacon}

const canaryJS = `(function(){
  try{ fetch('` + canaryFetch + `',{mode:'no-cors'}).catch(function(){}); }catch(e){}
  try{ var i=new Image(); i.src='` + canaryPixel + `'; }catch(e){}
  try{ if(navigator.sendBeacon){ navigator.sendBeacon('` + canaryBeacon + `','probe'); } }catch(e){}
  return 1;
})()`

// canaryWait bounds how long the canary waits for every probe to reach an
// outcome after it fires. A probe still without one is INCONCLUSIVE.
const canaryWait = 10 * time.Second

type netObs struct {
	mu        sync.Mutex
	requested map[string]bool
	responded map[string]bool

	// Per-URL outcomes, for the canary. loadingFailed carries only a request id,
	// so urls maps it back to the URL the request was for.
	urls       map[network.RequestID]string
	answered   map[string]bool   // a response (or a redirect) came back for the URL
	failed     map[string]string // loadingFailed: blockedReason, else the net error
	cspBlocked map[string]bool   // an enforced (not report-only) CSP blocked the URL
	changed    chan struct{}     // signalled after every recorded event
}

func newObs() *netObs {
	return &netObs{
		requested: map[string]bool{}, responded: map[string]bool{},
		urls: map[network.RequestID]string{}, answered: map[string]bool{},
		failed: map[string]string{}, cspBlocked: map[string]bool{},
		changed: make(chan struct{}, 1),
	}
}

func (o *netObs) on(ev interface{}) {
	o.mu.Lock()
	switch e := ev.(type) {
	case *network.EventRequestWillBeSent:
		o.requested[hostOnly(e.Request.URL)] = true
		o.urls[e.RequestID] = e.Request.URL
		if e.RedirectResponse != nil {
			// The redirected URL was answered: the request left the browser.
			o.answered[e.RedirectResponse.URL] = true
		}
	case *network.EventResponseReceived:
		o.responded[hostOnly(e.Response.URL)] = true
		o.answered[e.Response.URL] = true
	case *network.EventLoadingFailed:
		if u, ok := o.urls[e.RequestID]; ok {
			reason := string(e.BlockedReason)
			if reason == "" {
				reason = e.ErrorText
			}
			if reason == "" {
				reason = "failed without a reason"
			}
			o.failed[u] = reason
		}
	case *audits.EventIssueAdded:
		// Chrome reports CSP-blocked fetch/sendBeacon here only: they are stopped
		// in the renderer and never reach the network domain.
		if e.Issue != nil && e.Issue.Details != nil {
			if d := e.Issue.Details.ContentSecurityPolicyIssueDetails; d != nil && !d.IsReportOnly && d.BlockedURL != "" {
				o.cspBlocked[d.BlockedURL] = true
			}
		}
	default:
		o.mu.Unlock()
		return
	}
	o.mu.Unlock()
	select {
	case o.changed <- struct{}{}:
	default:
	}
}

// canaryProbe is what was observed for one canary URL.
type canaryProbe struct {
	URL        string `json:"url"`
	Answered   bool   `json:"answered"`
	CSPBlocked bool   `json:"csp_blocked"`
	Failure    string `json:"failure,omitempty"`
}

func (p canaryProbe) settled() bool { return p.Answered || p.CSPBlocked || p.Failure != "" }

func (o *netObs) canaryProbes() []canaryProbe {
	o.mu.Lock()
	defer o.mu.Unlock()
	ps := make([]canaryProbe, 0, len(canaryProbeURLs))
	for _, u := range canaryProbeURLs {
		p := canaryProbe{URL: u, Answered: o.answered[u], CSPBlocked: o.cspBlocked[u]}
		switch f := o.failed[u]; {
		case f == string(network.BlockedReasonCsp):
			p.CSPBlocked = true
		case f != "":
			p.Failure = f
		}
		ps = append(ps, p)
	}
	return ps
}

// awaitCanary returns once every canary probe has an outcome, or after wait.
// Expiry is not an error: the verdict reports unsettled probes as INCONCLUSIVE.
func awaitCanary(obs *netObs, wait time.Duration) chromedp.ActionFunc {
	return func(ctx context.Context) error {
		deadline := time.NewTimer(wait)
		defer deadline.Stop()
		for {
			settled := true
			for _, p := range obs.canaryProbes() {
				settled = settled && p.settled()
			}
			if settled {
				return nil
			}
			select {
			case <-obs.changed:
			case <-deadline.C:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

func (o *netObs) respondedHosts() []string { return o.hosts(o.responded) }
func (o *netObs) requestedHosts() []string { return o.hosts(o.requested) }

func (o *netObs) hosts(set map[string]bool) []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	var hs []string
	for h := range set {
		hs = append(hs, h)
	}
	return hs
}

// extraBrowserFlags is a test seam: tests append Chrome switches (e.g.
// host-resolver-rules) to stand a local server in for the canary host. It is
// never set outside tests.
var extraBrowserFlags []chromedp.ExecAllocatorOption

// headless starts a headless Chrome tab under parent and returns its context.
// The cancel func tears down the tab and the browser process.
func headless(parent context.Context, chromePath string) (context.Context, context.CancelFunc) {
	opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	opts = append(opts, chromedp.Headless, chromedp.DisableGPU, chromedp.NoSandbox)
	if chromePath != "" {
		opts = append(opts, chromedp.ExecPath(chromePath))
	}
	opts = append(opts, extraBrowserFlags...)
	allocCtx, cancelA := chromedp.NewExecAllocator(parent, opts...)
	ctx, cancel := chromedp.NewContext(allocCtx)
	// Safety cap on a headless run (a hung browser must not wedge the check). 45s
	// matches the CLI's default per-check budget and leaves headroom for a cold
	// Chrome start under load / the race detector on CI, where 30s could flake.
	ctx, cancelT := context.WithTimeout(ctx, 45*time.Second)
	return ctx, func() { cancelT(); cancel(); cancelA() }
}

// browse loads url in headless Chrome, optionally injecting JS, and returns the
// observed network activity. Errors (e.g. no Chrome) propagate -> Inconclusive.
func browse(parent context.Context, chromePath, url, inject string, settle time.Duration) (*netObs, error) {
	ctx, cancel := headless(parent, chromePath)
	defer cancel()

	obs := newObs()
	chromedp.ListenTarget(ctx, obs.on)

	tasks := chromedp.Tasks{
		network.Enable(),
		chromedp.Navigate(url),
		chromedp.Sleep(settle),
	}
	if inject != "" {
		var res []byte
		tasks = append(tasks, chromedp.Evaluate(inject, &res))
		tasks = append(tasks, chromedp.Sleep(2*time.Second))
	}
	if err := chromedp.Run(ctx, tasks); err != nil {
		return obs, err
	}
	return obs, nil
}

func hostSuffixIn(host string, list []string) (string, bool) {
	for _, t := range list {
		if host == t || strings.HasSuffix(host, "."+t) {
			return t, true
		}
	}
	return "", false
}

// AG-NET-05: observed network shows no third-party response origins. Hosts the
// manifest explicitly declares (egressAllowed) are not reported, with the same
// level gating and exact-host semantics as AG-NET-02/-04.
func chkOfflineProof(ctx context.Context, c *CheckCtx) Outcome {
	if c.Tools.Chrome == "" {
		return inconclusive("no Chrome/Chromium found for headless verification")
	}
	obs, err := browse(ctx, c.Tools.Chrome, c.Surface.URL, "", 3*time.Second)
	if err != nil {
		return inconclusive("headless load failed: " + err.Error())
	}
	return offlineProofVerdict(hostOnly(c.Surface.URL), obs.respondedHosts(), egressAllowed(c))
}

// egressAllowed returns the hosts the manifest declares as legitimate egress:
// allow.connect and allow.subresources from L1 (scoped egress), allow.embeds from
// L2 (marketing). Entries may be origins or bare hosts; L0 (strict air-gap)
// allows nothing. Matching stays exact-host: a sibling subdomain of the surface is
// NOT implicitly first-party (consistent with AG-NET-02) and must be declared.
func egressAllowed(c *CheckCtx) []string {
	var raw []string
	if c.Level >= 1 {
		raw = append(raw, c.Allow.Connect...)
		raw = append(raw, c.Allow.Subresources...)
	}
	if c.Level >= 2 {
		raw = append(raw, c.Allow.Embeds...)
	}
	hosts := make([]string, 0, len(raw))
	for _, e := range raw {
		if h := hostOnly(e); h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// offlineProofVerdict fails if any responded host is third-party and not declared
// in allow (exact host match).
func offlineProofVerdict(self string, responded, allow []string) Outcome {
	var third []string
	for _, h := range responded {
		if h == "" || h == self || hostAllowed(h, allow) {
			continue
		}
		third = append(third, h)
	}
	if len(third) > 0 {
		return bad("third-party responses from: "+strings.Join(uniq(third), ", "), "no third-party network during load")
	}
	return okay("no third-party responses observed during load", "")
}

// AG-PRV-02: no tracker beacons fire before any consent interaction.
func chkPreConsentEgress(ctx context.Context, c *CheckCtx) Outcome {
	if c.Tools.Chrome == "" {
		return inconclusive("no Chrome/Chromium found for headless verification")
	}
	obs, err := browse(ctx, c.Tools.Chrome, c.Surface.URL, "", 3*time.Second)
	if err != nil {
		return inconclusive("headless load failed: " + err.Error())
	}
	return preConsentVerdict(obs.requestedHosts())
}

// preConsentVerdict fails if the first-visit (no-consent) load contacted any
// known third-party analytics/tracker host. The catalog (analyticsHosts) is
// shared with AG-PRV-01; expanding it from the original 8-host list is the RUN-03
// fix — a request is an actual egress, so host-matching here carries no
// false-positive risk (unlike static substring scans of the HTML body).
func preConsentVerdict(requested []string) Outcome {
	for _, h := range requested {
		if t, hit := isAnalyticsHost(h); hit {
			return bad("tracker contacted pre-consent: "+t, "no analytics/tracker egress before consent")
		}
	}
	return okay("no pre-consent tracker egress", "")
}

// AG-GOV-06: the active egress canary — a known probe to a non-allowlisted
// origin MUST be blocked by the page's CSP, and the block must be observed.
func chkEgressCanary(ctx context.Context, c *CheckCtx) Outcome {
	if c.Tools.Chrome == "" {
		return inconclusive("no Chrome/Chromium found for canary verification")
	}
	bctx, cancel := headless(ctx, c.Tools.Chrome)
	defer cancel()
	obs := newObs()
	chromedp.ListenTarget(bctx, obs.on)
	var res []byte
	err := chromedp.Run(bctx,
		network.Enable(),
		audits.Enable(),
		chromedp.Navigate(c.Surface.URL),
		chromedp.Sleep(1*time.Second), // the post-load settle this check always had, kept as is
		chromedp.Evaluate(canaryJS, &res),
		awaitCanary(obs, canaryWait),
	)
	if err != nil {
		return inconclusive("headless canary run failed: " + err.Error())
	}
	return egressCanaryVerdict(obs.canaryProbes())
}

// egressCanaryVerdict judges the canary from what was observed per probe.
// FAIL: a probe was answered. A CSP-blocked request never leaves the browser, so
// a response (from the canary host, a captive portal or a proxy alike) proves
// the page's CSP let that channel out. PASS: every probe was blocked by an
// enforced CSP, as reported by the browser. Anything else (a network error, a
// report-only policy, no event at all) proves nothing: INCONCLUSIVE.
func egressCanaryVerdict(probes []canaryProbe) Outcome {
	var answered, unproven []string
	for _, p := range probes {
		switch {
		case p.Answered:
			answered = append(answered, p.URL)
		case p.CSPBlocked:
		case p.Failure != "":
			unproven = append(unproven, p.URL+" ("+p.Failure+")")
		default:
			unproven = append(unproven, p.URL+" (no outcome observed within "+canaryWait.String()+")")
		}
	}
	detail := map[string]any{"probes": probes}
	if len(answered) > 0 {
		return Outcome{Status: Fail, Evidence: Evidence{
			Observed: "canary probe(s) left the browser and were answered: " + strings.Join(answered, ", "),
			Expected: "an enforced CSP blocks every canary probe",
			Detail:   detail}}
	}
	if len(probes) == 0 {
		return inconclusive("no canary probe observed")
	}
	if len(unproven) > 0 {
		return Outcome{Status: Inconclusive, Err: "canary not proven blocked by CSP: " + strings.Join(unproven, "; "),
			Evidence: Evidence{Detail: detail}}
	}
	return Outcome{Status: Pass, Evidence: Evidence{
		Observed: fmt.Sprintf("all %d canary probes to %s blocked by an enforced CSP", len(probes), canaryHost),
		Detail:   detail}}
}

// browseEval loads url in headless Chrome and returns the JSON string produced by
// js (which must itself JSON.stringify its result). await=true unwraps a Promise.
func browseEval(parent context.Context, chromePath, url, js string, settle time.Duration, await bool) (string, error) {
	ctx, cancel := headless(parent, chromePath)
	defer cancel()

	var out string
	var eval chromedp.Action
	if await {
		eval = chromedp.Evaluate(js, &out, func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
			return p.WithAwaitPromise(true)
		})
	} else {
		eval = chromedp.Evaluate(js, &out)
	}
	err := chromedp.Run(ctx, chromedp.Navigate(url), chromedp.Sleep(settle), eval)
	return out, err
}

type swReg struct {
	Scope  string `json:"scope"`
	Script string `json:"script"`
}

// swWait bounds how long after load AG-NET-07 waits for a registration. Sites
// often register on load or when idle, which a cold Chrome can push past a few
// seconds. The browse cap (and the per-check budget) still bounds the whole run.
const swWait = 10 * time.Second

// serviceWorkerJS polls getRegistrations() until one appears or swWait passes,
// then resolves to the JSON array of registrations (empty if none, or if the
// page has no service-worker API). A rejection propagates as an eval error.
var serviceWorkerJS = `(navigator.serviceWorker ? new Promise(function(resolve, reject){` +
	`var deadline=Date.now()+` + strconv.FormatInt(swWait.Milliseconds(), 10) + `;` +
	`(function poll(){navigator.serviceWorker.getRegistrations().then(function(rs){` +
	`if(rs.length===0&&Date.now()<deadline){setTimeout(poll,100);return;}` +
	`resolve(JSON.stringify(rs.map(function(r){var w=r.active||r.waiting||r.installing||{};` +
	`return {scope:r.scope||'', script:w.scriptURL||''};})));},reject);})();}) : "[]")`

// AG-NET-07: a registered Service Worker is same-origin (script and scope).
func chkServiceWorker(ctx context.Context, c *CheckCtx) Outcome {
	if c.Tools.Chrome == "" {
		return inconclusive("no Chrome/Chromium for service-worker inspection")
	}
	out, err := browseEval(ctx, c.Tools.Chrome, c.Surface.URL, serviceWorkerJS, 0, true)
	if err != nil {
		return inconclusive("headless service-worker inspection failed: " + err.Error())
	}
	var regs []swReg
	if e := json.Unmarshal([]byte(out), &regs); e != nil {
		return inconclusive("could not parse service-worker registrations: " + e.Error())
	}
	return serviceWorkerVerdict(hostOnly(c.Surface.URL), regs)
}

func serviceWorkerVerdict(self string, regs []swReg) Outcome {
	if len(regs) == 0 {
		return inconclusive("surface declares a service worker but none was registered within " + swWait.String() + " of load")
	}
	for _, r := range regs {
		if r.Script != "" && hostOnly(r.Script) != self {
			return bad("service-worker script is cross-origin: "+r.Script, "same-origin service-worker script")
		}
		if r.Scope != "" && hostOnly(r.Scope) != self {
			return bad("service-worker scope is cross-origin: "+r.Scope, "same-origin service-worker scope")
		}
	}
	return okay(fmt.Sprintf("%d service worker(s), all same-origin", len(regs)), "")
}

type storageObs struct {
	Local   []string `json:"local"`
	Session []string `json:"session"`
}

// storageJS enumerates ONLY localStorage/sessionStorage. Cookies are excluded on
// purpose: document.cookie reports server-set (Set-Cookie) cookies that the page
// author didn't choose as client storage, and never the HttpOnly ones — cookie
// hardening is AG-PRV-05's job, not AG-PRV-04's. Accessors are wrapped so a
// SecurityError in a storage-disabled/opaque context yields empty, not a throw.
const storageJS = `(function(){var r={local:[],session:[]};` +
	`try{r.local=Object.keys(localStorage)}catch(e){}` +
	`try{r.session=Object.keys(sessionStorage)}catch(e){}` +
	`return JSON.stringify(r);})()`

// AG-PRV-04: client storage is minimized to the declared allow-list.
func chkClientStorage(ctx context.Context, c *CheckCtx) Outcome {
	if c.Tools.Chrome == "" {
		return inconclusive("no Chrome/Chromium for client-storage inspection")
	}
	out, err := browseEval(ctx, c.Tools.Chrome, c.Surface.URL, storageJS, 3*time.Second, false)
	if err != nil {
		return inconclusive("headless client-storage inspection failed: " + err.Error())
	}
	var obs storageObs
	if e := json.Unmarshal([]byte(out), &obs); e != nil {
		return inconclusive("could not parse client storage: " + e.Error())
	}
	return storageVerdict(c.Allow.Storage, obs)
}

func storageVerdict(allow []string, obs storageObs) Outcome {
	permitted := map[string]bool{}
	for _, k := range allow {
		permitted[k] = true
	}
	seen := map[string]bool{}
	var offenders []string
	for _, group := range [][]string{obs.Local, obs.Session} {
		for _, k := range group {
			if k == "" || permitted[k] || seen[k] {
				continue
			}
			seen[k] = true
			offenders = append(offenders, k)
		}
	}
	if len(offenders) > 0 {
		return bad("client-storage keys outside the allow-list: "+strings.Join(offenders, ", "),
			"only declared allow.storage keys persisted")
	}
	total := len(obs.Local) + len(obs.Session)
	return okay(fmt.Sprintf("%d client-storage key(s), all allow-listed", total), "")
}
