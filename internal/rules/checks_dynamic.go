package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

// canaryOrigin is a resolvable but non-allowlisted host. A *successful*
// response to it means the CSP egress boundary is down. example.com is
// IANA-reserved for exactly this kind of test traffic and carries no payload.
const canaryHost = "example.com"
const canaryJS = `(function(){
  try{ fetch('https://example.com/agssh-canary-probe',{mode:'no-cors'}); }catch(e){}
  try{ var i=new Image(); i.src='https://example.com/agssh-canary-pixel.png'; }catch(e){}
  try{ if(navigator.sendBeacon){ navigator.sendBeacon('https://example.com/agssh-canary-beacon','probe'); } }catch(e){}
  return 1;
})()`

var trackerHosts = []string{
	"googletagmanager.com", "google-analytics.com", "analytics.google.com",
	"stats.g.doubleclick.net", "connect.facebook.net", "px.ads.linkedin.com",
	"cdn.segment.com", "static.hotjar.com",
}

type netObs struct {
	mu        sync.Mutex
	requested map[string]bool
	responded map[string]bool
}

func newObs() *netObs {
	return &netObs{requested: map[string]bool{}, responded: map[string]bool{}}
}

func (o *netObs) on(ev interface{}) {
	switch e := ev.(type) {
	case *network.EventRequestWillBeSent:
		o.mu.Lock()
		o.requested[hostOnly(e.Request.URL)] = true
		o.mu.Unlock()
	case *network.EventResponseReceived:
		o.mu.Lock()
		o.responded[hostOnly(e.Response.URL)] = true
		o.mu.Unlock()
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

// browse loads url in headless Chrome, optionally injecting JS, and returns the
// observed network activity. Errors (e.g. no Chrome) propagate -> Inconclusive.
func browse(parent context.Context, chromePath, url, inject string, settle time.Duration) (*netObs, error) {
	opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	opts = append(opts, chromedp.Headless, chromedp.DisableGPU, chromedp.NoSandbox)
	if chromePath != "" {
		opts = append(opts, chromedp.ExecPath(chromePath))
	}
	allocCtx, cancelA := chromedp.NewExecAllocator(parent, opts...)
	defer cancelA()
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()
	ctx, cancelT := context.WithTimeout(ctx, 30*time.Second)
	defer cancelT()

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

// AG-NET-05: observed network shows no third-party response origins.
func chkOfflineProof(ctx context.Context, c *CheckCtx) Outcome {
	if c.Tools.Chrome == "" {
		return inconclusive("no Chrome/Chromium found for headless verification")
	}
	obs, err := browse(ctx, c.Tools.Chrome, c.Surface.URL, "", 3*time.Second)
	if err != nil {
		return inconclusive("headless load failed: " + err.Error())
	}
	return offlineProofVerdict(hostOnly(c.Surface.URL), obs.respondedHosts())
}

// offlineProofVerdict fails if any responded host is third-party.
func offlineProofVerdict(self string, responded []string) Outcome {
	var third []string
	for _, h := range responded {
		if h == "" || h == self {
			continue
		}
		third = append(third, h)
	}
	if len(third) > 0 {
		return bad("third-party responses from: "+strings.Join(uniq(third), ", "), "no third-party network during load")
	}
	return okay("only first-party responses observed", "")
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

// preConsentVerdict fails if any requested host is a known tracker.
func preConsentVerdict(requested []string) Outcome {
	for _, h := range requested {
		if t, hit := hostSuffixIn(h, trackerHosts); hit {
			return bad("tracker contacted pre-consent: "+t, "no analytics/tracker egress before consent")
		}
	}
	return okay("no pre-consent tracker egress", "")
}

// AG-GOV-06: the active egress canary — a known probe to a non-allowlisted
// origin MUST be blocked. A successful response means the wall is down.
func chkEgressCanary(ctx context.Context, c *CheckCtx) Outcome {
	if c.Tools.Chrome == "" {
		return inconclusive("no Chrome/Chromium found for canary verification")
	}
	obs, err := browse(ctx, c.Tools.Chrome, c.Surface.URL, canaryJS, 1*time.Second)
	if err != nil {
		return inconclusive("headless canary run failed: " + err.Error())
	}
	obs.mu.Lock()
	attempted, got := obs.requested[canaryHost], obs.responded[canaryHost]
	obs.mu.Unlock()
	return egressCanaryVerdict(attempted, got)
}

// egressCanaryVerdict: a response to the canary means the egress wall is down.
func egressCanaryVerdict(attempted, responded bool) Outcome {
	if responded {
		return Outcome{Status: Fail, Evidence: Evidence{
			Observed: "canary probe to " + canaryHost + " received a response",
			Expected: "CSP blocks the probe (no response)",
			Detail:   map[string]any{"attempted": attempted, "responded": true}}}
	}
	return Outcome{Status: Pass, Evidence: Evidence{
		Observed: "canary probe blocked (no response from " + canaryHost + ")",
		Detail:   map[string]any{"attempted": attempted, "responded": false}}}
}

// browseEval loads url in headless Chrome and returns the JSON string produced by
// js (which must itself JSON.stringify its result). await=true unwraps a Promise.
func browseEval(parent context.Context, chromePath, url, js string, settle time.Duration, await bool) (string, error) {
	opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	opts = append(opts, chromedp.Headless, chromedp.DisableGPU, chromedp.NoSandbox)
	if chromePath != "" {
		opts = append(opts, chromedp.ExecPath(chromePath))
	}
	allocCtx, cancelA := chromedp.NewExecAllocator(parent, opts...)
	defer cancelA()
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()
	ctx, cancelT := context.WithTimeout(ctx, 30*time.Second)
	defer cancelT()

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

const serviceWorkerJS = `(navigator.serviceWorker ? navigator.serviceWorker.getRegistrations().then(function(rs){` +
	`return JSON.stringify(rs.map(function(r){var w=r.active||r.waiting||r.installing||{};` +
	`return {scope:r.scope||'', script:w.scriptURL||''};}));}) : "[]")`

// AG-NET-07: a registered Service Worker is same-origin (script and scope).
func chkServiceWorker(ctx context.Context, c *CheckCtx) Outcome {
	if c.Tools.Chrome == "" {
		return inconclusive("no Chrome/Chromium for service-worker inspection")
	}
	out, err := browseEval(ctx, c.Tools.Chrome, c.Surface.URL, serviceWorkerJS, 3*time.Second, true)
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
		return inconclusive("surface declares a service worker but none was registered at load")
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
	Cookies []string `json:"cookies"`
}

const storageJS = `JSON.stringify({local:Object.keys(localStorage), session:Object.keys(sessionStorage),` +
	`cookies: document.cookie ? document.cookie.split(';').map(function(c){return c.split('=')[0].trim();}) : []})`

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
	for _, group := range [][]string{obs.Local, obs.Session, obs.Cookies} {
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
	total := len(obs.Local) + len(obs.Session) + len(obs.Cookies)
	return okay(fmt.Sprintf("%d client-storage key(s), all allow-listed", total), "")
}
