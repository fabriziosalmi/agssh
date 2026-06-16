package rules

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
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

func (o *netObs) respondedHosts() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	var hs []string
	for h := range o.responded {
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
	self := hostOnly(c.Surface.URL)
	var third []string
	for _, h := range obs.respondedHosts() {
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
	obs.mu.Lock()
	defer obs.mu.Unlock()
	for h := range obs.requested {
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
	attempted := obs.requested[canaryHost]
	got := obs.responded[canaryHost]
	obs.mu.Unlock()
	if got {
		return Outcome{Status: Fail, Evidence: Evidence{
			Observed: "canary probe to " + canaryHost + " received a response",
			Expected: "CSP blocks the probe (no response)",
			Detail:   map[string]any{"attempted": attempted, "responded": true}}}
	}
	return Outcome{Status: Pass, Evidence: Evidence{
		Observed: "canary probe blocked (no response from " + canaryHost + ")",
		Detail:   map[string]any{"attempted": attempted, "responded": false}}}
}
