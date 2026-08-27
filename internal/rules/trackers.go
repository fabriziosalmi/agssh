package rules

import "strings"

// analyticsHosts is the canonical set of third-party analytics / tracking /
// session-replay / advertising telemetry hosts, as registrable domains or exact
// hostnames. It is the single source of truth shared by the two privacy rules:
//
//   - AG-PRV-01 (static)  — is such a host REFERENCED in the shipped HTML
//     (a <script src>, <link>, <img>, <iframe> … that actually loads it)?
//   - AG-PRV-02 (dynamic) — is such a host REQUESTED at runtime, pre-consent?
//
// Detection is HOST-based on purpose. An earlier implementation substring-matched
// the HTML body for code tokens (gtag(, _paq, G-XXXXXXXXXX, …). An adversarial
// review showed that approach false-positives on exactly agssh's audience: a
// privacy tool's own docs page that *explains* how to remove Google Analytics,
// a GDPR guide teaching readers to block the Meta pixel, or even the string
// "G-quadruplex" all match those tokens while running zero analytics. A host that
// appears in a resource-loading attribute (or an actual network request) is a
// real load, not prose — so it is the signal we key on. The trade-off is that
// FIRST-PARTY self-hosted counters (a Matomo on your own origin) are out of
// scope; that is a far weaker privacy concern (no third-party data transfer, the
// core AG-PRV rationale) and cannot be told from prose statically without the
// false positives above.
//
// Every entry serves ONLY telemetry for its vendor — never a shared CDN, and
// never a host that also serves a legitimate non-tracking function. The catalog
// was adversarially audited host-by-host for exactly that: a fail on a CRITICAL
// MUST has to be TRUE, so soundness beats completeness. Hosts that double as
// something a clean site loads for FUNCTION are deliberately excluded — the FB
// JS SDK (Login/embeds) on connect.facebook.net, support-chat widgets (Intercom),
// feature-flag / survey / in-app-guidance control planes (Statsig, PostHog
// *-assets, Pendo agent, Piwik PRO's CMP), and general asset CDNs (Klaviyo's
// static host). Where a vendor separates its tracking host from its functional
// one, only the tracking host is kept (events.statsigapi.net, a.klaviyo.com,
// data.pendo.io, us/eu.i.posthog.com). The cost is missing a tracker that shares
// a host with a functional service — an acceptable trade for zero false alarms.
var analyticsHosts = []string{
	// Google (Analytics, Tag Manager, Ads/DoubleClick)
	"google-analytics.com", "analytics.google.com", "googletagmanager.com",
	"stats.g.doubleclick.net", "doubleclick.net", "googleadservices.com", "googlesyndication.com",
	// Meta / LinkedIn / TikTok / X pixels
	// (connect.facebook.net is deliberately EXCLUDED: the same host serves the FB
	// JS SDK — Login, Like/Share, embeds, Messenger — a legitimate non-tracking
	// load. The pixel would need path-level matching (fbevents.js), which a
	// host-based check cannot do; a false FAIL on a MUST is worse than the miss.)
	"px.ads.linkedin.com", "ads.linkedin.com", "snap.licdn.com",
	"analytics.tiktok.com", "analytics-sg.tiktok.com",
	// Product analytics — event sinks only. The vendors' asset/config CDNs
	// (us-assets/eu-assets.i.posthog.com, cdn.pendo.io, api.statsig.com,
	// statsigapi.net, featuregates.org) are EXCLUDED: a feature-flag / survey /
	// in-app-guidance integration loads those with no telemetry, so matching them
	// would false-FAIL a clean functional use.
	"api.mixpanel.com", "api-eu.mixpanel.com", "api-js.mixpanel.com", "cdn.mxpnl.com",
	"api.amplitude.com", "api2.amplitude.com", "api.eu.amplitude.com", "cdn.amplitude.com", "cdn.eu.amplitude.com",
	"heapanalytics.com", "cdn.heapanalytics.com",
	"app.posthog.com", "us.i.posthog.com", "eu.i.posthog.com",
	"data.pendo.io", "api.june.so", "cdn.june.so", "events.statsigapi.net",
	// Privacy-first & lightweight analytics
	"plausible.io", "usefathom.com", "cdn.usefathom.com",
	"umami.is", "api.umami.is", "cloud.umami.is", "analytics.umami.is",
	"gc.zgo.at", "goatcounter.com",
	"simpleanalytics.com", "simpleanalyticscdn.com", "scripts.simpleanalyticscdn.com", "queue.simpleanalyticscdn.com",
	"pirsch.io", "api.pirsch.io", "rum.cronitor.io",
	"cloudflareinsights.com", "static.cloudflareinsights.com",
	// Session replay & product experience
	"hotjar.com", "hotjar.io", "clarity.ms", "fullstory.com",
	"logrocket.com", "logrocket.io", "lr-ingest.io", "mouseflow.com", "smartlook.com",
	"contentsquare.net", "clicktale.net",
	// Tag managers, CDPs & marketing automation
	"cdn.segment.com", "api.segment.io", "cdn.rudderlabs.com", "tags.tiqcdn.com", "collect.tealiumiq.com",
	"jssdkcdns.mparticle.com", "jssdks.mparticle.com", "identity.mparticle.com",
	"js.hs-analytics.net", "js.hs-scripts.com", "track.hubspot.com",
	"munchkin.marketo.net", "mktoresp.com",
	// Klaviyo tracking hosts only — static.klaviyo.com (its general asset CDN,
	// also serving form CSS/images) is EXCLUDED to avoid false positives.
	"static-tracking.klaviyo.com", "a.klaviyo.com",
	// (Intercom EXCLUDED entirely: it is a support/live-chat widget sites embed for
	// function; suffix-matching it would false-FAIL every site offering support.)
	// Regional
	"mc.yandex.ru", "mc.yandex.com", "hm.baidu.com",
	// Adobe Analytics / Experience Cloud
	"2o7.net", "omtrdc.net", "demdex.net", "adobedtm.com", "assets.adobedtm.com",
	// APM / RUM telemetry (transmit user data third-party)
	"js-agent.newrelic.com", "nr-data.net",
	"browser-intake-datadoghq.com", "browser-intake-datadoghq.eu", "datadoghq-browser-agent.com",
	// Hosted analytics / measurement / heatmaps not covered above
	// (piwik.pro EXCLUDED: the registrable domain also serves a standalone Consent
	// Manager / CMP usable without analytics.)
	"matomo.cloud",
	"scorecardresearch.com", "quantserve.com", "quantcount.com",
	"chartbeat.com", "static.chartbeat.com", "parsely.com", "cdn.parsely.com", "p.parsely.com",
	"crazyegg.com", "script.crazyegg.com", "kissmetrics.io", "woopra.com",
}

// isAnalyticsHost reports whether host is (a subdomain of) a known analytics /
// tracking vendor host, returning the matched catalog entry.
func isAnalyticsHost(host string) (string, bool) {
	return hostSuffixIn(strings.ToLower(strings.TrimSpace(host)), analyticsHosts)
}

// analyticsPathSignals catches trackers whose HOST is deliberately absent from
// analyticsHosts because it also serves a legitimate non-tracking resource, but
// whose tracking loader lives at a distinctive PATH. Matching (host, path) instead
// of the bare host keeps the functional sibling clean: connect.facebook.net serves
// both fbevents.js (the Meta Pixel) and sdk.js (FB Login/embeds), so we flag only
// the former. Path matching needs the full reference URL, so it is applied where
// that is available (the static plane); the dynamic plane sees hosts only.
var analyticsPathSignals = []struct{ host, pathContains, label string }{
	{"connect.facebook.net", "fbevents.js", "connect.facebook.net/fbevents.js (Meta Pixel)"},
}

// isAnalyticsRef reports whether a resource reference (host + URL path) is a known
// tracker — either a catalog host, or a functional-dual-use host on its tracking
// path. Returns the matched label.
func isAnalyticsRef(host, path string) (string, bool) {
	if t, ok := isAnalyticsHost(host); ok {
		return t, true
	}
	h, lp := strings.ToLower(strings.TrimSpace(host)), strings.ToLower(path)
	for _, s := range analyticsPathSignals {
		if (h == s.host || strings.HasSuffix(h, "."+s.host)) && strings.Contains(lp, s.pathContains) {
			return s.label, true
		}
	}
	return "", false
}
