package rules

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// effectiveResolver resolves the DNS server to query: the explicit override
// (manifest dns.resolver / -resolver), else the host's own configured resolver
// from resolv.conf. No public IP is baked into the runner — fitting for a tool
// whose thesis is "no third-party egress you didn't declare". Empty means we
// could not determine one, and the DNS checks go INCONCLUSIVE (fail-closed).
func effectiveResolver(override string) string {
	if r := strings.TrimSpace(override); r != "" {
		if _, _, err := net.SplitHostPort(r); err != nil {
			r = net.JoinHostPort(r, "53") // bare host -> :53
		}
		return r
	}
	if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cfg.Servers) > 0 {
		port := cfg.Port
		if port == "" {
			port = "53"
		}
		return net.JoinHostPort(cfg.Servers[0], port)
	}
	return ""
}

func dnsQuery(resolver, zone string, qtype uint16, wantDO bool) (*dns.Msg, error) {
	if resolver == "" {
		return nil, fmt.Errorf("no DNS resolver available (set dns.resolver or -resolver)")
	}
	m := new(dns.Msg)
	fqdn := dns.Fqdn(zone)
	m.SetQuestion(fqdn, qtype)
	if wantDO {
		m.SetEdns0(4096, true)
	}
	cl := &dns.Client{Timeout: 6 * time.Second}
	resp, _, err := cl.Exchange(m, resolver)
	return resp, err
}

// AG-DNS-01: a CAA policy exists on the zone.
func chkCAA(_ context.Context, c *CheckCtx) Outcome {
	if c.Zone == "" {
		return inconclusive("no dns.zone declared in manifest")
	}
	r := effectiveResolver(c.Resolver)
	if r == "" {
		return inconclusive("no DNS resolver available (set dns.resolver or -resolver)")
	}
	resp, err := dnsQuery(r, c.Zone, dns.TypeCAA, false)
	if err != nil {
		return inconclusive("CAA query failed: " + err.Error())
	}
	var issuers []string
	for _, rr := range resp.Answer {
		if caa, ok := rr.(*dns.CAA); ok {
			issuers = append(issuers, caa.Tag+":"+caa.Value)
		}
	}
	if len(issuers) == 0 {
		return bad("no CAA records", "a CAA policy restricting issuance")
	}
	return okay("CAA present: "+strings.Join(issuers, " "), "")
}

// AG-DNS-02: the zone is DNSSEC-signed (AD bit from a validating resolver, or
// a DNSKEY present).
func chkDNSSEC(_ context.Context, c *CheckCtx) Outcome {
	if c.Zone == "" {
		return inconclusive("no dns.zone declared in manifest")
	}
	r := effectiveResolver(c.Resolver)
	if r == "" {
		return inconclusive("no DNS resolver available (set dns.resolver or -resolver)")
	}
	resp, err := dnsQuery(r, c.Zone, dns.TypeSOA, true)
	if err != nil {
		return inconclusive("DNSSEC query failed: " + err.Error())
	}
	if resp.AuthenticatedData {
		return okay("resolver set AD (DNSSEC-validated)", "")
	}
	keyResp, err := dnsQuery(r, c.Zone, dns.TypeDNSKEY, true)
	if err == nil {
		for _, rr := range keyResp.Answer {
			if _, ok := rr.(*dns.DNSKEY); ok {
				return okay("DNSKEY present (signed zone)", "")
			}
		}
	}
	return bad("no AD bit and no DNSKEY", "DNSSEC-signed zone")
}

// AG-DNS-03: the surface host has no danglable CNAME (takeover risk). A target
// that does NOT resolve is the classic dangling case. A target that DOES resolve
// can still be an unclaimed resource on a takeover-prone provider — detected via
// the live surface body fingerprint. (The original check only caught the former.)
func chkDangling(_ context.Context, c *CheckCtx) Outcome {
	r := effectiveResolver(c.Resolver)
	if r == "" {
		return inconclusive("no DNS resolver available (set dns.resolver or -resolver)")
	}
	host := hostOnly(c.Surface.URL)
	if host == "" {
		return inconclusive("cannot derive surface host")
	}
	cn, err := dnsQuery(r, host, dns.TypeCNAME, false)
	if err != nil {
		return inconclusive("CNAME query failed: " + err.Error())
	}
	var target string
	for _, rr := range cn.Answer {
		if c2, ok := rr.(*dns.CNAME); ok {
			target = c2.Target
		}
	}
	if target == "" {
		return okay("no CNAME (apex or A/AAAA)", "")
	}
	// 1) Classic dangling: the CNAME target does not resolve.
	a, err := dnsQuery(r, target, dns.TypeA, false)
	if err != nil {
		return inconclusive("target A query failed: " + err.Error())
	}
	if a.Rcode == dns.RcodeNameError || len(a.Answer) == 0 {
		return bad("CNAME -> "+target+" does not resolve (dangling)", "every CNAME target resolves")
	}
	// 2) Target resolves but may be unclaimed: match the live body fingerprint.
	body := ""
	if c.Doc != nil {
		body = string(c.Doc.Body)
	}
	if sig, matched := takeoverFingerprint(body); matched {
		return bad("CNAME -> "+target+" serves an unclaimed-resource fingerprint: "+sig,
			"CNAME target is a claimed, serving resource")
	}
	// 3) Resolves, on a takeover-prone provider, but we have no body to confirm it
	// is claimed -> fail-closed INCONCLUSIVE rather than a silent PASS.
	if prov, ok := takeoverProvider(target); ok && body == "" {
		return inconclusive("CNAME -> " + target + " points at " + prov +
			" (takeover-prone) and the surface body is unavailable to confirm it is claimed")
	}
	return okay("CNAME -> "+target+" resolves; no takeover fingerprint", "")
}

// takeoverProvider reports whether target is hosted on a provider where an
// unclaimed/unconfigured resource is a known subdomain-takeover vector.
func takeoverProvider(target string) (string, bool) {
	t := strings.ToLower(strings.TrimSuffix(target, "."))
	for _, p := range takeoverProviders {
		if strings.HasSuffix(t, p.suffix) {
			return p.name, true
		}
	}
	return "", false
}

var takeoverProviders = []struct{ suffix, name string }{
	{".github.io", "GitHub Pages"},
	{".herokuapp.com", "Heroku"},
	{".herokudns.com", "Heroku"},
	{".s3.amazonaws.com", "AWS S3"},
	{".cloudfront.net", "AWS CloudFront"},
	{".azurewebsites.net", "Azure App Service"},
	{".cloudapp.net", "Azure Cloud"},
	{".trafficmanager.net", "Azure Traffic Manager"},
	{".blob.core.windows.net", "Azure Blob"},
	{".fastly.net", "Fastly"},
	{".ghost.io", "Ghost"},
	{".pantheonsite.io", "Pantheon"},
	{".readthedocs.io", "Read the Docs"},
	{".surge.sh", "Surge"},
	{".bitbucket.io", "Bitbucket"},
	{".netlify.app", "Netlify"},
	{".wordpress.com", "WordPress"},
	{".statuspage.io", "Statuspage"},
	{".zendesk.com", "Zendesk"},
}

// takeoverFingerprint returns a matched provider "unclaimed resource" signature
// found in the response body, if any. Signatures are kept specific to avoid
// false positives on ordinary 404 pages.
func takeoverFingerprint(body string) (string, bool) {
	lb := strings.ToLower(body)
	for _, sig := range takeoverFingerprints {
		if strings.Contains(lb, strings.ToLower(sig)) {
			return sig, true
		}
	}
	return "", false
}

var takeoverFingerprints = []string{
	"There isn't a GitHub Pages site here",
	"herokucdn.com/error-pages/no-such-app.html",
	"NoSuchBucket",
	"The specified bucket does not exist",
	"Fastly error: unknown domain",
	"Sorry, this shop is currently unavailable",                             // Shopify
	"Whatever you were looking for doesn't currently exist at this address", // Tumblr
	"Site not found · Netlify",
	"project not found", // Surge
	"This UserVoice subdomain is currently available",
	"Do you want to register *.wordpress.com",
	"Repository not found", // Bitbucket/GitHub Pages-style
}

func hostOnly(raw string) string {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
	}
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.Index(raw, ":"); i >= 0 {
		raw = raw[:i]
	}
	return strings.ToLower(raw)
}

// surfaceAddr returns host:port for the surface URL, defaulting to :443.
func surfaceAddr(raw string) string {
	h := hostOnly(raw)
	if h == "" {
		return ""
	}
	rest := strings.TrimSpace(raw)
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, ":"); i >= 0 {
		if port := rest[i+1:]; port != "" {
			return net.JoinHostPort(h, port)
		}
	}
	return net.JoinHostPort(h, "443")
}

// AG-HDR-08: TLS floor — legacy TLS (1.0/1.1) MUST be refused; 1.2+ MUST work.
//
// The legacy probe sends a hand-built TLS 1.0 ClientHello over a raw socket and
// inspects the server's first record. We do NOT use crypto/tls for the legacy
// dial: since Go 1.22 the standard library client refuses to negotiate TLS
// 1.0/1.1 itself, so a crypto/tls dial would fail client-side and we'd score a
// false PASS even against a server that still accepts legacy TLS.
func chkTLSFloor(_ context.Context, c *CheckCtx) Outcome {
	host := hostOnly(c.Surface.URL)
	addr := surfaceAddr(c.Surface.URL)
	if host == "" || addr == "" {
		return inconclusive("cannot derive surface host")
	}
	accepted, reachable := offersLegacyTLS(addr, host, 6*time.Second)
	if !reachable {
		return inconclusive("cannot reach " + addr + " for TLS probe")
	}
	if accepted {
		return bad("legacy TLS (1.0/1.1) accepted", "TLS 1.0/1.1 refused")
	}
	// Confirm 1.2+ actually works. We only assert the version floor here, not the
	// PKI (certificate validity is out of scope for this rule), so trust is skipped.
	modern := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} //nolint:gosec // version-floor probe, not a trust check
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 6 * time.Second}, "tcp", addr, modern)
	if err != nil {
		return inconclusive("legacy refused but TLS 1.2+ handshake failed: " + err.Error())
	}
	v := conn.ConnectionState().Version
	conn.Close()
	return okay(fmt.Sprintf("legacy refused; modern ok (0x%04x)", v), "")
}

// ---------- supply chain ----------

// lockfiles maps a known lockfile to the substring that proves it pins
// dependencies by integrity hash. An empty marker means the file IS the hash set
// (e.g. go.sum), so its presence alone proves pinning.
var lockfiles = []struct{ name, marker string }{
	{"package-lock.json", `"integrity"`},
	{"npm-shrinkwrap.json", `"integrity"`},
	{"yarn.lock", "integrity "},
	{"pnpm-lock.yaml", "integrity:"},
	{"Cargo.lock", "checksum = "},
	{"go.sum", ""},
	{"poetry.lock", "hash"},
	{"Pipfile.lock", `"hashes"`},
	{"composer.lock", "shasum"},
}

// AG-SUP-02: dependencies are pinned by integrity hash. We audit the recognised
// lockfiles present in the repo: each must carry integrity hashes. No recognised
// lockfile -> INCONCLUSIVE (fail-closed, nothing to prove against).
func chkPinnedDeps(_ context.Context, c *CheckCtx) Outcome {
	var audited, unpinned []string
	for _, lf := range lockfiles {
		b, err := os.ReadFile(filepath.Join(c.RepoDir, lf.name))
		if err != nil {
			continue
		}
		audited = append(audited, lf.name)
		if lf.marker != "" && !bytes.Contains(b, []byte(lf.marker)) {
			unpinned = append(unpinned, lf.name)
		}
	}
	if len(audited) == 0 {
		return inconclusive("no recognised lockfile to audit for integrity hashes")
	}
	if len(unpinned) > 0 {
		return bad("lockfile(s) without integrity hashes: "+strings.Join(unpinned, ", "),
			"every dependency pinned by integrity hash")
	}
	return okay("integrity-hash-pinned lockfiles: "+strings.Join(audited, ", "), "")
}

// AG-SUP-04: no secrets in the shipped artifact (gitleaks over dist).
func chkNoSecrets(ctx context.Context, c *CheckCtx) Outcome {
	if c.Tools.Gitleaks == "" {
		return inconclusive("gitleaks not found on PATH")
	}
	dir := c.DistDir
	if _, err := os.Stat(dir); err != nil {
		dir = c.RepoDir
	}
	cmd := exec.CommandContext(ctx, c.Tools.Gitleaks, "detect", "--no-banner", "--no-git", "--source", dir)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return okay("gitleaks: no secrets", "")
	}
	return bad("gitleaks flagged secrets: "+lastLine(out), "no secrets in shipped output")
}

// AG-SUP-05: no source maps in the shipped artifact.
func chkNoSourceMaps(_ context.Context, c *CheckCtx) Outcome {
	dir := c.DistDir
	if _, err := os.Stat(dir); err != nil {
		return inconclusive("dist dir not found: " + dir)
	}
	var found []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(p, ".map") {
			found = append(found, filepath.Base(p))
		}
		return nil
	})
	if len(found) > 0 {
		return bad("source maps shipped: "+strings.Join(found, ", "), "no .map files in production output")
	}
	return okay("no source maps in dist", "")
}

// AG-SUP-06: no known-vulnerable dependencies (osv-scanner). The exit code is
// unreliable (osv-scanner exits non-zero for vulns AND for scan errors / missing
// lockfiles), so we parse the JSON: a scan error -> INCONCLUSIVE (honest,
// fail-closed), real advisories -> FAIL, clean -> PASS.
func chkNoKnownVulns(ctx context.Context, c *CheckCtx) Outcome {
	if c.Tools.OSVScanner == "" {
		return inconclusive("osv-scanner not found on PATH")
	}
	cmd := exec.CommandContext(ctx, c.Tools.OSVScanner, "--format=json", "--recursive", c.RepoDir)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	_ = cmd.Run() // verdict comes from the JSON, not the exit code
	n, ids, ok := parseOSVResults(stdout.Bytes())
	if !ok {
		return inconclusive("osv-scanner produced no parseable JSON (scan error?): " + lastLine(stderr.Bytes()))
	}
	if n == 0 {
		return okay("osv-scanner: no known vulnerabilities", "")
	}
	advis := "advisories"
	if n == 1 {
		advis = "advisory"
	}
	return bad(fmt.Sprintf("osv-scanner: %d known %s (%s)", n, advis, strings.Join(ids, ", ")), "0 known advisories")
}

// parseOSVResults flattens osv-scanner JSON to a de-duplicated vulnerability-ID
// list. ok=false means the output was not valid osv-scanner JSON (a scan error,
// not a clean result) — the caller maps that to INCONCLUSIVE, never PASS.
func parseOSVResults(jsonOut []byte) (count int, ids []string, ok bool) {
	jsonOut = bytes.TrimSpace(jsonOut)
	if len(jsonOut) == 0 {
		return 0, nil, false
	}
	var doc struct {
		Results []struct {
			Packages []struct {
				Vulnerabilities []struct {
					ID string `json:"id"`
				} `json:"vulnerabilities"`
			} `json:"packages"`
		} `json:"results"`
	}
	if err := json.Unmarshal(jsonOut, &doc); err != nil {
		return 0, nil, false
	}
	seen := map[string]bool{}
	for _, r := range doc.Results {
		for _, p := range r.Packages {
			for _, v := range p.Vulnerabilities {
				if v.ID != "" && !seen[v.ID] {
					seen[v.ID] = true
					ids = append(ids, v.ID)
				}
			}
		}
	}
	return len(ids), ids, true
}

// AG-SUP-07: an SBOM is produced and retained.
func chkSBOM(_ context.Context, c *CheckCtx) Outcome {
	patterns := []string{"*.spdx.json", "*.cdx.json", "sbom.json", "bom.json", "*.sbom"}
	for _, root := range []string{c.DistDir, c.RepoDir} {
		for _, pat := range patterns {
			matches, _ := filepath.Glob(filepath.Join(root, pat))
			if len(matches) > 0 {
				return okay("SBOM found: "+filepath.Base(matches[0]), "")
			}
		}
	}
	return bad("no SBOM artifact found", "an SPDX/CycloneDX SBOM retained with the build")
}

func lastLine(b []byte) string {
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) == 0 {
		return ""
	}
	s := lines[len(lines)-1]
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
