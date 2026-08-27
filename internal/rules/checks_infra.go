package rules

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ansiCSIRe matches ANSI CSI escape sequences (colour codes, cursor moves) that
// scanners emit on a TTY; they are noise, not evidence.
var ansiCSIRe = regexp.MustCompile("\x1b\\[[0-9;]*[a-zA-Z]")

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

// AG-DNS-01: a CAA policy RESTRICTS certificate issuance on the zone. It is not
// enough that some CAA record exists — a zone that publishes only iodef (a
// contact address) or another non-issuance tag pins issuance to no one. The MUST
// (title: "CAA pins certificate issuance") requires at least one issue/issuewild
// property. `issue ";"` counts: it forbids all issuance, a valid restriction.
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
	var records []string
	restricts := false
	for _, rr := range resp.Answer {
		if caa, ok := rr.(*dns.CAA); ok {
			records = append(records, caa.Tag+":"+caa.Value)
			switch strings.ToLower(caa.Tag) { // CAA tags are case-insensitive
			case "issue", "issuewild":
				restricts = true
			}
		}
	}
	if !restricts {
		observed := "no issue/issuewild CAA property"
		if len(records) > 0 {
			observed += " (present: " + strings.Join(records, " ") + ")"
		} else {
			observed = "no CAA records"
		}
		return bad(observed, "a CAA policy restricting issuance (issue/issuewild)")
	}
	return okay("CAA restricts issuance: "+strings.Join(records, " "), "")
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
	// 2) The target resolves. Only a takeover-PRONE provider warrants a body
	// fingerprint check — otherwise a benign page that merely contains a phrase
	// like "project not found" must not fail this MUST.
	prov, prone := takeoverProvider(target)
	if !prone {
		return okay("CNAME -> "+target+" resolves (not a takeover-prone provider)", "")
	}
	body := ""
	if c.Doc != nil {
		body = string(c.Doc.Body)
	}
	if body == "" {
		// On a prone provider with no body to confirm the resource is claimed,
		// fail closed to INCONCLUSIVE rather than a silent PASS.
		return inconclusive("CNAME -> " + target + " points at " + prov +
			" (takeover-prone) and the surface body is unavailable to confirm it is claimed")
	}
	if sig, matched := takeoverFingerprint(body); matched {
		return bad("CNAME -> "+target+" ("+prov+") serves an unclaimed-resource fingerprint: "+sig,
			"CNAME target is a claimed, serving resource")
	}
	return okay("CNAME -> "+target+" ("+prov+") resolves and serves no takeover fingerprint", "")
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
	"This UserVoice subdomain is currently available",
	"Do you want to register *.wordpress.com",
	"Repository not found · Bitbucket", // full Bitbucket marker (not the bare phrase)
}

// hostOnly extracts the lowercased host from a URL (or a scheme-less authority),
// correctly unwrapping IPv6 literals like [::1]. net/url does the bracket-aware
// parsing the previous hand-rolled colon-splitting got wrong.
func hostOnly(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "//" + raw // treat a bare authority (host[:port][/path]) as host-relative
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// surfaceAddr returns host:port for the surface URL, defaulting to :443. IPv6
// literals are re-bracketed by net.JoinHostPort.
func surfaceAddr(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "//" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port)
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
	accepted, conclusive := offersLegacyTLS(addr, host, 6*time.Second)
	if accepted {
		return bad("legacy TLS (1.0/1.1) accepted", "TLS 1.0/1.1 refused")
	}
	if !conclusive {
		return inconclusive("legacy-TLS refusal not provable for " + addr +
			" (unreachable, or the server answered with a non-version error); cannot conclude the floor")
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

// lockfiles maps a known lockfile to the substrings that prove it pins
// dependencies by integrity hash (ANY one suffices — e.g. yarn classic uses
// "integrity ", yarn berry uses "checksum:"). A nil markers slice means the file
// IS the hash set (go.sum), so a non-empty file proves pinning. Markers are
// chosen to match a per-dependency hash, never a lockfile-wide digest (poetry's
// content-hash, composer's empty shasum) which would be a constant-true false PASS.
var lockfiles = []struct {
	name    string
	markers []string
}{
	{"package-lock.json", []string{`"integrity"`}},
	{"npm-shrinkwrap.json", []string{`"integrity"`}},
	{"yarn.lock", []string{"integrity ", "checksum:"}}, // classic + berry
	{"pnpm-lock.yaml", []string{"integrity:"}},
	{"Cargo.lock", []string{"checksum = "}},
	{"go.sum", nil},
	{"poetry.lock", []string{"sha256:"}},  // per-file hash, not content-hash
	{"Pipfile.lock", []string{"sha256:"}}, // hashes list, not the _meta digest
}

func containsAny(b []byte, subs []string) bool {
	for _, s := range subs {
		if bytes.Contains(b, []byte(s)) {
			return true
		}
	}
	return false
}

// AG-SUP-02: dependencies are pinned by integrity hash. We audit the recognised
// lockfiles present in the repo: each must carry per-dependency integrity hashes.
// No recognised lockfile (or only an empty go.sum) -> INCONCLUSIVE (fail-closed,
// nothing to prove against), never a silent PASS.
func chkPinnedDeps(_ context.Context, c *CheckCtx) Outcome {
	var audited, unpinned []string
	for _, lf := range lockfiles {
		b, err := os.ReadFile(filepath.Join(c.RepoDir, lf.name))
		if err != nil {
			continue
		}
		if len(lf.markers) == 0 { // go.sum: only a populated file proves anything
			if len(bytes.TrimSpace(b)) == 0 {
				continue // empty -> audited nothing
			}
			audited = append(audited, lf.name)
			continue
		}
		audited = append(audited, lf.name)
		if !containsAny(b, lf.markers) {
			unpinned = append(unpinned, lf.name)
		}
	}
	if len(audited) == 0 {
		return inconclusive("no recognised, populated lockfile to audit for integrity hashes")
	}
	if len(unpinned) > 0 {
		return bad("lockfile(s) without integrity hashes: "+strings.Join(unpinned, ", "),
			"every dependency pinned by integrity hash")
	}
	return okay("integrity-hash-pinned lockfiles: "+strings.Join(audited, ", "), "")
}

// AG-SUP-04: no secrets in the shipped artifact (gitleaks over dist).
func chkNoSecrets(ctx context.Context, c *CheckCtx) Outcome {
	dir := c.DistDir
	if !dirExists(dir) {
		dir = c.RepoDir
	}
	if !dirExists(dir) {
		// No artifact/repo to inspect (e.g. a URL-only scan): we cannot prove the
		// shipped output is secret-free, so fail-closed to INCONCLUSIVE — never
		// scan the process's working directory by accident.
		return inconclusive("no dist/repo directory to scan for secrets")
	}
	if !hasScannableFiles(dir) {
		// The directory exists but holds no shipped artifacts (empty, or only
		// config/VCS metadata). An empty scan is not evidence of "no secrets" — it
		// is evidence that nothing was examined. N/A, not a vacuous PASS.
		return naReason("no shipped artifacts to scan for secrets (empty or config-only directory)")
	}
	if c.Tools.Gitleaks == "" {
		return inconclusive("gitleaks not found on PATH")
	}
	// gitleaks exits 1 for BOTH "leaks found" and some fatal scan errors (an
	// unreadable file, a malformed .gitleaks.toml), so the exit code alone cannot
	// tell a real finding from a broken run. Take the verdict from the JSON report
	// instead: findings present -> FAIL; an empty report (or a clean exit with no
	// report) -> PASS; no parseable report on a non-zero exit -> INCONCLUSIVE. A
	// tool that could not run must never manufacture a secret.
	report, err := os.CreateTemp("", "agssh-gitleaks-*.json")
	if err != nil {
		return inconclusive("cannot create gitleaks report file: " + err.Error())
	}
	reportPath := report.Name()
	report.Close()
	defer os.Remove(reportPath)

	cmd := exec.CommandContext(ctx, c.Tools.Gitleaks, "detect", "--no-banner", "--no-git",
		"--source", dir, "--report-format", "json", "--report-path", reportPath)
	out, runErr := cmd.CombinedOutput()

	data, _ := os.ReadFile(reportPath)
	if trimmed := bytes.TrimSpace(data); len(trimmed) > 0 {
		var findings []json.RawMessage
		if json.Unmarshal(trimmed, &findings) != nil {
			return inconclusive("gitleaks report not parseable: " + toolDiag(out))
		}
		if len(findings) > 0 {
			return bad(fmt.Sprintf("gitleaks flagged %d secret(s)", len(findings)), "no secrets in shipped output")
		}
		return okay("gitleaks: no secrets", "")
	}
	// No report written. A clean exit means nothing to report; a non-zero exit
	// means the scan itself failed.
	if runErr == nil {
		return okay("gitleaks: no secrets", "")
	}
	return inconclusive("gitleaks did not complete: " + toolDiag(out))
}

// AG-SUP-05: no source maps in the shipped artifact.
func chkNoSourceMaps(_ context.Context, c *CheckCtx) Outcome {
	dir := c.DistDir
	if _, err := os.Stat(dir); err != nil {
		return inconclusive("dist dir not found: " + dir)
	}
	if !hasScannableFiles(dir) {
		return naReason("no shipped artifacts to scan for source maps (empty or config-only directory)")
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
	return okay("no .map files in dist", "")
}

// AG-SUP-06: no known-vulnerable dependencies (osv-scanner). The exit code is
// unreliable (osv-scanner exits non-zero for vulns AND for scan errors / missing
// lockfiles), so we parse the JSON: a scan error -> INCONCLUSIVE (honest,
// fail-closed), real advisories -> FAIL, clean -> PASS.
func chkNoKnownVulns(ctx context.Context, c *CheckCtx) Outcome {
	if !dirExists(c.RepoDir) {
		// No repository to scan (e.g. a URL-only scan). Refuse to let osv-scanner
		// fall back to the process working directory ("" scans '.').
		return inconclusive("no repository directory to scan for known vulnerabilities")
	}
	if !hasScannableFiles(c.RepoDir) {
		// Directory present but no shipped artifacts — inapplicable, not a clean
		// bill of health. Coherent with AG-SUP-04 on the same input (RUN-04).
		return naReason("no shipped artifacts to scan for known vulnerabilities (empty or config-only directory)")
	}
	if c.Tools.OSVScanner == "" {
		return inconclusive("osv-scanner not found on PATH")
	}
	cmd := exec.CommandContext(ctx, c.Tools.OSVScanner, "--format=json", "--recursive", c.RepoDir)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	_ = cmd.Run() // verdict comes from the JSON, not the exit code
	n, ids, ok := parseOSVResults(stdout.Bytes())
	if !ok {
		return inconclusive("osv-scanner produced no parseable JSON (scan error?): " + toolDiag(stderr.Bytes()))
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
				Groups []struct {
					IDs []string `json:"ids"`
				} `json:"groups"`
			} `json:"packages"`
		} `json:"results"`
	}
	if err := json.Unmarshal(jsonOut, &doc); err != nil {
		return 0, nil, false
	}
	seen := map[string]bool{}
	add := func(id string) {
		if id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for _, r := range doc.Results {
		for _, p := range r.Packages {
			for _, v := range p.Vulnerabilities {
				add(v.ID)
			}
			for _, g := range p.Groups { // modern osv-scanner reports IDs here too
				for _, id := range g.IDs {
					add(id)
				}
			}
		}
	}
	return len(ids), ids, true
}

// AG-SUP-07: an SBOM is produced and retained.
func chkSBOM(_ context.Context, c *CheckCtx) Outcome {
	patterns := []string{"*.spdx.json", "*.cdx.json", "sbom.json", "bom.json", "*.sbom"}
	roots := make([]string, 0, 2)
	for _, root := range []string{c.DistDir, c.RepoDir} {
		if dirExists(root) {
			roots = append(roots, root)
		}
	}
	if len(roots) == 0 {
		// No dist/repo to inspect (e.g. a URL-only scan) — we cannot prove an SBOM
		// exists or is absent, so fail-closed to INCONCLUSIVE rather than FAIL.
		return inconclusive("no dist/repo directory to scan for an SBOM")
	}
	for _, root := range roots {
		for _, pat := range patterns {
			matches, _ := filepath.Glob(filepath.Join(root, pat))
			if len(matches) > 0 {
				return okay("SBOM found: "+filepath.Base(matches[0]), "")
			}
		}
	}
	return bad("no SBOM artifact found", "an SPDX/CycloneDX SBOM retained with the build")
}

// dirExists reports whether p names an existing directory. An empty path is
// never a directory — guarding on it keeps filepath.Join(p, name) from
// collapsing to a working-directory-relative read.
func dirExists(p string) bool {
	if strings.TrimSpace(p) == "" {
		return false
	}
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// hasScannableFiles reports whether dir holds at least one regular file that
// counts as shipped output: a non-hidden file outside a dot-directory. Config
// and VCS metadata (.airgap.yml, .gitleaks.toml, .git/, .github/) are not shipped
// artifacts, so a directory holding only those has nothing for the supply-plane
// scanners to judge — scanning it and reporting "clean" would be a vacuous PASS.
// The supply family treats such a directory as N/A rather than PASS.
func hasScannableFiles(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != dir && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir // .git, .github, …
			}
			return nil
		}
		if strings.HasPrefix(d.Name(), ".") {
			return nil // hidden file (.airgap.yml, .gitleaks.toml) — not shipped output
		}
		found = true
		return filepath.SkipAll // one is enough
	})
	return found
}

// toolDiag turns a scanner's raw output into ONE sanitized diagnostic line that
// is safe to embed as rule evidence. A scanner that fails to run tends to print
// its own usage/`--help` chatter (which is UX about the tool, not evidence about
// the surface) plus banners and control characters; surfacing that verbatim made
// an INCONCLUSIVE read like the surface itself said "see --help". toolDiag scans
// bottom-up for the last line that carries an actual diagnostic, strips the
// usage tail and control characters, and caps the length.
func toolDiag(b []byte) string {
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if s := sanitizeDiagLine(lines[i]); s != "" {
			return s
		}
	}
	return "(no diagnostic output)"
}

// sanitizeDiagLine returns the evidence-bearing part of one output line, or ""
// if the line is a blank / a pure "run … --help for usage" pointer.
func sanitizeDiagLine(line string) string {
	line = ansiCSIRe.ReplaceAllString(line, "")
	if i := strings.Index(strings.ToLower(line), "--help"); i >= 0 {
		line = line[:i] // drop the "--help for usage" tail: UX, not evidence
	}
	line = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, line)
	line = strings.TrimRight(strings.Join(strings.Fields(line), " "), " ,;.-")
	low := strings.ToLower(line)
	if line == "" || low == "usage" || strings.HasPrefix(low, "run ") || strings.HasPrefix(low, "see ") {
		return "" // carries no evidence once the usage pointer is removed
	}
	if len(line) > 160 {
		line = line[:160] + "…"
	}
	return line
}
