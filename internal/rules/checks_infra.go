package rules

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const resolver = "1.1.1.1:53" // validating resolver for DNSSEC AD probing

func dnsQuery(zone string, qtype uint16, wantDO bool) (*dns.Msg, error) {
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
	resp, err := dnsQuery(c.Zone, dns.TypeCAA, false)
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
	resp, err := dnsQuery(c.Zone, dns.TypeSOA, true)
	if err != nil {
		return inconclusive("DNSSEC query failed: " + err.Error())
	}
	if resp.AuthenticatedData {
		return okay("resolver set AD (DNSSEC-validated)", "")
	}
	keyResp, err := dnsQuery(c.Zone, dns.TypeDNSKEY, true)
	if err == nil {
		for _, rr := range keyResp.Answer {
			if _, ok := rr.(*dns.DNSKEY); ok {
				return okay("DNSKEY present (signed zone)", "")
			}
		}
	}
	return bad("no AD bit and no DNSKEY", "DNSSEC-signed zone")
}

// AG-DNS-03: the surface host has no dangling CNAME (takeover risk).
func chkDangling(_ context.Context, c *CheckCtx) Outcome {
	host := hostOnly(c.Surface.URL)
	if host == "" {
		return inconclusive("cannot derive surface host")
	}
	cn, err := dnsQuery(host, dns.TypeCNAME, false)
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
	// Resolve the CNAME target; NXDOMAIN/empty => dangling.
	a, err := dnsQuery(target, dns.TypeA, false)
	if err != nil {
		return inconclusive("target A query failed: " + err.Error())
	}
	if a.Rcode == dns.RcodeNameError || len(a.Answer) == 0 {
		return bad("CNAME -> "+target+" does not resolve (dangling)", "every CNAME target resolves")
	}
	return okay("CNAME -> "+target+" resolves", "")
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

// AG-HDR-08: TLS floor — legacy TLS (1.0/1.1) MUST be refused; 1.2+ MUST work.
func chkTLSFloor(_ context.Context, c *CheckCtx) Outcome {
	host := hostOnly(c.Surface.URL)
	if host == "" {
		return inconclusive("cannot derive surface host")
	}
	addr := net.JoinHostPort(host, "443")
	dialer := &net.Dialer{Timeout: 6 * time.Second}

	legacy := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}
	if conn, err := tls.DialWithDialer(dialer, "tcp", addr, legacy); err == nil {
		v := conn.ConnectionState().Version
		conn.Close()
		return bad(fmt.Sprintf("legacy TLS accepted (0x%04x)", v), "TLS 1.0/1.1 refused")
	}
	modern := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, modern)
	if err != nil {
		return inconclusive("TLS 1.2+ handshake failed: " + err.Error())
	}
	v := conn.ConnectionState().Version
	conn.Close()
	return okay(fmt.Sprintf("legacy refused; modern ok (0x%04x)", v), "")
}

// ---------- supply chain ----------

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

// AG-SUP-06: no known-vulnerable dependencies (osv-scanner).
func chkNoKnownVulns(ctx context.Context, c *CheckCtx) Outcome {
	if c.Tools.OSVScanner == "" {
		return inconclusive("osv-scanner not found on PATH")
	}
	cmd := exec.CommandContext(ctx, c.Tools.OSVScanner, "scan", "--recursive", c.RepoDir)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return okay("osv-scanner: no known vulnerabilities", "")
	}
	// osv-scanner exits non-zero when vulnerabilities are found.
	return bad("osv-scanner reported vulnerabilities: "+lastLine(out), "0 known high/critical advisories")
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

// ---------- CI / pipeline ----------

var usesRe = regexp.MustCompile(`(?m)uses:\s*([^\s#]+)`)
var sha40Re = regexp.MustCompile(`^[0-9a-f]{40}$`)

func workflowFiles(dir string) []string {
	var fs []string
	for _, ext := range []string{"*.yml", "*.yaml"} {
		m, _ := filepath.Glob(filepath.Join(dir, ext))
		fs = append(fs, m...)
	}
	return fs
}

// AG-CI-01: third-party Actions are pinned to a full 40-char commit SHA.
func chkPinnedActions(_ context.Context, c *CheckCtx) Outcome {
	files := workflowFiles(c.WorkflowsDir)
	if len(files) == 0 {
		return inconclusive("no workflow files at " + c.WorkflowsDir)
	}
	var unpinned []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, m := range usesRe.FindAllStringSubmatch(string(b), -1) {
			ref := strings.Trim(m[1], `"'`)
			if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "docker://") {
				continue // local / docker pin handled elsewhere
			}
			parts := strings.SplitN(ref, "@", 2)
			if len(parts) != 2 || !sha40Re.MatchString(parts[1]) {
				unpinned = append(unpinned, ref)
			}
		}
	}
	if len(unpinned) > 0 {
		return bad("unpinned Actions: "+strings.Join(uniq(unpinned), ", "), "uses: owner/action@<40-char-sha>")
	}
	return okay("all third-party Actions SHA-pinned", "")
}

// AG-CI-02: workflows declare least-privilege top-level permissions.
func chkLeastPriv(_ context.Context, c *CheckCtx) Outcome {
	files := workflowFiles(c.WorkflowsDir)
	if len(files) == 0 {
		return inconclusive("no workflow files at " + c.WorkflowsDir)
	}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		s := string(b)
		if !strings.Contains(s, "permissions:") {
			return bad("workflow without explicit permissions: "+filepath.Base(f), "top-level permissions, defaulting to read")
		}
		if strings.Contains(s, "permissions: write-all") || strings.Contains(s, "permissions: read-all") {
			return bad("over-broad permissions in "+filepath.Base(f), "scope write to the job that needs it")
		}
	}
	return okay("workflows declare scoped permissions", "")
}

// AG-CI-03: untrusted code is not run in a privileged context.
func chkNoUntrustedPriv(_ context.Context, c *CheckCtx) Outcome {
	files := workflowFiles(c.WorkflowsDir)
	if len(files) == 0 {
		return inconclusive("no workflow files at " + c.WorkflowsDir)
	}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		s := string(b)
		if strings.Contains(s, "pull_request_target") &&
			(strings.Contains(s, "github.event.pull_request.head") || strings.Contains(s, "head.sha") || strings.Contains(s, "head.ref")) {
			return bad("pull_request_target checks out PR head: "+filepath.Base(f),
				"never build untrusted PR code with elevated tokens")
		}
	}
	return okay("no untrusted-code-in-privileged-context pattern", "")
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

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
