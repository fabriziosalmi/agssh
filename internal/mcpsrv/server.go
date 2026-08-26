// Package mcpsrv exposes the AGSSH-STD-001 runner over the Model Context
// Protocol. It reuses the engine directly (no shell-out, no temp files): each
// tool call synthesizes an in-memory manifest.Config from typed arguments and
// invokes engine.Evaluate against the live surface, returning the same signed
// conformance record the CLI emits.
package mcpsrv

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/net/publicsuffix"

	"github.com/fabriziosalmi/agssh/internal/engine"
	"github.com/fabriziosalmi/agssh/internal/httpx"
	"github.com/fabriziosalmi/agssh/internal/manifest"
	"github.com/fabriziosalmi/agssh/internal/report"
	"github.com/fabriziosalmi/agssh/internal/rules"
)

const defaultTimeout = 45 * time.Second

// New builds an MCP server with the AGSSH tool surface registered. The caller
// connects it to a transport (StdioTransport in the binary, an in-memory
// transport in tests).
func New(version string) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{
		Name:    "agssh",
		Title:   "AGSSH-STD-001 conformance runner",
		Version: version,
		Description: "Evaluate a live web surface against AGSSH-STD-001 " +
			"(egress/CSP/headers/DNS/TLS/supply-chain/CI). Deterministic, fail-closed.",
	}, nil)

	mcp.AddTool(s, &mcp.Tool{
		Name: "agssh_scan",
		Description: "Evaluate a LIVE URL against AGSSH-STD-001 and return the conformance " +
			"verdict, weighted score, and a severity-ranked fix queue. The manifest is " +
			"synthesized from the arguments — no repository or config file is required. " +
			"Repo/supply-chain/CI rules that need source access report INCONCLUSIVE (fail-closed). " +
			"The server performs a server-side fetch of the URL, so by default it refuses " +
			"loopback/private/link-local targets (SSRF guard); set allow_private_targets to " +
			"scan a local dev server. Defaults: profile=Bronze, level=L0 (strict air-gap), kind=site.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(true)},
	}, handleScan)

	mcp.AddTool(s, &mcp.Tool{
		Name: "agssh_scan_config",
		Description: "Evaluate the surface(s) declared in an existing .airgap.yml, with full " +
			"CLI parity: repository, built-artifact (dist), and CI-workflow rules are checked " +
			"against real paths. Use this to assess a whole repo (including Silver/Gold " +
			"supply-chain and governance families) rather than a bare URL.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(true)},
	}, handleScanConfig)

	mcp.AddTool(s, &mcp.Tool{
		Name: "agssh_list_rules",
		Description: "List the AGSSH-STD-001 rule registry (id, title, family, obligation, " +
			"severity, profile, plane), optionally filtered by family and/or target profile. " +
			"Read-only introspection — no network.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, handleListRules)

	return s
}

// ---- agssh_scan -------------------------------------------------------------

// ScanInput is the argument schema for agssh_scan. Only URL is required.
type ScanInput struct {
	URL                 string   `json:"url" jsonschema:"live surface URL to evaluate; https assumed if the scheme is omitted"`
	Profile             string   `json:"profile,omitempty" jsonschema:"target profile (cumulative): Bronze (default), Silver, Gold"`
	Level               string   `json:"level,omitempty" jsonschema:"strictness band: L0 strict air-gap (default), L1 scoped egress, L2 marketing"`
	Kind                string   `json:"kind,omitempty" jsonschema:"surface kind: site (default), client-tool, docs"`
	Paths               []string `json:"paths,omitempty" jsonschema:"extra SAME-ORIGIN paths to sample; static checks run worst-case across url + paths"`
	Zone                string   `json:"zone,omitempty" jsonschema:"DNS zone for CAA/DNSSEC/dangling checks; default: registrable domain derived from url"`
	Resolver            string   `json:"resolver,omitempty" jsonschema:"DNS resolver host or host:port; default: the host's configured resolver"`
	AllowConnect        []string `json:"allow_connect,omitempty" jsonschema:"L1+ explicit connect-src origins (never '*')"`
	AllowSubresources   []string `json:"allow_subresources,omitempty" jsonschema:"L1+ subresource hosts exempted by AG-NET-02 (case-insensitive exact host match)"`
	AllowEmbeds         []string `json:"allow_embeds,omitempty" jsonschema:"L2 sanctioned third-party embed hosts"`
	AllowStorage        []string `json:"allow_storage,omitempty" jsonschema:"functional cookie / localStorage keys permitted (AG-PRV-04)"`
	GeneratesFiles      bool     `json:"generates_files,omitempty" jsonschema:"surface produces downloadable files client-side (enables the file-generation rules)"`
	ThreadedWASM        bool     `json:"threaded_wasm,omitempty" jsonschema:"surface ships threaded WebAssembly (COOP/COEP isolation rules apply)"`
	HasServiceWorker    bool     `json:"has_service_worker,omitempty" jsonschema:"surface registers a service worker"`
	Stateless           bool     `json:"stateless,omitempty" jsonschema:"no cookies/localStorage; satisfies Tier-D anti-framing on header-less hosts"`
	PrivacySurface      bool     `json:"privacy_surface,omitempty" jsonschema:"referrer leakage matters for this surface (AG-NET-09); implied for client-tool/docs"`
	TimeoutSeconds      int      `json:"timeout_seconds,omitempty" jsonschema:"per-check timeout in seconds (default 45)"`
	AllowPrivateTargets bool     `json:"allow_private_targets,omitempty" jsonschema:"permit scanning loopback/private/link-local hosts (e.g. localhost, 127.0.0.1, an RFC1918 dev server). OFF by default: an untrusted caller must not turn the server into an SSRF probe of internal services"`
}

func handleScan(ctx context.Context, _ *mcp.CallToolRequest, in ScanInput) (res *mcp.CallToolResult, out ScanResult, err error) {
	defer recoverToError(&err)

	surfURL, e := normalizeURL(in.URL)
	if e != nil {
		return nil, ScanResult{}, e
	}
	zone := strings.TrimSpace(in.Zone)
	if zone == "" {
		zone = registrableDomain(surfURL)
	}

	cfg := &manifest.Config{
		TargetProfile: orDefault(in.Profile, "Bronze"),
		Level:         orDefault(in.Level, "L0"),
		Surfaces: []manifest.Surface{{
			URL:              surfURL,
			Paths:            in.Paths,
			Kind:             orDefault(in.Kind, "site"),
			GeneratesFiles:   in.GeneratesFiles,
			ThreadedWASM:     in.ThreadedWASM,
			HasServiceWorker: in.HasServiceWorker,
			Stateless:        in.Stateless,
			PrivacySurface:   in.PrivacySurface,
		}},
		DNS:   manifest.DNS{Zone: zone, Resolver: in.Resolver},
		Allow: manifest.Allow{Connect: in.AllowConnect, Storage: in.AllowStorage, Embeds: in.AllowEmbeds, Subresources: in.AllowSubresources},
		Waivers: manifest.Waivers{Budget: manifest.Budget{
			MaxCount: 3, MaxWeight: 6, MaxWindowDays: 30,
		}},
	}
	if e := validateConfig(cfg); e != nil {
		return nil, ScanResult{}, e
	}

	to := timeout(in.TimeoutSeconds)

	// SSRF guard. The URL is untrusted (a model may have chosen it), so by default
	// refuse non-public targets — a scan must not become a probe of cloud metadata
	// (169.254.169.254), localhost, or an RFC1918 service. NewGuarded blocks at
	// dial time on the RESOLVED IP, so it also covers redirects and DNS-rebinding.
	// allow_private_targets is the explicit opt-in for a legitimate local scan.
	client := httpx.NewGuarded(to)
	if in.AllowPrivateTargets {
		client = httpx.New(to)
	} else {
		if e := httpx.GuardPublicTarget(ctx, surfURL); e != nil {
			return nil, ScanResult{}, e
		}
		// The DNS-plane checks dial the caller's `resolver` directly (not through
		// the guarded HTTP client), so guard it too — otherwise it is an alternate
		// SSRF vector to internal hosts.
		if e := httpx.GuardPublicHostPort(ctx, in.Resolver); e != nil {
			return nil, ScanResult{}, fmt.Errorf("resolver: %w", e)
		}
	}

	// URL-only scan: there is no source tree. Point the repo/dist/workflow roots
	// at a guaranteed-absent ABSOLUTE path so every source-plane checker resolves
	// to nothing (INCONCLUSIVE, fail-closed) and none of them silently scans the
	// server's working directory. Empty strings are NOT safe here:
	// filepath.Join("", name) collapses to a CWD-relative read.
	noSrc, cleanup, e := absentSourceRoot()
	if e != nil {
		return nil, ScanResult{}, fmt.Errorf("cannot allocate a scratch root: %w", e)
	}
	defer cleanup()
	opts := engine.Options{
		RepoDir: noSrc, DistDir: noSrc, WorkflowsDir: noSrc,
		HTTP: client, Now: time.Now(), PerCheck: to, Resolver: in.Resolver,
	}
	rec := engine.Evaluate(cfg, cfg.Surfaces[0], opts)
	// Don't disclose the server's temp path: some checkers echo the (absent)
	// workflow/repo root verbatim in their INCONCLUSIVE evidence.
	scrubPath(rec, filepath.Dir(noSrc))
	return renderResult(rec)
}

// ---- agssh_scan_config ------------------------------------------------------

// ScanConfigInput drives a full CLI-parity evaluation from an on-disk manifest.
type ScanConfigInput struct {
	ConfigPath  string `json:"config_path" jsonschema:"path to an existing .airgap.yml"`
	Repo        string `json:"repo,omitempty" jsonschema:"repository root for source/supply-chain checks; default: the directory containing config_path"`
	Dist        string `json:"dist,omitempty" jsonschema:"built-artifact directory (secrets/source-maps/SBOM); default: <repo>/dist"`
	Workflows   string `json:"workflows,omitempty" jsonschema:"CI workflows directory; default: <repo>/.github/workflows"`
	Profile     string `json:"profile,omitempty" jsonschema:"override the manifest target profile: Bronze|Silver|Gold"`
	Level       string `json:"level,omitempty" jsonschema:"override the manifest level: L0|L1|L2"`
	Resolver    string `json:"resolver,omitempty" jsonschema:"DNS resolver host or host:port; overrides the manifest resolver"`
	TimeoutSecs int    `json:"timeout_seconds,omitempty" jsonschema:"per-check timeout in seconds (default 45)"`
}

func handleScanConfig(ctx context.Context, _ *mcp.CallToolRequest, in ScanConfigInput) (res *mcp.CallToolResult, out ScanResult, err error) {
	defer recoverToError(&err)

	cfgPath := strings.TrimSpace(in.ConfigPath)
	if cfgPath == "" {
		return nil, ScanResult{}, fmt.Errorf("config_path is required")
	}
	cfg, e := manifest.Load(cfgPath)
	if e != nil {
		return nil, ScanResult{}, e
	}
	if in.Profile != "" {
		cfg.TargetProfile = in.Profile
	}
	if in.Level != "" {
		cfg.Level = in.Level
	}
	if e := validateConfig(cfg); e != nil {
		return nil, ScanResult{}, e
	}

	repo := orDefault(in.Repo, filepath.Dir(cfgPath))
	dist := orDefault(in.Dist, filepath.Join(repo, "dist"))
	wf := orDefault(in.Workflows, filepath.Join(repo, ".github", "workflows"))

	to := timeout(in.TimeoutSecs)
	opts := engine.Options{
		RepoDir: repo, DistDir: dist, WorkflowsDir: wf,
		HTTP: httpx.New(to), Now: time.Now(), PerCheck: to, Resolver: in.Resolver,
	}

	// Evaluate every surface, then fold into a single headline verdict.
	var records []*report.Record
	for _, sf := range cfg.Surfaces {
		records = append(records, engine.Evaluate(cfg, sf, opts))
	}
	primary, allConformant, roster := aggregateSurfaces(records)

	res, out, err = renderResult(primary)
	if err != nil {
		return res, out, err
	}
	out.Conformant = allConformant
	out.Verdict = verdictString(allConformant)
	if len(roster) > 1 {
		out.Surfaces = roster
		var b strings.Builder
		fmt.Fprintf(&b, "\nConfig gate (AND of %d surfaces): %s\n", len(roster), verdictString(allConformant))
		for _, s := range roster {
			fmt.Fprintf(&b, "  %-15s %s (%.0f%%)\n", s.Verdict, s.Surface, s.Pct)
		}
		res.Content = append(res.Content, &mcp.TextContent{Text: b.String()})
	}
	return res, out, err
}

// ---- agssh_list_rules -------------------------------------------------------

type ListRulesInput struct {
	Family  string `json:"family,omitempty" jsonschema:"filter by family, e.g. AG-NET, AG-CSP, AG-HDR, AG-DNS, AG-TLS, AG-SUP, AG-CI, AG-PRV, AG-GOV (matches the rule id prefix)"`
	Profile string `json:"profile,omitempty" jsonschema:"only rules included at or below this target profile: Bronze|Silver|Gold"`
}

type RuleInfo struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Family     string `json:"family"`
	Obligation string `json:"obligation"`
	Severity   string `json:"severity"`
	Profile    string `json:"profile"`
	Plane      string `json:"plane"`
}

type ListRulesOutput struct {
	Count int        `json:"count"`
	Rules []RuleInfo `json:"rules"`
}

func handleListRules(_ context.Context, _ *mcp.CallToolRequest, in ListRulesInput) (res *mcp.CallToolResult, out ListRulesOutput, err error) {
	defer recoverToError(&err)

	var maxProfile manifest.Profile
	if in.Profile != "" {
		p, e := manifest.ParseProfile(in.Profile)
		if e != nil {
			return nil, ListRulesOutput{}, e
		}
		maxProfile = p
	}
	fam := strings.ToUpper(strings.TrimSpace(in.Family))

	for _, r := range rules.All() {
		if fam != "" && !strings.HasPrefix(strings.ToUpper(r.ID), fam) && !strings.EqualFold(r.Family, fam) {
			continue
		}
		if maxProfile != 0 && !maxProfile.AtLeast(r.Profile) {
			continue
		}
		out.Rules = append(out.Rules, RuleInfo{
			ID: r.ID, Title: r.Title, Family: r.Family,
			Obligation: r.Obligation.String(), Severity: r.Severity.String(),
			Profile: r.Profile.String(), Plane: r.Plane.String(),
		})
	}
	out.Count = len(out.Rules)

	var b strings.Builder
	fmt.Fprintf(&b, "%d AGSSH-STD-001 rules\n", out.Count)
	for _, r := range out.Rules {
		fmt.Fprintf(&b, "  %-11s [%-8s %-6s %s] %s\n", r.ID, r.Severity, r.Obligation, r.Profile, r.Title)
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, out, nil
}

// ---- shared output model ----------------------------------------------------

// ScanResult is the structured output of a scan: the verdict essentials plus the
// full result set. It mirrors the report.Record the CLI writes, minus the
// signature envelope (a scan tool never signs).
type ScanResult struct {
	Standard   string           `json:"standard"`
	Version    string           `json:"version"`
	Surface    string           `json:"surface"`
	Profile    string           `json:"profile"`
	Level      string           `json:"level"`
	Verdict    string           `json:"verdict"`
	Conformant bool             `json:"conformant"`
	Score      report.Score     `json:"score"`
	Counts     Counts           `json:"counts"`
	Violations []string         `json:"governance_violations,omitempty"`
	FixQueue   []report.FixItem `json:"fix_queue,omitempty"`
	Results    []rules.Result   `json:"results,omitempty"`
	Surfaces   []SurfaceVerdict `json:"surfaces,omitempty"` // set only for multi-surface manifests
}

type Counts struct {
	Pass         int `json:"pass"`
	Fail         int `json:"fail"`
	Inconclusive int `json:"inconclusive"`
	Waived       int `json:"waived"`
	NA           int `json:"na"`
}

type SurfaceVerdict struct {
	Surface    string  `json:"surface"`
	Verdict    string  `json:"verdict"`
	Conformant bool    `json:"conformant"`
	Pct        float64 `json:"pct"`
}

// renderResult adapts a *report.Record into the tool's text + structured output.
func renderResult(rec *report.Record) (*mcp.CallToolResult, ScanResult, error) {
	if rec == nil {
		return nil, ScanResult{}, fmt.Errorf("evaluation produced no record")
	}
	out := ScanResult{
		Standard: rec.Standard, Version: rec.Version, Surface: rec.Surface,
		Profile: rec.Profile, Level: rec.Level, Conformant: rec.Conformant,
		Verdict: verdictString(rec.Conformant), Score: rec.Score,
		Counts: countStatuses(rec), Violations: rec.Violations, FixQueue: rec.FixQueue,
		Results: rec.Results,
	}
	var buf bytes.Buffer
	rec.Render(&buf)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: buf.String()}},
	}, out, nil
}

func countStatuses(rec *report.Record) Counts {
	var c Counts
	for _, r := range rec.Results {
		switch {
		case r.Waived:
			c.Waived++
		case r.Status == "PASS":
			c.Pass++
		case r.Status == "FAIL":
			c.Fail++
		case r.Status == "INCONCLUSIVE":
			c.Inconclusive++
		case r.Status == "N/A":
			c.NA++
		}
	}
	return c
}

// aggregateSurfaces folds per-surface records into one headline verdict that
// matches the CLI gate: conformant only if EVERY surface is (the CLI ANDs them).
// The returned primary record — used for the detailed fix queue — is the first
// FAILING surface (so the detail matches a real failure) else the first surface.
func aggregateSurfaces(records []*report.Record) (primary *report.Record, allConformant bool, roster []SurfaceVerdict) {
	allConformant = true
	for _, rec := range records {
		if rec == nil {
			continue
		}
		if !rec.Conformant {
			allConformant = false
		}
		if primary == nil || (primary.Conformant && !rec.Conformant) {
			primary = rec
		}
		roster = append(roster, SurfaceVerdict{
			Surface: rec.Surface, Conformant: rec.Conformant,
			Pct: rec.Score.Pct, Verdict: verdictString(rec.Conformant),
		})
	}
	return primary, allConformant, roster
}

// scrubPath removes an internal path prefix (the synthesized absent source root)
// from every result's evidence, so a URL-only scan never discloses the server's
// temp-directory layout to the caller.
func scrubPath(rec *report.Record, secret string) {
	if rec == nil || strings.TrimSpace(secret) == "" {
		return
	}
	repl := func(s string) string { return strings.ReplaceAll(s, secret, "<no-source>") }
	for i := range rec.Results {
		rec.Results[i].Err = repl(rec.Results[i].Err)
		rec.Results[i].Evidence.Observed = repl(rec.Results[i].Evidence.Observed)
	}
	for i := range rec.FixQueue {
		rec.FixQueue[i].Observed = repl(rec.FixQueue[i].Observed)
		rec.FixQueue[i].Expected = repl(rec.FixQueue[i].Expected)
	}
}

// ---- helpers ----------------------------------------------------------------

func validateConfig(cfg *manifest.Config) error {
	if len(cfg.Surfaces) == 0 {
		return fmt.Errorf("no surfaces declared")
	}
	if _, err := cfg.Profile(); err != nil {
		return err
	}
	if _, err := cfg.LevelV(); err != nil {
		return err
	}
	for i, s := range cfg.Surfaces {
		if strings.TrimSpace(s.URL) == "" {
			return fmt.Errorf("surface[%d] has no url", i)
		}
	}
	// Reject wildcard allow-lists: an untrusted caller must not be able to pass
	// allow_connect=["*"] (etc.) and disable the very check it scopes.
	return manifest.ValidateAllow(cfg.Allow)
}

// normalizeURL requires an absolute http(s) URL with a host. A bare host such as
// "example.org" is upgraded to https://example.org so a caller need not remember
// the scheme; anything with an explicit non-http scheme is rejected.
func normalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("url is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid url %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("url scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("url %q has no host", raw)
	}
	return u.String(), nil
}

// registrableDomain derives the eTLD+1 (the DNS zone) from a surface URL's host,
// stripping the port. Returns "" when the host is an IP or otherwise has no
// registrable domain, in which case the DNS-plane checks stay inconclusive.
func registrableDomain(surfURL string) string {
	u, err := url.Parse(surfURL)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	if host == "" {
		return ""
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return etld1
}

// absentSourceRoot returns an absolute path whose final component does not
// exist, used as the repo/dist/workflow root for URL-only scans. The parent is a
// fresh empty temp dir removed by cleanup; the returned child is never created,
// so os.Stat fails and filepath.Join stays anchored to an absolute, non-CWD path.
// If a scratch dir cannot be created it fails closed (returns an error) rather
// than falling back to a fixed path that might exist and be scanned as a repo.
func absentSourceRoot() (path string, cleanup func(), err error) {
	parent, err := os.MkdirTemp("", "agssh-mcp-norepo-")
	if err != nil {
		return "", func() {}, err
	}
	return filepath.Join(parent, "no-source"), func() { _ = os.RemoveAll(parent) }, nil
}

func timeout(secs int) time.Duration {
	if secs <= 0 {
		return defaultTimeout
	}
	return time.Duration(secs) * time.Second
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func verdictString(conformant bool) string {
	if conformant {
		return "CONFORMANT"
	}
	return "NON-CONFORMANT"
}

func ptr[T any](v T) *T { return &v }

// recoverToError converts an unexpected panic inside a handler into a tool error
// rather than tearing down the long-lived stdio server.
func recoverToError(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("internal error: %v", r)
	}
}
