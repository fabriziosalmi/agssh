// Package engine selects the applicable rules for a surface, runs their
// checkers, evaluates the engine-plane governance rules, applies waivers, and
// renders the fail-closed gate verdict into a signed conformance record.
package engine

import (
	"context"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fabriziosalmi/agssh/internal/httpx"
	"github.com/fabriziosalmi/agssh/internal/manifest"
	"github.com/fabriziosalmi/agssh/internal/report"
	"github.com/fabriziosalmi/agssh/internal/rules"
)

const docVersion = "v1.0.0"

type Options struct {
	RepoDir      string
	DistDir      string
	WorkflowsDir string
	HTTP         *httpx.Client
	Now          time.Time
	Author       string
	Approvers    map[string]bool
	Sign         bool
	ArtifactPath string
	PerCheck     time.Duration
	Resolver     string // DNS resolver override; empty => host default
}

// Evaluate runs the full conformance assessment for one surface.
func Evaluate(cfg *manifest.Config, surface manifest.Surface, opts Options) *report.Record {
	profile, _ := cfg.Profile()
	level, _ := cfg.LevelV()
	tools := rules.DiscoverTools()
	if opts.PerCheck <= 0 {
		opts.PerCheck = 45 * time.Second
	}

	// Fetch the live surface (and any extra declared paths). Static checks read
	// the root document by default; for multi-path surfaces they are evaluated
	// worst-case across every sampled document (a weaker per-path header loses).
	var docs []*httpx.Doc
	if opts.HTTP != nil {
		docs = fetchDocs(opts.HTTP, surface.URL, surface.Paths, opts.PerCheck)
	}
	var rootDoc *httpx.Doc
	if len(docs) > 0 {
		rootDoc = docs[0]
	}

	resolver := opts.Resolver
	if resolver == "" {
		resolver = cfg.DNS.Resolver
	}
	cctx := &rules.CheckCtx{
		Surface: surface, Level: level, Allow: cfg.Allow, Zone: cfg.DNS.Zone,
		Resolver: resolver,
		RepoDir:  opts.RepoDir, DistDir: opts.DistDir, WorkflowsDir: opts.WorkflowsDir,
		Now: opts.Now, HTTP: opts.HTTP, Doc: rootDoc, Tools: tools,
	}

	all := rules.All()
	byID := make(map[string]rules.Rule, len(all))
	for _, r := range all {
		byID[r.ID] = r
	}

	// 1) Surface checks within the target profile.
	var results []rules.Result
	for _, r := range all {
		if !profile.AtLeast(r.Profile) {
			continue // rule above the target profile -> excluded
		}
		if r.Applies != nil && !r.Applies(surface, level) {
			continue // not applicable to this surface/level -> N/A, excluded
		}
		if r.Plane == rules.PlaneEngine {
			continue // governance rules handled below
		}
		check := r.Check
		if check == nil {
			results = append(results, rules.Stamp(r, rules.IncOutcome("no checker bound")))
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), opts.PerCheck)
		var out rules.Outcome
		if r.Plane == rules.PlaneStatic && len(docs) > 1 {
			out = worstAcrossDocs(ctx, check, cctx, docs)
		} else {
			out = check(ctx, cctx)
		}
		cancel()
		results = append(results, rules.Stamp(r, out))
	}

	// 2) Governance (AG-GOV-01..04) + waiver set.
	gov, active, waiverRecs, violations := governance(cfg, profile, byID, opts.Now, opts.Approvers, opts.Author)
	results = append(results, gov...)

	// 3) Hermetic-build hint (AG-GOV-07).
	if r, ok := byID["AG-GOV-07"]; ok && profile.AtLeast(r.Profile) {
		results = append(results, rules.Stamp(r, hermeticOutcome()))
	}

	// 4) Apply valid waivers — only a SHOULD failure can be suppressed.
	for i := range results {
		if results[i].Ob() == rules.Should && results[i].Raw().Failing() && active[results[i].RuleID] {
			results[i].SetWaived(true)
		}
	}

	rec := &report.Record{
		Standard:    "AGSSH-STD-001",
		Version:     docVersion,
		Generator:   "agssh-runner " + docVersion,
		GeneratedAt: opts.Now.UTC().Format(time.RFC3339),
		Surface:     surface.URL,
		Profile:     profile.String(),
		Level:       level.String(),
		Results:     results,
		Waivers:     waiverRecs,
		Violations:  violations,
	}

	// 5) Sign the record (AG-GOV-05). The signature binds to a digest of the
	// record payload; an optional artifact file digest is also recorded.
	if opts.Sign {
		if payload, err := rec.CanonicalForSigning(); err == nil {
			rec.ArtifactDigest = report.Digest(payload)
			ctx, cancel := context.WithTimeout(context.Background(), opts.PerCheck)
			if sig, err := report.SignBlob(ctx, tools.Cosign, payload); err == nil {
				rec.Signature = sig
			}
			cancel()
		}
		if opts.ArtifactPath != "" {
			if d, err := report.DigestFile(opts.ArtifactPath); err == nil {
				rec.ArtifactDigest = d
			}
		}
	}

	// 6) AG-GOV-05 result depends on the signature (Gold only).
	if r, ok := byID["AG-GOV-05"]; ok && profile.AtLeast(r.Profile) {
		var out rules.Outcome
		if rec.Signature != nil {
			out = rules.PassOutcome("record externally derived from live surface and signed", "")
		} else {
			out = rules.FailOutcome("record unsigned", "external signed attestation required at Gold (run with -sign and cosign present)")
		}
		r05 := rules.Stamp(r, out)
		rec.Results = append(rec.Results, r05)
	}

	// 7) Gate (fail-closed) + score + fix queue.
	rec.Conformant = gate(rec.Results, violations)
	rec.Score = score(rec.Results, active, byID)
	rec.FixQueue = report.BuildFixQueue(rec.Results)
	return rec
}

// gate blocks on ANY failing MUST, any unwaived failing SHOULD, or any
// governance violation. Inconclusive counts as failing (fail-closed).
func gate(results []rules.Result, violations []string) bool {
	if len(violations) > 0 {
		return false
	}
	for _, res := range results {
		if res.Raw().Failing() && !res.Waived {
			return false
		}
	}
	return true
}

// score is the weighted conformance score; deviation debt is reported beside it.
func score(results []rules.Result, active map[string]bool, byID map[string]rules.Rule) report.Score {
	earned, possible := 0, 0
	for _, res := range results {
		if res.Status == "N/A" {
			continue
		}
		w := res.Sev().Weight()
		possible += w
		if res.Status == "PASS" {
			earned += w
		}
	}
	debt := 0
	for id := range active {
		if r, ok := byID[id]; ok {
			debt += r.Severity.Weight()
		}
	}
	pct := 0.0
	if possible > 0 {
		pct = 100 * float64(earned) / float64(possible)
	}
	return report.Score{Earned: earned, Possible: possible, Pct: pct, DeviationDebt: debt}
}

// fetchDocs retrieves the surface root plus any extra declared same-origin
// paths, each with bounded retries. The root is always first; unreachable URLs
// are dropped (a static check over zero docs stays INCONCLUSIVE via cctx.Doc==nil).
func fetchDocs(client *httpx.Client, surfaceURL string, paths []string, perCheck time.Duration) []*httpx.Doc {
	targets := []string{surfaceURL}
	if base, err := url.Parse(surfaceURL); err == nil {
		seen := map[string]bool{surfaceURL: true}
		for _, p := range paths {
			ref, err := url.Parse(strings.TrimSpace(p))
			if err != nil {
				continue
			}
			full := base.ResolveReference(ref).String()
			if !seen[full] {
				seen[full] = true
				targets = append(targets, full)
			}
		}
	}
	var docs []*httpx.Doc
	for _, t := range targets {
		if d := fetchWithRetry(client, t, perCheck, 3); d != nil {
			docs = append(docs, d)
		}
	}
	return docs
}

// fetchWithRetry retries a transient fetch failure within the per-check budget so
// a single network blip doesn't turn the whole gate red.
func fetchWithRetry(client *httpx.Client, target string, perCheck time.Duration, attempts int) *httpx.Doc {
	for i := 0; i < attempts; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), perCheck)
		d, err := client.Fetch(ctx, target)
		cancel()
		if err == nil {
			return d
		}
	}
	return nil
}

// worstAcrossDocs runs a static checker against every sampled document and keeps
// the worst outcome (Fail > Inconclusive > Pass > N/A) — a per-path weakness is
// never masked by a stronger root.
func worstAcrossDocs(ctx context.Context, check rules.Checker, base *rules.CheckCtx, docs []*httpx.Doc) rules.Outcome {
	var worst rules.Outcome
	for i, d := range docs {
		cc := *base
		cc.Doc = d
		o := check(ctx, &cc)
		if i == 0 || statusRank(o.Status) > statusRank(worst.Status) {
			worst = o
		}
	}
	return worst
}

func statusRank(s rules.Status) int {
	switch s {
	case rules.Fail:
		return 3
	case rules.Inconclusive:
		return 2
	case rules.Pass:
		return 1
	default: // N/A
		return 0
	}
}

// hermeticOutcome infers whether the build environment is ephemeral/hermetic
// from CI signals. Locally it is Inconclusive (fail-closed at Gold).
func hermeticOutcome() rules.Outcome {
	if os.Getenv("CI") == "" {
		return rules.IncOutcome("not running in CI; cannot verify ephemeral hermetic build")
	}
	if os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "" {
		return rules.PassOutcome("CI with OIDC token endpoint (ephemeral credentials)", "")
	}
	return rules.IncOutcome("CI detected but no OIDC token endpoint; use OIDC federation, not stored secrets")
}
