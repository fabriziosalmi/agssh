// Package engine selects the applicable rules for a surface, runs their
// checkers, evaluates the engine-plane governance rules, applies waivers, and
// renders the fail-closed gate verdict into a signed conformance record.
package engine

import (
	"context"
	"os"
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
}

// Evaluate runs the full conformance assessment for one surface.
func Evaluate(cfg *manifest.Config, surface manifest.Surface, opts Options) *report.Record {
	profile, _ := cfg.Profile()
	level, _ := cfg.LevelV()
	tools := rules.DiscoverTools()
	if opts.PerCheck <= 0 {
		opts.PerCheck = 45 * time.Second
	}

	// Fetch the live surface once; static checks read this document.
	var doc *httpx.Doc
	if opts.HTTP != nil {
		ctx, cancel := context.WithTimeout(context.Background(), opts.PerCheck)
		if d, err := opts.HTTP.Fetch(ctx, surface.URL); err == nil {
			doc = d
		}
		cancel()
	}

	cctx := &rules.CheckCtx{
		Surface: surface, Level: level, Allow: cfg.Allow, Zone: cfg.DNS.Zone,
		RepoDir: opts.RepoDir, DistDir: opts.DistDir, WorkflowsDir: opts.WorkflowsDir,
		Now: opts.Now, HTTP: opts.HTTP, Doc: doc, Tools: tools,
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
		out := check(ctx, cctx)
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
