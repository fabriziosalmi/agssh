// Package rules defines the rule model and every checker. A rule is a binary
// predicate over a defined input (the live surface, its DNS zone, its repo)
// that emits structured evidence. Draconian posture: a rule the runner cannot
// conclusively verify is INCONCLUSIVE, which the gate treats as a FAIL.
package rules

import (
	"context"
	"os"
	"os/exec"
	"time"

	"github.com/fabriziosalmi/agssh/internal/httpx"
	"github.com/fabriziosalmi/agssh/internal/manifest"
)

type Status int

const (
	Pass          Status = iota // verified conformant
	Fail                        // verified non-conformant
	Inconclusive                // could not verify -> fail-closed (counts as Fail)
	NotApplicable               // out of scope at this level/profile/surface
)

func (s Status) String() string {
	return [...]string{"PASS", "FAIL", "INCONCLUSIVE", "N/A"}[s]
}

// Failing reports the fail-closed verdict: anything not provably PASS (and not
// excluded as N/A) blocks.
func (s Status) Failing() bool { return s == Fail || s == Inconclusive }

type Obligation int

const (
	Must Obligation = iota
	Should
)

func (o Obligation) String() string { return [...]string{"MUST", "SHOULD"}[o] }

type Severity int

const (
	Critical Severity = iota
	High
	Medium
	Low
)

func (s Severity) String() string { return [...]string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}[s] }

// Weight orders the fix queue and feeds the deviation-debt budget.
func (s Severity) Weight() int { return [...]int{8, 4, 2, 1}[s] }

type Plane int

const (
	PlaneStatic  Plane = iota // headers / HTML / CSP of the live surface
	PlaneDynamic              // headless-browser observation (chromedp)
	PlaneDNS                  // DNS zone (CAA / DNSSEC / dangling)
	PlaneTLS                  // TLS negotiation floor
	PlaneSupply               // dependency / artifact scanners
	PlaneCI                   // workflow static analysis
	PlaneEngine               // governance, evaluated by the engine itself
)

func (p Plane) String() string {
	return [...]string{"static", "dynamic", "dns", "tls", "supply", "ci", "engine"}[p]
}

type Evidence struct {
	Observed string         `json:"observed,omitempty"`
	Expected string         `json:"expected,omitempty"`
	Detail   map[string]any `json:"detail,omitempty"`
}

// Outcome is what a checker returns; the engine stamps it with rule metadata.
type Outcome struct {
	Status   Status
	Evidence Evidence
	Err      string
}

func okay(observed, expected string) Outcome {
	return Outcome{Status: Pass, Evidence: Evidence{Observed: observed, Expected: expected}}
}
func bad(observed, expected string) Outcome {
	return Outcome{Status: Fail, Evidence: Evidence{Observed: observed, Expected: expected}}
}
func inconclusive(reason string) Outcome {
	return Outcome{Status: Inconclusive, Err: reason}
}
func na() Outcome { return Outcome{Status: NotApplicable} }

// Result is a stamped Outcome ready for the report.
type Result struct {
	RuleID     string     `json:"rule"`
	Title      string     `json:"title"`
	Family     string     `json:"family"`
	Plane      string     `json:"plane"`
	Obligation string     `json:"obligation"`
	Severity   string     `json:"severity"`
	Profile    string     `json:"profile"`
	Status     string     `json:"status"`
	Waived     bool       `json:"waived,omitempty"`
	Evidence   Evidence   `json:"evidence"`
	Err        string     `json:"error,omitempty"`
	raw        Status     // internal verdict, pre-waiver
	sev        Severity   // internal, for scoring
	ob         Obligation // internal
}

func (r Result) Raw() Status         { return r.raw }
func (r Result) Sev() Severity       { return r.sev }
func (r Result) Ob() Obligation      { return r.ob }
func (r *Result) SetWaived(b bool)   { r.Waived = b }
func (r *Result) SetStatus(s Status) { r.raw = s; r.Status = s.String() }

// Stamp builds a fully-populated Result from a Rule and a checker Outcome.
func Stamp(r Rule, o Outcome) Result {
	return Result{
		RuleID:     r.ID,
		Title:      r.Title,
		Family:     r.Family,
		Plane:      r.Plane.String(),
		Obligation: r.Obligation.String(),
		Severity:   r.Severity.String(),
		Profile:    r.Profile.String(),
		Status:     o.Status.String(),
		Evidence:   o.Evidence,
		Err:        o.Err,
		raw:        o.Status,
		sev:        r.Severity,
		ob:         r.Obligation,
	}
}

// MakeOutcome exposes the unexported Outcome constructors to sibling packages
// that need to synthesize engine-plane results.
func PassOutcome(observed, expected string) Outcome { return okay(observed, expected) }
func FailOutcome(observed, expected string) Outcome { return bad(observed, expected) }
func IncOutcome(reason string) Outcome              { return inconclusive(reason) }

// Toolbox holds resolved paths to external scanners; empty means "not found",
// and a check that needs a missing tool returns Inconclusive.
type Toolbox struct {
	OSVScanner string
	Gitleaks   string
	Zizmor     string
	Cosign     string
	Chrome     string
}

func DiscoverTools() Toolbox {
	look := func(names ...string) string {
		for _, n := range names {
			if p, err := exec.LookPath(n); err == nil {
				return p
			}
		}
		return ""
	}
	return Toolbox{
		OSVScanner: look("osv-scanner"),
		Gitleaks:   look("gitleaks"),
		Zizmor:     look("zizmor"),
		Cosign:     look("cosign"),
		Chrome:     chromePath(look),
	}
}

// chromePath resolves a headless browser: explicit env first (AGSSH_CHROME /
// CHROME_PATH, e.g. the headless-shell path inside the container image), then
// the usual binaries on PATH.
func chromePath(look func(...string) string) string {
	for _, env := range []string{"AGSSH_CHROME", "CHROME_PATH"} {
		if v := os.Getenv(env); v != "" {
			if _, err := exec.LookPath(v); err == nil {
				return v
			}
			if fi, err := os.Stat(v); err == nil && !fi.IsDir() {
				return v
			}
		}
	}
	return look("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "headless-shell")
}

// CheckCtx is the evidence surface a checker may read.
type CheckCtx struct {
	Surface      manifest.Surface
	Level        manifest.Level
	Allow        manifest.Allow
	Zone         string
	RepoDir      string
	DistDir      string
	WorkflowsDir string
	Now          time.Time
	HTTP         *httpx.Client
	Doc          *httpx.Doc
	Tools        Toolbox
}

type Checker func(ctx context.Context, c *CheckCtx) Outcome

// Rule is one normative requirement.
type Rule struct {
	ID         string
	Title      string
	Family     string
	Obligation Obligation
	Severity   Severity
	Profile    manifest.Profile
	Plane      Plane
	Applies    func(manifest.Surface, manifest.Level) bool
	Check      Checker
}

// ---- applicability helpers ----

func always(_ manifest.Surface, _ manifest.Level) bool { return true }

func atLevels(ls ...manifest.Level) func(manifest.Surface, manifest.Level) bool {
	return func(_ manifest.Surface, l manifest.Level) bool {
		for _, x := range ls {
			if x == l {
				return true
			}
		}
		return false
	}
}

func ifFileGen(s manifest.Surface, _ manifest.Level) bool       { return s.GeneratesFiles }
func ifThreadedWASM(s manifest.Surface, _ manifest.Level) bool  { return s.ThreadedWASM }
func ifServiceWorker(s manifest.Surface, _ manifest.Level) bool { return s.HasServiceWorker }

// todo marks a rule whose automated checker is not implemented in this build.
// Fail-closed: it returns Inconclusive with the tool/approach to wire in.
func todo(how string) Checker {
	return func(_ context.Context, _ *CheckCtx) Outcome {
		return inconclusive("not auto-verified in this build — " + how)
	}
}
