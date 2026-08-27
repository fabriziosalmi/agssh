package engine

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fabriziosalmi/agssh/internal/httpx"
	"github.com/fabriziosalmi/agssh/internal/manifest"
	"github.com/fabriziosalmi/agssh/internal/rules"
)

func TestFetchDocsMultiPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	client := httpx.New(3 * time.Second)

	docs, rootErr := fetchDocs(client, srv.URL, []string{"/extra", "/extra"}, 3*time.Second)
	if len(docs) != 2 { // root + /extra (deduped)
		t.Fatalf("got %d docs, want 2 (root + one deduped path)", len(docs))
	}
	if rootErr != nil {
		t.Fatalf("reachable root must have no error, got %v", rootErr)
	}
	// An unreachable extra path is dropped; the root still comes back with no error.
	docs, rootErr = fetchDocs(client, srv.URL, []string{"http://127.0.0.1:1/down"}, 1*time.Second)
	if len(docs) != 1 || rootErr != nil {
		t.Fatalf("got %d docs (err %v), want 1 with no root error (unreachable path dropped)", len(docs), rootErr)
	}
	// An unreachable ROOT yields zero docs and a non-nil transport error.
	docs, rootErr = fetchDocs(client, "http://127.0.0.1:1/", nil, 1*time.Second)
	if len(docs) != 0 || rootErr == nil {
		t.Fatalf("unreachable root: got %d docs err=%v, want 0 docs and a non-nil error", len(docs), rootErr)
	}
}

// TestEvaluateUnscannableSurface pins the reachability gate: when the surface
// root cannot be fetched, Evaluate returns a distinct UNSCANNABLE record with no
// verdict, score, fix queue, or results — the runner never observed the surface,
// so it makes no claim about it.
func TestEvaluateUnscannableSurface(t *testing.T) {
	surf := manifest.Surface{URL: "http://127.0.0.1:1/", Kind: "site", Stateless: true}
	cfg := &manifest.Config{TargetProfile: "Bronze", Level: "L0", Surfaces: []manifest.Surface{surf}}
	rec := Evaluate(cfg, surf, Options{
		HTTP: httpx.New(500 * time.Millisecond), Now: time.Now(), PerCheck: 500 * time.Millisecond,
	})
	if !rec.Unscannable {
		t.Fatalf("an unreachable root must be UNSCANNABLE; got conformant=%v results=%d", rec.Conformant, len(rec.Results))
	}
	if rec.Conformant {
		t.Error("an unscannable surface must never be conformant")
	}
	if rec.Score.Possible != 0 || len(rec.FixQueue) != 0 || len(rec.Results) != 0 {
		t.Errorf("unscannable must emit no score/fixqueue/results; got score=%+v fixq=%d results=%d",
			rec.Score, len(rec.FixQueue), len(rec.Results))
	}
	if rec.Unreachable == "" {
		t.Error("unscannable must carry a human transport reason")
	}
}

// TestUnreachableReasonClassifies pins the human wording per failure mode.
func TestUnreachableReasonClassifies(t *testing.T) {
	cases := []struct {
		name  string
		cause error
		want  string // substring
	}{
		{"nxdomain", &net.DNSError{Err: "no such host", Name: "nope.invalid", IsNotFound: true}, "does not resolve"},
		{"refused", errors.New("dial tcp 127.0.0.1:1: connect: connection refused"), "refused"},
		{"timeout", context.DeadlineExceeded, "did not respond"},
		{"tls", errors.New("x509: certificate signed by unknown authority"), "TLS handshake"},
		{"nil", nil, "per-check timeout"},
	}
	for _, c := range cases {
		got := unreachableReason("https://host.example/", c.cause)
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: reason %q must contain %q", c.name, got, c.want)
		}
	}
}

func TestWorstAcrossDocs(t *testing.T) {
	// A static check failing on ANY sampled doc must lose worst-case.
	check := func(_ context.Context, c *rules.CheckCtx) rules.Outcome {
		if c.Doc != nil && c.Doc.Status >= 500 {
			return rules.FailOutcome("5xx", "")
		}
		return rules.PassOutcome("ok", "")
	}
	docs := []*httpx.Doc{{Status: 200}, {Status: 500}, {Status: 200}}
	if out := worstAcrossDocs(context.Background(), check, &rules.CheckCtx{}, docs); out.Status != rules.Fail {
		t.Errorf("worst across docs = %s, want FAIL (a weak path must not be masked)", out.Status)
	}
	allOK := []*httpx.Doc{{Status: 200}, {Status: 200}}
	if out := worstAcrossDocs(context.Background(), check, &rules.CheckCtx{}, allOK); out.Status != rules.Pass {
		t.Errorf("all-ok across docs = %s, want PASS", out.Status)
	}
}

// res builds a stamped Result with a chosen obligation/severity/status/waived.
func res(ob rules.Obligation, sev rules.Severity, st rules.Status, waived bool) rules.Result {
	r := rules.Rule{ID: "X", Obligation: ob, Severity: sev, Profile: manifest.Bronze, Plane: rules.PlaneStatic}
	var o rules.Outcome
	switch st {
	case rules.Pass:
		o = rules.PassOutcome("ok", "")
	case rules.Fail:
		o = rules.FailOutcome("bad", "")
	case rules.Inconclusive:
		o = rules.IncOutcome("inc")
	default:
		o = rules.Outcome{Status: rules.NotApplicable}
	}
	out := rules.Stamp(r, o)
	if waived {
		out.SetWaived(true)
	}
	return out
}

// TestGateTruthTable proves the fail-closed gate EXHAUSTIVELY: a single result
// passes the gate iff it is not (Failing AND not waived). Failing == Fail or
// Inconclusive. This is the core promise — nothing is green unless proven — as a
// closed-form truth table, so there is no doubt about the verdict logic.
func TestEnforceCIRulesGate(t *testing.T) {
	surf := manifest.Surface{URL: "https://example.test/", Kind: "site", Stateless: true}
	hasCI := func(enforce bool) bool {
		cfg := &manifest.Config{
			TargetProfile: "Silver", Level: "L2",
			Surfaces: []manifest.Surface{surf},
			Pipeline: manifest.Pipeline{EnforceCIRules: enforce},
		}
		rec := Evaluate(cfg, surf, Options{Now: time.Now(), PerCheck: time.Second})
		for _, r := range rec.Results {
			if r.Family == "AG-CI" {
				return true
			}
		}
		return false
	}
	if hasCI(false) {
		t.Errorf("enforce_ci_rules=false must exclude the AG-CI family")
	}
	if !hasCI(true) {
		t.Errorf("enforce_ci_rules=true must evaluate the AG-CI family")
	}
}

func TestGateTruthTable(t *testing.T) {
	statuses := []rules.Status{rules.Pass, rules.Fail, rules.Inconclusive, rules.NotApplicable}
	for _, st := range statuses {
		for _, waived := range []bool{false, true} {
			failing := st == rules.Fail || st == rules.Inconclusive
			want := !(failing && !waived) // conformant unless an unwaived failing result
			got := gate([]rules.Result{res(rules.Should, rules.High, st, waived)}, nil)
			if got != want {
				t.Errorf("gate(status=%s waived=%v) = %v, want %v", st, waived, got, want)
			}
		}
	}
}

// TestGateAnyPositionBlocks pins the "ANY failing result blocks" contract with
// multi-element slices and hardcoded expectations (not a formula), killing a
// "check only results[0]" mutant that the single-element table would miss.
func TestGateAnyPositionBlocks(t *testing.T) {
	pass := res(rules.Should, rules.Low, rules.Pass, false)
	failUnwaived := res(rules.Must, rules.Critical, rules.Fail, false)

	if gate([]rules.Result{pass, pass, failUnwaived}, nil) {
		t.Error("an unwaived FAIL in the LAST position must block")
	}
	if gate([]rules.Result{failUnwaived, pass}, nil) {
		t.Error("an unwaived FAIL in the FIRST position must block")
	}
	if !gate([]rules.Result{pass, pass, pass}, nil) {
		t.Error("all PASS must be conformant")
	}
}

func TestGateInconclusiveIsFailClosed(t *testing.T) {
	if gate([]rules.Result{res(rules.Should, rules.Low, rules.Inconclusive, false)}, nil) {
		t.Fatal("a single unwaived INCONCLUSIVE must block the gate (fail-closed)")
	}
}

func TestGateViolationsAlwaysBlock(t *testing.T) {
	allPass := []rules.Result{res(rules.Must, rules.Critical, rules.Pass, false)}
	if gate(allPass, []string{"a governance violation"}) {
		t.Fatal("any governance violation must block, even with all checks passing")
	}
	if !gate(allPass, nil) {
		t.Fatal("all-pass, no violations must be conformant")
	}
}

func TestGateWaivedFailingPasses(t *testing.T) {
	// At the gate layer a waived failing result no longer blocks (whether a waiver
	// is *allowed* is enforced earlier, in governance()).
	mixed := []rules.Result{
		res(rules.Must, rules.Critical, rules.Pass, false),
		res(rules.Should, rules.Medium, rules.Fail, true),
	}
	if !gate(mixed, nil) {
		t.Fatal("a waived failing SHOULD must not block the gate")
	}
}

func TestScore(t *testing.T) {
	// Critical=8, High=4, Medium=2, Low=1. N/A excluded from the denominator.
	results := []rules.Result{
		res(rules.Must, rules.Critical, rules.Pass, false),       // +8 earned, +8 possible
		res(rules.Should, rules.High, rules.Fail, false),         // +4 possible
		res(rules.Should, rules.Medium, rules.Pass, false),       // +2 earned, +2 possible
		res(rules.Should, rules.Low, rules.NotApplicable, false), // excluded
	}
	s := score(results, map[string]bool{}, map[string]rules.Rule{})
	if s.Earned != 10 || s.Possible != 14 {
		t.Fatalf("score earned/possible = %d/%d, want 10/14", s.Earned, s.Possible)
	}
	if s.Pct < 71.4 || s.Pct > 71.5 {
		t.Errorf("pct = %.2f, want ~71.43", s.Pct)
	}
	if s.Scored != 3 { // 3 non-N/A rules in the denominator (the N/A is excluded)
		t.Errorf("scored = %d, want 3 (N/A excluded from the level-relative scope)", s.Scored)
	}
}

// TestBuildEnvironmentDegraded pins RUN-07: a missing tool that silently disabled
// a plane (Chrome → dynamic) surfaces as degraded=true with the tool named, so a
// consumer summarising by status can still tell a partial scan from a complete
// one. A missing tool that no in-scope rule needed does not degrade.
func TestBuildEnvironmentDegraded(t *testing.T) {
	dynInc := rules.Stamp(
		rules.Rule{ID: "AG-PRV-02", Plane: rules.PlaneDynamic, Severity: rules.Critical, Obligation: rules.Must, Profile: manifest.Bronze},
		rules.IncOutcome("headless load failed"),
	)
	staticPass := rules.Stamp(
		rules.Rule{ID: "AG-CSP-01", Plane: rules.PlaneStatic, Severity: rules.High, Profile: manifest.Bronze},
		rules.PassOutcome("ok", ""),
	)
	has := func(ss []string, w string) bool {
		for _, s := range ss {
			if s == w {
				return true
			}
		}
		return false
	}

	// Chrome absent + a dynamic rule INCONCLUSIVE -> degraded, chrome named.
	env := buildEnvironment(rules.Toolbox{}, []rules.Result{dynInc, staticPass})
	if !env.Degraded || !has(env.MissingTools, "chrome") {
		t.Fatalf("chrome absent + dynamic INCONCLUSIVE must be degraded; got %+v", env)
	}
	if env.Tools["chrome"] {
		t.Error("tools[chrome] must be false when Chrome is not resolved")
	}
	// Chrome present -> not degraded, even with a dynamic INCONCLUSIVE from another cause.
	if env2 := buildEnvironment(rules.Toolbox{Chrome: "/usr/bin/chrome"}, []rules.Result{dynInc, staticPass}); env2.Degraded {
		t.Errorf("Chrome present must not be degraded; got %+v", env2)
	}
	// A missing tool no in-scope rule needed -> not degraded.
	if env3 := buildEnvironment(rules.Toolbox{Chrome: "/usr/bin/chrome"}, []rules.Result{staticPass}); env3.Degraded {
		t.Errorf("a missing tool no rule needed must not degrade; got %+v", env3)
	}
}

func TestHermeticOutcome(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	if hermeticOutcome().Status != rules.Inconclusive {
		t.Error("outside CI: want INCONCLUSIVE")
	}
	t.Setenv("CI", "true")
	if hermeticOutcome().Status != rules.Inconclusive {
		t.Error("CI without OIDC: want INCONCLUSIVE")
	}
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example")
	if hermeticOutcome().Status != rules.Pass {
		t.Error("CI with OIDC endpoint: want PASS")
	}
}

// ---- governance (the draconian heart), exhaustively ----

func ruleIndex() map[string]rules.Rule {
	m := map[string]rules.Rule{}
	for _, r := range rules.All() {
		m[r.ID] = r
	}
	return m
}

func TestGovernanceMustNeverWaivable(t *testing.T) {
	// AG-NET-01 is a MUST. A waiver covering it is invalid and a violation.
	cfg := &manifest.Config{Deviations: []manifest.Deviation{{
		Rule: "AG-NET-01", Reason: "x", Expires: "2999-01-01", Approver: "a", Signature: "s",
	}}}
	_, active, _, viol := governance(cfg, manifest.Bronze, ruleIndex(), time.Now(), nil, "")
	if active["AG-NET-01"] {
		t.Error("a MUST must never be waivable (AG-GOV-01)")
	}
	if len(viol) == 0 {
		t.Error("waiving a MUST must produce a governance violation")
	}
}

func TestGovernanceExpiry(t *testing.T) {
	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	idx := ruleIndex()
	// Pick a real SHOULD rule.
	should := firstShould(t, idx)

	expired := &manifest.Config{Deviations: []manifest.Deviation{{Rule: should, Expires: "2020-01-01"}}}
	if _, active, _, viol := governance(expired, manifest.Bronze, idx, now, nil, ""); active[should] || len(viol) == 0 {
		t.Error("an expired waiver must be inactive and a violation (AG-GOV-02)")
	}

	beyond := &manifest.Config{
		Deviations: []manifest.Deviation{{Rule: should, Expires: "2027-01-01"}},
		Waivers:    manifest.Waivers{Budget: manifest.Budget{MaxWindowDays: 30}},
	}
	if _, active, _, viol := governance(beyond, manifest.Bronze, idx, now, nil, ""); active[should] || len(viol) == 0 {
		t.Error("a waiver expiring beyond the window must be rejected (AG-GOV-02)")
	}

	ok := &manifest.Config{Deviations: []manifest.Deviation{{Rule: should, Expires: "2026-06-20"}}}
	if _, active, _, viol := governance(ok, manifest.Bronze, idx, now, nil, ""); !active[should] || len(viol) != 0 {
		t.Errorf("an in-window SHOULD waiver must be active with no violation (got active=%v viol=%v)", active[should], viol)
	}
}

func TestGovernanceSegregationOfDutiesAtGold(t *testing.T) {
	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	idx := ruleIndex()
	should := firstShouldAtGold(t, idx)

	base := func(d manifest.Deviation) *manifest.Config {
		d.Rule, d.Expires = should, "2026-06-20"
		return &manifest.Config{Deviations: []manifest.Deviation{d}}
	}
	approvers := map[string]bool{"approver@x": true}

	// Self-approved -> invalid at Gold.
	if _, active, _, _ := governance(base(manifest.Deviation{Approver: "author@x", Signature: "s"}), manifest.Gold, idx, now, approvers, "author@x"); active[should] {
		t.Error("self-approved waiver must be invalid at Gold (AG-GOV-04)")
	}
	// Approver not in allow-list -> invalid.
	if _, active, _, _ := governance(base(manifest.Deviation{Approver: "stranger@x", Signature: "s"}), manifest.Gold, idx, now, approvers, "author@x"); active[should] {
		t.Error("unknown approver must be invalid at Gold")
	}
	// Unsigned -> invalid.
	if _, active, _, _ := governance(base(manifest.Deviation{Approver: "approver@x"}), manifest.Gold, idx, now, approvers, "author@x"); active[should] {
		t.Error("unsigned waiver must be invalid at Gold")
	}
	// Distinct, allow-listed, signed -> valid.
	if _, active, _, _ := governance(base(manifest.Deviation{Approver: "approver@x", Signature: "s"}), manifest.Gold, idx, now, approvers, "author@x"); !active[should] {
		t.Error("a distinct, allow-listed, signed approver must yield a valid waiver at Gold")
	}
}

func TestGovernanceDebtCeiling(t *testing.T) {
	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	idx := ruleIndex()
	a, b := twoShoulds(t, idx)
	cfg := &manifest.Config{
		Deviations: []manifest.Deviation{{Rule: a, Expires: "2026-06-20"}, {Rule: b, Expires: "2026-06-20"}},
		Waivers:    manifest.Waivers{Budget: manifest.Budget{MaxCount: 1, MaxWindowDays: 30}},
	}
	_, _, _, viol := governance(cfg, manifest.Bronze, idx, now, nil, "")
	if len(viol) == 0 {
		t.Error("exceeding max_count must raise a debt-ceiling violation (AG-GOV-03)")
	}
}

// ---- helpers to pick real rules from the registry ----

func firstShould(t *testing.T, idx map[string]rules.Rule) string {
	t.Helper()
	for _, r := range idx {
		if r.Obligation == rules.Should && r.Profile == manifest.Bronze {
			return r.ID
		}
	}
	for _, r := range idx { // fall back to any SHOULD
		if r.Obligation == rules.Should {
			return r.ID
		}
	}
	t.Fatal("no SHOULD rule in registry")
	return ""
}

func firstShouldAtGold(t *testing.T, idx map[string]rules.Rule) string {
	t.Helper()
	for _, r := range idx {
		if r.Obligation == rules.Should && manifest.Gold.AtLeast(r.Profile) {
			return r.ID
		}
	}
	t.Fatal("no SHOULD rule visible at Gold")
	return ""
}

func twoShoulds(t *testing.T, idx map[string]rules.Rule) (string, string) {
	t.Helper()
	var ids []string
	for _, r := range idx {
		if r.Obligation == rules.Should && manifest.Silver.AtLeast(r.Profile) {
			ids = append(ids, r.ID)
		}
		if len(ids) == 2 {
			return ids[0], ids[1]
		}
	}
	t.Fatal("need two SHOULD rules visible at Silver")
	return "", ""
}
