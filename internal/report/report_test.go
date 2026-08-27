package report

import (
	"strings"
	"testing"

	"github.com/fabriziosalmi/agssh/internal/rules"
)

// stamp builds a Result at a chosen status/severity for queue-split tests.
func stamp(id, family string, sev rules.Severity, st rules.Status, reason string) rules.Result {
	r := rules.Rule{ID: id, Title: id + " title", Family: family, Severity: sev, Obligation: rules.Should}
	var o rules.Outcome
	switch st {
	case rules.Fail:
		o = rules.FailOutcome("observed "+id, "expected "+id)
	case rules.Inconclusive:
		o = rules.IncOutcome(reason)
	default:
		o = rules.PassOutcome("ok", "")
	}
	return rules.Stamp(r, o)
}

// TestFixQueueAndUnassessedSplit pins RUN-09: FAILs go to the (severity-ranked)
// fix queue; INCONCLUSIVEs go to a separate, rule-ID-ordered "could not assess"
// list carrying the reason — never interleaved, never severity-ranked together.
func TestFixQueueAndUnassessedSplit(t *testing.T) {
	results := []rules.Result{
		stamp("AG-SUP-06", "AG-SUP", rules.High, rules.Inconclusive, "osv-scanner not found on PATH"),
		stamp("AG-NET-02", "AG-NET", rules.Critical, rules.Fail, ""),
		stamp("AG-HDR-02", "AG-HDR", rules.Medium, rules.Fail, ""),
		stamp("AG-DNS-01", "AG-DNS", rules.Medium, rules.Inconclusive, "no dns.zone declared in manifest"),
		stamp("AG-CSP-01", "AG-CSP", rules.Low, rules.Pass, ""),
	}

	fq := BuildFixQueue(results)
	if len(fq) != 2 {
		t.Fatalf("fix queue must hold the 2 FAILs only, got %d: %+v", len(fq), fq)
	}
	// Highest weight (Critical AG-NET-02) first.
	if fq[0].Rule != "AG-NET-02" || fq[1].Rule != "AG-HDR-02" {
		t.Errorf("fix queue must be severity-ranked, got %s then %s", fq[0].Rule, fq[1].Rule)
	}
	for _, f := range fq {
		if f.Status == "INCONCLUSIVE" {
			t.Errorf("an INCONCLUSIVE rule (%s) leaked into the fix queue", f.Rule)
		}
	}

	ua := BuildUnassessed(results)
	if len(ua) != 2 {
		t.Fatalf("unassessed must hold the 2 INCONCLUSIVEs, got %d: %+v", len(ua), ua)
	}
	// Ordered by rule ID (AG-DNS-01 before AG-SUP-06), NOT by severity.
	if ua[0].Rule != "AG-DNS-01" || ua[1].Rule != "AG-SUP-06" {
		t.Errorf("unassessed must be rule-ID-ordered, got %s then %s", ua[0].Rule, ua[1].Rule)
	}
	if ua[1].Reason != "osv-scanner not found on PATH" {
		t.Errorf("unassessed must carry the checker's reason, got %q", ua[1].Reason)
	}
}

// TestRenderSectionsAreDistinct proves the two sections render under distinct,
// unambiguous headers so a reader (or an LLM summarising the MCP text) can never
// read "could not check" as "must fix".
func TestRenderSectionsAreDistinct(t *testing.T) {
	rec := &Record{
		Version: "vX", Surface: "https://x.test/", Profile: "Bronze", Level: "L0",
		FixQueue:   []FixItem{{Rule: "AG-NET-02", Title: "loaders", Severity: "CRITICAL", Status: "FAIL"}},
		Unassessed: []UnassessedItem{{Rule: "AG-SUP-06", Title: "vulns", Severity: "HIGH", Reason: "osv-scanner not found on PATH"}},
	}
	var b strings.Builder
	rec.Render(&b)
	out := b.String()
	if !strings.Contains(out, "Fix queue (FAIL only") {
		t.Error("fix-queue header must state FAIL-only")
	}
	if !strings.Contains(out, "Could not assess") {
		t.Error("unassessed section must have its own header")
	}
	// AG-SUP-06 must appear only under the second section, with its reason.
	if !strings.Contains(out, "osv-scanner not found on PATH") {
		t.Error("unassessed reason must be shown")
	}
	fqIdx := strings.Index(out, "Fix queue")
	caIdx := strings.Index(out, "Could not assess")
	if fqIdx < 0 || caIdx < 0 || caIdx < fqIdx {
		t.Error("fix queue must render before the could-not-assess section")
	}
}

// TestRenderDegradedEnvironment pins RUN-07: a degraded environment surfaces as a
// prominent header line, not buried in one rule's error.
func TestRenderDegradedEnvironment(t *testing.T) {
	rec := &Record{
		Version: "vX", Surface: "https://x.test/", Profile: "Bronze", Level: "L0",
		Environment: &Environment{
			Degraded: true, Reason: "no headless browser — the dynamic plane did not run; set AGSSH_CHROME",
			Tools: map[string]bool{"chrome": false}, MissingTools: []string{"chrome"},
		},
	}
	var b strings.Builder
	rec.Render(&b)
	out := b.String()
	if !strings.Contains(out, "Partial scan (degraded environment)") || !strings.Contains(out, "AGSSH_CHROME") {
		t.Errorf("degraded env must render a prominent header with the fix; got:\n%s", out)
	}

	// A fully-armed environment renders no degraded header.
	ok := &Record{Version: "vX", Surface: "s", Profile: "Bronze", Level: "L0",
		Environment: &Environment{Degraded: false, Tools: map[string]bool{"chrome": true}}}
	var b2 strings.Builder
	ok.Render(&b2)
	if strings.Contains(b2.String(), "Partial scan") {
		t.Error("a non-degraded environment must not render the partial-scan header")
	}
}
