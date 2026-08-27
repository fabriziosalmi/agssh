// Package report defines the signed conformance record (the evidence artifact)
// and renders a human summary. The record is the authoritative output of an
// external run against the live surface (AG-GOV-05).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/fabriziosalmi/agssh/internal/rules"
)

type Score struct {
	Earned        int     `json:"earned"`
	Possible      int     `json:"possible"`
	Pct           float64 `json:"pct"`
	DeviationDebt int     `json:"deviation_debt"`
}

type FixItem struct {
	Rule     string `json:"rule"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
	Expected string `json:"expected,omitempty"`
	Observed string `json:"observed,omitempty"`
}

// UnassessedItem is a rule the runner could not evaluate (INCONCLUSIVE). It is
// kept in a list distinct from the fix queue and is NOT ranked by severity:
// severity describes the risk a rule guards against, which says nothing about a
// check that never ran. The reason (and, where the checker gave one, its
// remediation) tells the operator what to supply — install a scanner, pass
// -repo, fix DNS — rather than a change to the surface itself.
type UnassessedItem struct {
	Rule     string `json:"rule"`
	Title    string `json:"title"`
	Family   string `json:"family"`
	Severity string `json:"severity"`
	Reason   string `json:"reason,omitempty"`
}

type WaiverRec struct {
	Rule     string `json:"rule"`
	Approver string `json:"approver,omitempty"`
	Expires  string `json:"expires,omitempty"`
	Valid    bool   `json:"valid"`
	Reason   string `json:"reason,omitempty"`
	Note     string `json:"note,omitempty"`
}

type Signature struct {
	Scheme string `json:"scheme"`
	Value  string `json:"value"`
}

type Record struct {
	Standard       string           `json:"standard"`
	Version        string           `json:"version"`
	Generator      string           `json:"generator"`
	GeneratedAt    string           `json:"generated_at"`
	Surface        string           `json:"surface"`
	Profile        string           `json:"profile"`
	Level          string           `json:"level"`
	Unscannable    bool             `json:"unscannable,omitempty"`
	Unreachable    string           `json:"unreachable_reason,omitempty"`
	Conformant     bool             `json:"conformant"`
	Score          Score            `json:"score"`
	Results        []rules.Result   `json:"results"`
	Waivers        []WaiverRec      `json:"waivers,omitempty"`
	Violations     []string         `json:"governance_violations,omitempty"`
	FixQueue       []FixItem        `json:"fix_queue,omitempty"`
	Unassessed     []UnassessedItem `json:"unassessed,omitempty"`
	ArtifactDigest string           `json:"artifact_digest,omitempty"`
	Signature      *Signature       `json:"signature"`
}

// CanonicalForSigning returns the record serialized with the signature field
// nulled, so the signature can bind to a stable digest of its own payload.
func (r *Record) CanonicalForSigning() ([]byte, error) {
	clone := *r
	clone.Signature = nil
	return json.Marshal(&clone)
}

func (r *Record) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// BuildFixQueue collects unwaived FAIL results, highest weight first. It contains
// only rules the runner actually evaluated and found non-conformant — things the
// surface owner can change. Rules the runner could NOT evaluate (INCONCLUSIVE)
// are deliberately excluded: mixing "you must fix this" with "we could not check
// this" under one severity ordering makes the queue misleading. They go to
// BuildUnassessed instead.
func BuildFixQueue(results []rules.Result) []FixItem {
	type wq struct {
		item   FixItem
		weight int
	}
	var rows []wq
	for _, res := range results {
		if res.Raw() == rules.Fail && !res.Waived {
			rows = append(rows, wq{
				item: FixItem{
					Rule: res.RuleID, Title: res.Title, Severity: res.Severity,
					Status: res.Status, Expected: res.Evidence.Expected, Observed: res.Evidence.Observed,
				},
				weight: res.Sev().Weight(),
			})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].weight > rows[j].weight })
	out := make([]FixItem, len(rows))
	for i, r := range rows {
		out[i] = r.item
	}
	return out
}

// BuildUnassessed collects unwaived INCONCLUSIVE results — rules the runner could
// not evaluate (a missing scanner, an unfetched path, an undeclared zone). These
// still block the gate (fail-closed), but they are NOT fixes to the surface and
// are NOT ranked by severity; they are ordered stably by rule ID so a consumer
// cannot flatten "could not check" back into "must fix".
func BuildUnassessed(results []rules.Result) []UnassessedItem {
	var out []UnassessedItem
	for _, res := range results {
		if res.Raw() == rules.Inconclusive && !res.Waived {
			reason := res.Err
			if reason == "" {
				reason = res.Evidence.Observed
			}
			out = append(out, UnassessedItem{
				Rule: res.RuleID, Title: res.Title, Family: res.Family,
				Severity: res.Severity, Reason: reason,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Rule < out[j].Rule })
	return out
}

// Render writes a concise terminal summary.
func (r *Record) Render(w io.Writer) {
	fmt.Fprintf(w, "\nAGSSH-STD-001 %s — %s @ %s/%s\n", r.Version, r.Surface, r.Profile, r.Level)

	// A surface the runner never fetched yields no observations: emitting a
	// verdict, score, or badge would be a claim about something it never saw.
	// Report it as UNSCANNABLE with the transport cause and stop here.
	if r.Unscannable {
		fmt.Fprintf(w, "Verdict: UNSCANNABLE — %s\n", r.Unreachable)
		fmt.Fprintln(w, "The surface could not be fetched; no score, fix queue, or badge is emitted.")
		fmt.Fprintln(w)
		return
	}

	verdict := "NON-CONFORMANT"
	if r.Conformant {
		verdict = "CONFORMANT"
	}
	fmt.Fprintf(w, "Verdict: %s   Score: %d/%d (%.0f%%)   Deviation debt: %d\n",
		verdict, r.Score.Earned, r.Score.Possible, r.Score.Pct, r.Score.DeviationDebt)

	var pass, fail, inc, na, waived int
	for _, res := range r.Results {
		switch {
		case res.Waived:
			waived++
		case res.Status == "PASS":
			pass++
		case res.Status == "FAIL":
			fail++
		case res.Status == "INCONCLUSIVE":
			inc++
		case res.Status == "N/A":
			na++
		}
	}
	fmt.Fprintf(w, "Rules: %d PASS · %d FAIL · %d INCONCLUSIVE · %d waived · %d N/A\n",
		pass, fail, inc, waived, na)

	if len(r.Violations) > 0 {
		fmt.Fprintf(w, "\nGovernance violations:\n")
		for _, v := range r.Violations {
			fmt.Fprintf(w, "  ✗ %s\n", v)
		}
	}
	if len(r.FixQueue) > 0 {
		fmt.Fprintf(w, "\nFix queue (FAIL only, highest severity first):\n")
		for _, f := range r.FixQueue {
			line := fmt.Sprintf("  [%s] %s %s", f.Severity, f.Rule, f.Title)
			fmt.Fprintln(w, line)
			if f.Observed != "" {
				fmt.Fprintf(w, "         observed: %s\n", trim(f.Observed, 110))
			}
			if f.Expected != "" {
				fmt.Fprintf(w, "         expected: %s\n", trim(f.Expected, 110))
			}
		}
	}
	if len(r.Unassessed) > 0 {
		// A separate, unranked section: these rules never ran, so severity (the
		// risk they guard against) says nothing about them. Fail-closed still
		// blocks on them; the reason tells the operator what to supply.
		fmt.Fprintf(w, "\nCould not assess (%d — unverified, fail-closed; supply what's missing):\n", len(r.Unassessed))
		for _, u := range r.Unassessed {
			fmt.Fprintf(w, "  %s %s\n", u.Rule, u.Title)
			if u.Reason != "" {
				fmt.Fprintf(w, "         reason: %s\n", trim(u.Reason, 110))
			}
		}
	}
	if r.Signature != nil {
		fmt.Fprintf(w, "\nSigned: %s (digest %s)\n", r.Signature.Scheme, short(r.ArtifactDigest))
	}
	fmt.Fprintln(w)
}

func trim(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
func short(d string) string {
	if len(d) > 16 {
		return d[:16]
	}
	return d
}
