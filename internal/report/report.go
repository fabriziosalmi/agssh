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
	Standard       string         `json:"standard"`
	Version        string         `json:"version"`
	Generator      string         `json:"generator"`
	GeneratedAt    string         `json:"generated_at"`
	Surface        string         `json:"surface"`
	Profile        string         `json:"profile"`
	Level          string         `json:"level"`
	Conformant     bool           `json:"conformant"`
	Score          Score          `json:"score"`
	Results        []rules.Result `json:"results"`
	Waivers        []WaiverRec    `json:"waivers,omitempty"`
	Violations     []string       `json:"governance_violations,omitempty"`
	FixQueue       []FixItem      `json:"fix_queue,omitempty"`
	ArtifactDigest string         `json:"artifact_digest,omitempty"`
	Signature      *Signature     `json:"signature"`
}

// CanonicalForSigning returns the record serialized with the signature field
// nulled, so the signature can bind to a stable digest of its own payload.
func (r *Record) CanonicalForSigning() ([]byte, error) {
	clone := *r
	clone.Signature = nil
	return json.Marshal(&clone)
}

func (r *Record) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// BuildFixQueue collects unwaived failing results, highest weight first.
func BuildFixQueue(results []rules.Result) []FixItem {
	type wq struct {
		item   FixItem
		weight int
	}
	var rows []wq
	for _, res := range results {
		if res.Raw().Failing() && !res.Waived {
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

// Render writes a concise terminal summary.
func (r *Record) Render(w io.Writer) {
	verdict := "NON-CONFORMANT"
	if r.Conformant {
		verdict = "CONFORMANT"
	}
	fmt.Fprintf(w, "\nAGSSH-STD-001 %s — %s @ %s/%s\n", r.Version, r.Surface, r.Profile, r.Level)
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
		fmt.Fprintf(w, "\nFix queue (highest severity first):\n")
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
