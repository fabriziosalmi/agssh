package rules

import (
	"fmt"
	"strings"

	"github.com/fabriziosalmi/agssh/internal/manifest"
)

// RuleMarkdown renders one rule as Markdown: registry metadata, its mode at each
// level, and the standard's own why / check / fix / tool text from spec.json,
// word for word. A rule without text says so instead of inventing a remediation.
// The MCP rule resource and `agssh rule <id>` both print this, so they cannot
// disagree.
func RuleMarkdown(r Rule) string {
	sr, fam, hasText := SpecFor(r.ID)
	m := ruleLevelModes(r.ID)

	var b strings.Builder
	fmt.Fprintf(&b, "# %s: %s\n\n", r.ID, r.Title)
	b.WriteString("| Field | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| Standard | AGSSH-STD-001 %s |\n", StandardVersion)
	if hasText {
		fmt.Fprintf(&b, "| Family | %s (%s %s) |\n", r.Family, fam.Section, mdTableCell(fam.Title))
	} else {
		fmt.Fprintf(&b, "| Family | %s |\n", r.Family)
	}
	fmt.Fprintf(&b, "| Obligation | %s |\n", r.Obligation)
	fmt.Fprintf(&b, "| Severity | %s (weight %d) |\n", r.Severity, r.Severity.Weight())
	fmt.Fprintf(&b, "| Profile | %s (lowest cumulative profile that includes the rule) |\n", r.Profile)
	fmt.Fprintf(&b, "| Levels | L0 %s, L1 %s, L2 %s |\n", m[0], m[1], m[2])
	fmt.Fprintf(&b, "| Verification plane | %s |\n", r.Plane)
	if hasText {
		fmt.Fprintf(&b, "| Applies (standard) | %s |\n", mdTableCell(sr.Applies))
		fmt.Fprintf(&b, "| Check type (standard) | %s |\n", mdTableCell(sr.CheckType))
		if sr.Title != r.Title {
			fmt.Fprintf(&b, "| Title in the standard | %s |\n", mdTableCell(sr.Title))
		}
	}

	if !hasText {
		b.WriteString("\n## Normative text\n\nThe repository holds no rationale, check or remediation text " +
			"for this rule. Do not infer a remediation from this resource.\n")
		return b.String()
	}
	b.WriteString("\nThe sections below are the standard's own text for this rule.\n")
	fmt.Fprintf(&b, "\n## Rationale (why)\n\n%s\n", sr.Why)
	fmt.Fprintf(&b, "\n## Check (the predicate that must hold)\n\n```text\n%s\n```\n", sr.Check)
	fmt.Fprintf(&b, "\n## Remediation (how to satisfy)\n\n%s\n", sr.Fix)
	if strings.TrimSpace(sr.Tool) != "" {
		fmt.Fprintf(&b, "\n## Tooling\n\n%s\n", sr.Tool)
	}
	return b.String()
}

// ruleLevelModes returns the rule's mode at L0, L1, L2.
func ruleLevelModes(id string) [3]string {
	var out [3]string
	for i, l := range []manifest.Level{manifest.L0, manifest.L1, manifest.L2} {
		out[i] = ModeAt(id, l).String()
	}
	return out
}

// mdTableCell makes a value safe inside a Markdown table cell.
func mdTableCell(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.ReplaceAll(s, "|", "\\|")
}
