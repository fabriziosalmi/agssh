package mcpsrv

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fabriziosalmi/agssh/internal/manifest"
	"github.com/fabriziosalmi/agssh/internal/rules"
)

// Resource URIs. Every resource is read-only, deterministic and rendered from
// data compiled into the binary: the rule registry (internal/rules), the
// generated level table and the embedded standard text (rules/spec.json). No
// resource touches the network or the filesystem.
const (
	uriStandard     = "agssh://standard"
	uriRules        = "agssh://rules"
	uriRulePrefix   = "agssh://rules/"
	uriRuleTemplate = "agssh://rules/{id}"
	mimeMarkdown    = "text/markdown"
)

func registerResources(s *mcp.Server) {
	s.AddResource(&mcp.Resource{
		URI:      uriStandard,
		Name:     "agssh-standard",
		Title:    "AGSSH-STD-001 overview",
		MIMEType: mimeMarkdown,
		Description: "Version, profiles, levels, statuses, severity weights, fail-closed posture " +
			"and CLI exit codes of AGSSH-STD-001, as implemented by this build.",
	}, readStandard)

	s.AddResource(&mcp.Resource{
		URI:      uriRules,
		Name:     "agssh-rules",
		Title:    "AGSSH-STD-001 rule catalogue",
		MIMEType: mimeMarkdown,
		Description: "Every rule the runner enforces: id, title, obligation, severity, profile, " +
			"per-level mode (L0/L1/L2) and verification plane. Read agssh://rules/{id} for a rule's text.",
	}, readCatalogue)

	s.AddResourceTemplate(&mcp.ResourceTemplate{
		URITemplate: uriRuleTemplate,
		Name:        "agssh-rule",
		Title:       "AGSSH-STD-001 rule",
		MIMEType:    mimeMarkdown,
		Description: "One rule by id (e.g. agssh://rules/AG-NET-05): metadata plus the standard's " +
			"own rationale, check predicate, remediation and tooling text. Read this for each " +
			"rule in a scan's fix_queue before proposing a change.",
	}, readRule)
}

func textResult(uri, body string) *mcp.ReadResourceResult {
	return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
		URI: uri, MIMEType: mimeMarkdown, Text: body,
	}}}
}

// ---- agssh://standard -------------------------------------------------------

func readStandard(_ context.Context, req *mcp.ReadResourceRequest) (res *mcp.ReadResourceResult, err error) {
	defer recoverToError(&err)
	spec, err := rules.StandardSpec()
	if err != nil {
		return nil, err
	}
	all := rules.All()

	var b strings.Builder
	fmt.Fprintf(&b, "# %s: %s (%s)\n\n", spec.ID, spec.Title, rules.StandardVersion)
	fmt.Fprintf(&b, "%d rules in %d families. This server implements %s %s; ", len(all), len(spec.Families), spec.ID, rules.StandardVersion)
	b.WriteString("the full rule list is `agssh://rules`, one rule's normative text is `agssh://rules/{id}`.\n\n")

	b.WriteString("## Obligations\n\n")
	b.WriteString("- **MUST**: mandatory and never waivable (AG-GOV-01). A failing MUST makes the surface non-conformant.\n")
	b.WriteString("- **SHOULD**: a failure blocks unless covered by a governed waiver: bounded expiry (AG-GOV-02), " +
		"within the per-surface debt budget (AG-GOV-03), and at Gold signed by an approver other than the author (AG-GOV-04).\n")
	b.WriteString("- A MUST that is *advisory* at the evaluated level is reported, and waivable, as a SHOULD there.\n\n")

	b.WriteString("## Profiles (cumulative: Bronze ⊂ Silver ⊂ Gold)\n\n")
	b.WriteString("| Profile | For | Adds | Rules at this profile |\n|---|---|---|:--:|\n")
	for _, p := range spec.Profiles {
		pr, perr := manifest.ParseProfile(p.Name)
		n := 0
		if perr == nil {
			for _, r := range all {
				if pr.AtLeast(r.Profile) {
					n++
				}
			}
		}
		fmt.Fprintf(&b, "| **%s** (%s) | %s | %s | %d |\n", p.Name, p.Label, mdCell(p.For), mdCell(p.Adds), n)
	}

	b.WriteString("\n## Levels (strictness bands)\n\n")
	b.WriteString("| Level | Meaning | Defining control | Typical surface |\n|---|---|---|---|\n")
	for _, l := range spec.Levels {
		fmt.Fprintf(&b, "| **%s** (%s) | %s | %s | %s |\n", l.Name, l.Label, mdCell(l.Meaning), mdCell(l.Control), mdCell(l.Typical))
	}
	b.WriteString("\nPer rule, a level is `required`, `advisory` (behaves as SHOULD), `out_of_scope` " +
		"(not demanded; kept as credit if passed) or `forbidden` (the rule's subject is banned).\n\n")

	b.WriteString("## Statuses and posture: fail-closed\n\n")
	for _, st := range []rules.Status{rules.Pass, rules.Fail, rules.Inconclusive, rules.NotApplicable} {
		fmt.Fprintf(&b, "- `%s`: blocks the gate: %t\n", st, st.Failing())
	}
	b.WriteString("\nA rule the runner cannot conclusively verify returns `INCONCLUSIVE`, and the gate treats " +
		"it exactly like `FAIL`: a missing scanner, a missing headless browser or a check not implemented " +
		"in this build all block. The gate fails on any failing MUST, any unwaived failing SHOULD, or any " +
		"governance violation. Scan results list FAIL rules in `fix_queue` (highest severity first) and " +
		"INCONCLUSIVE rules separately in `unassessed`, each with the reason. When `environment.degraded` " +
		"is true the scan is partial (for example no headless browser for the dynamic plane) and the score " +
		"must not be trusted.\n\n")

	b.WriteString("## Severity weights\n\n")
	b.WriteString("The weighted score and the fix-queue order use these weights. The score orders remediation; " +
		"it is not the verdict.\n\n| Severity | Weight |\n|---|:--:|\n")
	for _, sv := range []rules.Severity{rules.Critical, rules.High, rules.Medium, rules.Low} {
		fmt.Fprintf(&b, "| %s | %d |\n", sv, sv.Weight())
	}

	b.WriteString("\n## CLI exit codes (`agssh`, `agssh scan`)\n\n")
	b.WriteString("| Code | Meaning |\n|:--:|---|\n")
	b.WriteString("| 0 | conformant |\n| 1 | non-conformant |\n| 2 | usage or internal error |\n" +
		"| 3 | a surface was unscannable (no verdict, score or badge is emitted) |\n")

	b.WriteString("\n## MCP surface of this server\n\n")
	b.WriteString("- Tools: `agssh_scan` (live URL; source-plane rules report INCONCLUSIVE), " +
		"`agssh_scan_config` (an existing `.airgap.yml`, with repo / dist / workflow rules), " +
		"`agssh_list_rules` (registry, no network).\n")
	b.WriteString("- Resources: `agssh://standard` (this page), `agssh://rules`, `agssh://rules/{id}`.\n")
	b.WriteString("- Prompt: `agssh_scan_and_fix` (scan a URL, then propose fixes rule by rule).\n")
	return textResult(req.Params.URI, b.String()), nil
}

// ---- agssh://rules ----------------------------------------------------------

func readCatalogue(_ context.Context, req *mcp.ReadResourceRequest) (res *mcp.ReadResourceResult, err error) {
	defer recoverToError(&err)
	spec, err := rules.StandardSpec()
	if err != nil {
		return nil, err
	}
	all := rules.All()
	byFamily := map[string][]rules.Rule{}
	for _, r := range all {
		byFamily[r.Family] = append(byFamily[r.Family], r)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# %s %s: rule catalogue\n\n", spec.ID, rules.StandardVersion)
	fmt.Fprintf(&b, "%d rules. Columns L0/L1/L2 give the rule's mode at each level. "+
		"Read `agssh://rules/{id}` for the rationale, check and remediation text of one rule.\n", len(all))

	listed := 0
	for _, f := range spec.Families {
		rs := byFamily[f.Prefix]
		if len(rs) == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n## %s %s: %s\n\n", f.Section, f.Prefix, f.Title)
		b.WriteString("| Rule | Title | Obligation | Severity | Profile | L0 | L1 | L2 | Plane |\n")
		b.WriteString("|---|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|\n")
		for _, r := range rs {
			m := levelModes(r.ID)
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s | %s | %s | %s |\n",
				r.ID, mdCell(r.Title), r.Obligation, r.Severity, r.Profile, m[0], m[1], m[2], r.Plane)
			listed++
		}
		delete(byFamily, f.Prefix)
	}
	// A registry family the standard's text does not name still gets listed, so
	// the catalogue can never silently omit an enforced rule.
	for fam, rs := range byFamily {
		fmt.Fprintf(&b, "\n## %s\n\n| Rule | Title | Obligation | Severity | Profile |\n|---|---|:--:|:--:|:--:|\n", fam)
		for _, r := range rs {
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n", r.ID, mdCell(r.Title), r.Obligation, r.Severity, r.Profile)
			listed++
		}
	}
	if listed != len(all) {
		return nil, fmt.Errorf("catalogue listed %d of %d rules", listed, len(all))
	}
	return textResult(req.Params.URI, b.String()), nil
}

// ---- agssh://rules/{id} -----------------------------------------------------

func readRule(_ context.Context, req *mcp.ReadResourceRequest) (res *mcp.ReadResourceResult, err error) {
	defer recoverToError(&err)
	uri := req.Params.URI
	id, ok := strings.CutPrefix(uri, uriRulePrefix)
	if !ok || id == "" || strings.Contains(id, "/") {
		return nil, mcp.ResourceNotFoundError(uri)
	}
	r, ok := rules.Lookup(id)
	if !ok {
		return nil, mcp.ResourceNotFoundError(uri)
	}
	return textResult(uri, renderRule(r)), nil
}

func renderRule(r rules.Rule) string {
	sr, fam, hasText := rules.SpecFor(r.ID)
	m := levelModes(r.ID)

	var b strings.Builder
	fmt.Fprintf(&b, "# %s: %s\n\n", r.ID, r.Title)
	b.WriteString("| Field | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| Standard | AGSSH-STD-001 %s |\n", rules.StandardVersion)
	if hasText {
		fmt.Fprintf(&b, "| Family | %s (%s %s) |\n", r.Family, fam.Section, mdCell(fam.Title))
	} else {
		fmt.Fprintf(&b, "| Family | %s |\n", r.Family)
	}
	fmt.Fprintf(&b, "| Obligation | %s |\n", r.Obligation)
	fmt.Fprintf(&b, "| Severity | %s (weight %d) |\n", r.Severity, r.Severity.Weight())
	fmt.Fprintf(&b, "| Profile | %s (lowest cumulative profile that includes the rule) |\n", r.Profile)
	fmt.Fprintf(&b, "| Levels | L0 %s, L1 %s, L2 %s |\n", m[0], m[1], m[2])
	fmt.Fprintf(&b, "| Verification plane | %s |\n", r.Plane)
	if hasText {
		fmt.Fprintf(&b, "| Applies (standard) | %s |\n", mdCell(sr.Applies))
		fmt.Fprintf(&b, "| Check type (standard) | %s |\n", mdCell(sr.CheckType))
		if sr.Title != r.Title {
			fmt.Fprintf(&b, "| Title in the standard | %s |\n", mdCell(sr.Title))
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

// levelModes returns the rule's mode at L0, L1, L2.
func levelModes(id string) [3]string {
	var out [3]string
	for i, l := range []manifest.Level{manifest.L0, manifest.L1, manifest.L2} {
		out[i] = rules.ModeAt(id, l).String()
	}
	return out
}

// mdCell makes a value safe inside a Markdown table cell.
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.ReplaceAll(s, "|", "\\|")
}
