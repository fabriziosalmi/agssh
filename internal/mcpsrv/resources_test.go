package mcpsrv_test

import (
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fabriziosalmi/agssh/internal/rules"
)

func TestListResourcesAndTemplates(t *testing.T) {
	cs, ctx := connect(t)

	lr, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	want := map[string]bool{"agssh://standard": false, "agssh://rules": false}
	for _, r := range lr.Resources {
		if _, ok := want[r.URI]; ok {
			want[r.URI] = true
		}
		if r.MIMEType != "text/markdown" {
			t.Errorf("resource %s: mimeType %q", r.URI, r.MIMEType)
		}
	}
	for uri, seen := range want {
		if !seen {
			t.Errorf("resource %s not advertised", uri)
		}
	}

	lt, err := cs.ListResourceTemplates(ctx, nil)
	if err != nil {
		t.Fatalf("ListResourceTemplates: %v", err)
	}
	found := false
	for _, rt := range lt.ResourceTemplates {
		if rt.URITemplate == "agssh://rules/{id}" {
			found = true
		}
	}
	if !found {
		t.Errorf("template agssh://rules/{id} not advertised; got %+v", lt.ResourceTemplates)
	}
}

func readText(t *testing.T, cs *mcp.ClientSession, uri string) string {
	t.Helper()
	res, err := cs.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: uri})
	if err != nil {
		t.Fatalf("ReadResource %s: %v", uri, err)
	}
	if len(res.Contents) != 1 {
		t.Fatalf("ReadResource %s: %d contents, want 1", uri, len(res.Contents))
	}
	c := res.Contents[0]
	if c.URI != uri || c.MIMEType != "text/markdown" {
		t.Errorf("ReadResource %s: uri=%q mime=%q", uri, c.URI, c.MIMEType)
	}
	return c.Text
}

func TestReadRuleResourceCarriesStandardText(t *testing.T) {
	cs, _ := connect(t)
	txt := readText(t, cs, "agssh://rules/AG-NET-05")

	// Metadata comes from the registry and the generated level table.
	for _, want := range []string{
		"# AG-NET-05: No third-party egress during load",
		"| Obligation | MUST |",
		"| Severity | HIGH (weight 4) |",
		"| Profile | Silver",
		"| Levels | L0 required, L1 advisory, L2 out_of_scope |",
		"| Verification plane | dynamic |",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("rule resource lacks %q:\n%s", want, txt)
		}
	}
	// The normative text is the standard's own words, verbatim.
	sr, _, ok := rules.SpecFor("AG-NET-05")
	if !ok {
		t.Fatal("no spec text for AG-NET-05")
	}
	for name, v := range map[string]string{"why": sr.Why, "check": sr.Check, "fix": sr.Fix} {
		if !strings.Contains(txt, v) {
			t.Errorf("rule resource does not carry the standard's %s text verbatim", name)
		}
	}
	if strings.Contains(txt, "holds no rationale") {
		t.Errorf("AG-NET-05 has text in the standard but the resource says it has none")
	}
}

func TestReadRuleResourceIsCaseInsensitive(t *testing.T) {
	cs, _ := connect(t)
	if txt := readText(t, cs, "agssh://rules/ag-hdr-01A"); !strings.HasPrefix(txt, "# AG-HDR-01a:") {
		t.Errorf("lower-case id did not resolve to AG-HDR-01a: %q", firstLine(txt))
	}
}

func TestReadUnknownRuleIsAnError(t *testing.T) {
	cs, ctx := connect(t)
	for _, uri := range []string{"agssh://rules/AG-NOPE-99", "agssh://rules/", "agssh://nothing"} {
		res, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: uri})
		if err == nil {
			t.Errorf("ReadResource %s: want an error, got success %+v", uri, res)
			continue
		}
		if !strings.Contains(strings.ToLower(err.Error()), "not found") {
			t.Errorf("ReadResource %s: want a resource-not-found error, got %v", uri, err)
		}
	}
}

func TestEveryRegistryRuleIsReadable(t *testing.T) {
	cs, _ := connect(t)
	for _, r := range rules.All() {
		txt := readText(t, cs, "agssh://rules/"+r.ID)
		if !strings.HasPrefix(txt, "# "+r.ID+": ") {
			t.Errorf("%s: unexpected heading %q", r.ID, firstLine(txt))
		}
		if !strings.Contains(txt, "## Remediation (how to satisfy)") {
			t.Errorf("%s: resource carries no remediation text", r.ID)
		}
	}
}

func TestReadCatalogueListsEveryRule(t *testing.T) {
	cs, _ := connect(t)
	txt := readText(t, cs, "agssh://rules")
	for _, r := range rules.All() {
		if !strings.Contains(txt, "| `"+r.ID+"` |") {
			t.Errorf("catalogue omits %s", r.ID)
		}
	}
	if !strings.Contains(txt, "| `AG-PRV-06` | Third-party embeds sandboxed | MUST | MEDIUM | Silver | forbidden | forbidden | required | static |") {
		t.Errorf("catalogue row for AG-PRV-06 does not carry its per-level modes")
	}
}

func TestReadStandardOverview(t *testing.T) {
	cs, _ := connect(t)
	txt := readText(t, cs, "agssh://standard")
	for _, want := range []string{
		rules.StandardVersion,
		"| **Bronze** (Baseline)", "| **Silver** (Hardened)", "| **Gold** (Sovereign)",
		"| **L0** (Air-Gapped Strict)", "| **L1** (Scoped Egress)", "| **L2** (Public Static)",
		"- `INCONCLUSIVE`: blocks the gate: true",
		"- `N/A`: blocks the gate: false",
		"| CRITICAL | 8 |",
		"| 3 | a surface was unscannable",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
}

func TestGetScanAndFixPrompt(t *testing.T) {
	cs, ctx := connect(t)

	lp, err := cs.ListPrompts(ctx, nil)
	if err != nil {
		t.Fatalf("ListPrompts: %v", err)
	}
	if len(lp.Prompts) != 1 || lp.Prompts[0].Name != "agssh_scan_and_fix" {
		t.Fatalf("prompts: %+v", lp.Prompts)
	}

	gp, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{
		Name:      "agssh_scan_and_fix",
		Arguments: map[string]string{"url": "https://example.org/", "profile": "silver", "level": "L1"},
	})
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}
	if len(gp.Messages) != 1 || gp.Messages[0].Role != "user" {
		t.Fatalf("messages: %+v", gp.Messages)
	}
	tc, ok := gp.Messages[0].Content.(*mcp.TextContent)
	if !ok {
		t.Fatalf("content type %T", gp.Messages[0].Content)
	}
	for _, want := range []string{
		`url="https://example.org/", profile="Silver", level="L1"`,
		"environment.degraded",
		"INCONCLUSIVE",
		"fix_queue",
		"agssh://rules/<rule id>",
	} {
		if !strings.Contains(tc.Text, want) {
			t.Errorf("prompt lacks %q:\n%s", want, tc.Text)
		}
	}

	// Defaults, and argument validation.
	gp, err = cs.GetPrompt(ctx, &mcp.GetPromptParams{Name: "agssh_scan_and_fix", Arguments: map[string]string{"url": "https://example.org/"}})
	if err != nil {
		t.Fatalf("GetPrompt defaults: %v", err)
	}
	if !strings.Contains(gp.Messages[0].Content.(*mcp.TextContent).Text, `profile="Bronze", level="L0"`) {
		t.Errorf("prompt defaults are not Bronze/L0")
	}
	for _, args := range []map[string]string{{}, {"url": "https://example.org/", "profile": "Platinum"}, {"url": "https://example.org/", "level": "L9"}} {
		if _, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{Name: "agssh_scan_and_fix", Arguments: args}); err == nil {
			t.Errorf("GetPrompt %v: want an error", args)
		}
	}
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
