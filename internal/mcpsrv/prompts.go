package mcpsrv

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fabriziosalmi/agssh/internal/manifest"
	"github.com/fabriziosalmi/agssh/internal/rules"
)

const promptScanAndFix = "agssh_scan_and_fix"

func registerPrompts(s *mcp.Server) {
	s.AddPrompt(&mcp.Prompt{
		Name:  promptScanAndFix,
		Title: "Scan a surface and propose fixes",
		Description: "Run agssh_scan on a live URL, check the environment first, treat INCONCLUSIVE " +
			"as blocking, then walk the fix queue by severity using each rule's agssh://rules/{id} text.",
		Arguments: []*mcp.PromptArgument{
			{Name: "url", Description: "live surface URL to evaluate", Required: true},
			{Name: "profile", Description: "target profile: Bronze (default), Silver, Gold"},
			{Name: "level", Description: "strictness level: L0 (default), L1, L2"},
		},
	}, getScanAndFix)
}

func getScanAndFix(_ context.Context, req *mcp.GetPromptRequest) (res *mcp.GetPromptResult, err error) {
	defer recoverToError(&err)
	args := req.Params.Arguments
	url := strings.TrimSpace(args["url"])
	if url == "" {
		return nil, fmt.Errorf("argument url is required")
	}
	p, err := manifest.ParseProfile(orDefault(args["profile"], "Bronze"))
	if err != nil {
		return nil, err
	}
	l, err := manifest.ParseLevel(orDefault(args["level"], "L0"))
	if err != nil {
		return nil, err
	}

	text := fmt.Sprintf(`Assess %[1]s against AGSSH-STD-001 %[2]s at profile %[3]s, level %[4]s, then propose fixes.

1. Call the agssh_scan tool with url=%[1]q, profile=%[3]q, level=%[4]q.
2. Check environment.degraded first. If it is true, report environment.reason and environment.missing_tools before anything else: the scan is partial and its score is not reliable (dynamic-plane rules need a headless Chrome/Chromium, set AGSSH_CHROME).
3. Report the verdict and the score. Treat every INCONCLUSIVE rule (the unassessed list) as blocking: the gate counts it as FAIL. For each one, state what is missing to assess it, from its reason. Never describe an INCONCLUSIVE rule as passing.
4. Walk fix_queue in order (highest severity first). For each item, read the resource agssh://rules/<rule id> and use its check and remediation text, together with the item's observed and expected values, to propose a concrete change (a response header, a CSP directive, a config or code edit). Do not add requirements that the rule text does not state.
5. A MUST failure cannot be waived (AG-GOV-01); only a SHOULD may carry a governed waiver.
6. Finish with the ordered list of changes, and list the rules that stay INCONCLUSIVE and what would resolve them. Repository, supply-chain and CI rules need agssh_scan_config with a .airgap.yml.`,
		url, rules.StandardVersion, p, l)

	return &mcp.GetPromptResult{
		Description: fmt.Sprintf("AGSSH-STD-001 scan and fix plan for %s (%s/%s)", url, p, l),
		Messages: []*mcp.PromptMessage{{
			Role:    "user",
			Content: &mcp.TextContent{Text: text},
		}},
	}, nil
}
