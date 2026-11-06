package main

import (
	"fmt"
	"io"

	"github.com/fabriziosalmi/agssh/internal/rules"
)

const ruleUsage = `usage: agssh rule <id>

Print one rule of AGSSH-STD-001 as Markdown: obligation, severity, profile, its
mode at each level, and the standard's own rationale, check, remediation and
tooling text. The id is matched case-insensitively (AG-NET-05, ag-net-05).
No network.

Exit codes: 0 printed · 2 usage error or unknown rule id.
`

// runRule prints the rule's Markdown to stdout. It is the CLI twin of the MCP
// resource agssh://rules/{id}: both render rules.RuleMarkdown.
func runRule(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || args[0] == "-h" || args[0] == "-help" || args[0] == "--help" {
		fmt.Fprint(stderr, ruleUsage)
		return 2
	}
	r, ok := rules.Lookup(args[0])
	if !ok {
		fmt.Fprintf(stderr, "agssh rule: unknown rule id %q\n", args[0])
		return 2
	}
	fmt.Fprint(stdout, rules.RuleMarkdown(r))
	return 0
}
