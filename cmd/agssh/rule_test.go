package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRulePrintsTheStandardText(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runRule([]string{"ag-net-05"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	for _, want := range []string{"# AG-NET-05:", "| Obligation | MUST |", "## Remediation (how to satisfy)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q", want)
		}
	}
}

func TestRuleRejectsUnknownAndBadUsage(t *testing.T) {
	for _, args := range [][]string{{"AG-XXX-99"}, {}, {"AG-NET-05", "AG-NET-01"}, {"-h"}} {
		var out, errb bytes.Buffer
		if code := runRule(args, &out, &errb); code != 2 {
			t.Errorf("runRule(%q) = %d, want 2", args, code)
		}
		if out.Len() != 0 {
			t.Errorf("runRule(%q) wrote to stdout: %q", args, out.String())
		}
	}
}
