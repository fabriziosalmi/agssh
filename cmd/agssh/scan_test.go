package main

import (
	"testing"
)

func TestRunScanUsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no url":         {},
		"bad profile":    {"-profile", "Platinum", "example.org"},
		"bad level":      {"-level", "L9", "example.org"},
		"wildcard allow": {"-allow-connect", "*", "example.org"},
		"bad scheme":     {"ftp://example.org"},
		"unknown flag":   {"-nope", "example.org"},
	} {
		if code := runScan(args); code != 2 {
			t.Errorf("%s: exit = %d, want 2", name, code)
		}
	}
}

// An unreachable target must exit 3 (could not look), never 0 or 1. Port 1 on
// loopback refuses instantly, so this stays offline and fast; flags placed AFTER
// the URL must still parse cleanly (flag/URL interleaving is handled in runScan).
func TestRunScanUnreachableIsExit3(t *testing.T) {
	if code := runScan([]string{"http://127.0.0.1:1/", "-timeout", "3s", "-level", "L1"}); code != 3 {
		t.Errorf("exit = %d, want 3", code)
	}
}

func TestMultiFlag(t *testing.T) {
	var m multi
	_ = m.Set("a")
	_ = m.Set("b")
	if len(m) != 2 || m.String() != "a,b" {
		t.Errorf("multi = %v", m)
	}
}
