package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func workflowsDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func TestChkPinnedActions(t *testing.T) {
	pinned := "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@1234567890abcdef1234567890abcdef12345678\n"
	unpinned := "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n"

	if out := chkPinnedActions(t.Context(), &CheckCtx{WorkflowsDir: workflowsDir(t, map[string]string{"ci.yml": pinned})}); out.Status != Pass {
		t.Errorf("pinned SHA: got %s, want PASS", out.Status)
	}
	if out := chkPinnedActions(t.Context(), &CheckCtx{WorkflowsDir: workflowsDir(t, map[string]string{"ci.yml": unpinned})}); out.Status != Fail {
		t.Errorf("tag ref: got %s, want FAIL", out.Status)
	}
}

func TestChkLeastPriv(t *testing.T) {
	topLevel := "permissions:\n  contents: read\njobs:\n  a:\n    steps: [{run: echo}]\n"
	// The old substring check passed this: job `a` has permissions, but job `b`
	// runs with the default token. A real AST must FAIL it.
	jobLevelOnly := "jobs:\n  a:\n    permissions:\n      contents: read\n    steps: [{run: echo}]\n  b:\n    steps: [{run: echo}]\n"
	commentedOnly := "# permissions:\n#   contents: read\njobs:\n  a:\n    steps: [{run: echo}]\n"
	writeAll := "permissions: write-all\njobs:\n  a:\n    steps: [{run: echo}]\n"

	cases := []struct {
		name string
		yaml string
		want Status
	}{
		{"top-level scoped", topLevel, Pass},
		{"job-level only, uncovered job", jobLevelOnly, Fail},
		{"commented permissions don't count", commentedOnly, Fail},
		{"write-all is over-broad", writeAll, Fail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := chkLeastPriv(t.Context(), &CheckCtx{WorkflowsDir: workflowsDir(t, map[string]string{"ci.yml": tc.yaml})})
			if out.Status != tc.want {
				t.Errorf("got %s, want %s", out.Status, tc.want)
			}
		})
	}
}

func TestChkNoUntrustedPriv(t *testing.T) {
	dangerous := "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
	safePRT := "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n"
	pushHead := "on: push\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"

	cases := []struct {
		name string
		yaml string
		want Status
	}{
		{"pull_request_target checks out head", dangerous, Fail},
		{"pull_request_target, no untrusted checkout", safePRT, Pass},
		{"untrusted ref but unprivileged trigger", pushHead, Pass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := chkNoUntrustedPriv(t.Context(), &CheckCtx{WorkflowsDir: workflowsDir(t, map[string]string{"wf.yml": tc.yaml})})
			if out.Status != tc.want {
				t.Errorf("got %s, want %s", out.Status, tc.want)
			}
		})
	}
}
