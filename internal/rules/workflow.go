package rules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ---------- CI / pipeline (parsed, not grepped) ----------
//
// These checks parse the workflow YAML into a typed model. The earlier versions
// used strings.Contains, which mis-fired in both directions: a job-level
// `permissions:` satisfied a top-level rule, a commented directive counted, and
// `pull_request_target` matched even when no untrusted ref was checked out.

type ghWorkflow struct {
	On          yaml.Node        `yaml:"on"`
	Permissions yaml.Node        `yaml:"permissions"`
	Jobs        map[string]ghJob `yaml:"jobs"`
}

type ghJob struct {
	Uses        string    `yaml:"uses"` // reusable-workflow call
	Permissions yaml.Node `yaml:"permissions"`
	Steps       []ghStep  `yaml:"steps"`
}

type ghStep struct {
	Uses string         `yaml:"uses"`
	With map[string]any `yaml:"with"`
}

func workflowFiles(dir string) []string {
	var fs []string
	for _, ext := range []string{"*.yml", "*.yaml"} {
		m, _ := filepath.Glob(filepath.Join(dir, ext))
		fs = append(fs, m...)
	}
	return fs
}

// parseWorkflows reads and YAML-decodes every workflow file in dir. Files that
// fail to parse are returned in bad so the caller can fail-closed on them.
func parseWorkflows(dir string) (parsed map[string]ghWorkflow, bad []string) {
	parsed = map[string]ghWorkflow{}
	for _, f := range workflowFiles(dir) {
		b, err := os.ReadFile(f)
		if err != nil {
			bad = append(bad, filepath.Base(f))
			continue
		}
		var wf ghWorkflow
		if err := yaml.Unmarshal(b, &wf); err != nil {
			bad = append(bad, filepath.Base(f))
			continue
		}
		parsed[filepath.Base(f)] = wf
	}
	return parsed, bad
}

// present reports whether a yaml.Node was actually set in the document (an
// absent key decodes to the zero Node, Kind == 0).
func present(n yaml.Node) bool { return n.Kind != 0 }

// permScalar returns the scalar value of a permissions node ("write-all",
// "read-all", "read", …) or "" when permissions is a mapping / absent.
func permScalar(n yaml.Node) string {
	if n.Kind == yaml.ScalarNode {
		return strings.ToLower(strings.TrimSpace(n.Value))
	}
	return ""
}

// AG-CI-01: third-party Actions are pinned to a full 40-char commit SHA.
func chkPinnedActions(_ context.Context, c *CheckCtx) Outcome {
	parsed, badFiles := parseWorkflows(c.WorkflowsDir)
	if len(parsed) == 0 && len(badFiles) == 0 {
		return inconclusive("no workflow files at " + c.WorkflowsDir)
	}
	if len(badFiles) > 0 {
		return inconclusive("unparseable workflow(s): " + strings.Join(badFiles, ", "))
	}
	var unpinned []string
	consider := func(ref string) {
		ref = strings.TrimSpace(ref)
		if ref == "" || strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "docker://") {
			return // local / docker-pinned refs are out of scope here
		}
		parts := strings.SplitN(ref, "@", 2)
		if len(parts) != 2 || !isSHA40(parts[1]) {
			unpinned = append(unpinned, ref)
		}
	}
	for _, wf := range parsed {
		for _, job := range wf.Jobs {
			consider(job.Uses) // reusable-workflow call
			for _, st := range job.Steps {
				consider(st.Uses)
			}
		}
	}
	if len(unpinned) > 0 {
		return bad("unpinned Actions: "+strings.Join(uniq(unpinned), ", "), "uses: owner/action@<40-char-sha>")
	}
	return okay("all third-party Actions SHA-pinned", "")
}

// AG-CI-02: every job runs with explicit, scoped permissions. Satisfied when a
// top-level `permissions` is declared, OR every job declares its own — a single
// job-level block no longer covers the rest. `write-all` is always over-broad.
func chkLeastPriv(_ context.Context, c *CheckCtx) Outcome {
	parsed, badFiles := parseWorkflows(c.WorkflowsDir)
	if len(parsed) == 0 && len(badFiles) == 0 {
		return inconclusive("no workflow files at " + c.WorkflowsDir)
	}
	if len(badFiles) > 0 {
		return inconclusive("unparseable workflow(s): " + strings.Join(badFiles, ", "))
	}
	for name, wf := range parsed {
		if permScalar(wf.Permissions) == "write-all" {
			return bad("top-level permissions: write-all in "+name, "scope write to the job that needs it")
		}
		topPresent := present(wf.Permissions)
		// A top-level block does NOT excuse a job that escalates to write-all: job
		// permissions override the top-level for that job, so always inspect them.
		for jn, job := range wf.Jobs {
			if permScalar(job.Permissions) == "write-all" {
				return bad("job "+jn+" in "+name+" uses permissions: write-all", "scope write to what the job needs")
			}
			if !topPresent && !present(job.Permissions) {
				return bad("job "+jn+" in "+name+" has no permissions and no top-level default",
					"declare top-level permissions, or scope each job")
			}
		}
	}
	return okay("every job runs with explicit, scoped permissions", "")
}

// AG-CI-03: untrusted code is not built in a privileged context — i.e. a
// pull_request_target / workflow_run workflow must not check out the PR head.
func chkNoUntrustedPriv(_ context.Context, c *CheckCtx) Outcome {
	parsed, badFiles := parseWorkflows(c.WorkflowsDir)
	if len(parsed) == 0 && len(badFiles) == 0 {
		return inconclusive("no workflow files at " + c.WorkflowsDir)
	}
	if len(badFiles) > 0 {
		return inconclusive("unparseable workflow(s): " + strings.Join(badFiles, ", "))
	}
	for name, wf := range parsed {
		events := workflowEvents(wf.On)
		if !events["pull_request_target"] && !events["workflow_run"] {
			continue // not a privileged-trigger workflow
		}
		for jn, job := range wf.Jobs {
			for _, st := range job.Steps {
				if !isCheckoutAction(st.Uses) {
					continue
				}
				ref, repo := withString(st.With, "ref"), withString(st.With, "repository")
				if refIsUntrusted(ref) || refIsUntrusted(repo) {
					val := ref
					if val == "" {
						val = repo
					}
					return bad("privileged "+name+" job "+jn+" checks out untrusted code (\""+val+"\")",
						"never build untrusted PR code with elevated tokens")
				}
			}
		}
	}
	return okay("no untrusted-code-in-privileged-context pattern", "")
}

// workflowEvents collects the trigger event names from an `on:` node, which may
// be a scalar ("push"), a sequence, or a mapping (event -> filters).
func workflowEvents(on yaml.Node) map[string]bool {
	out := map[string]bool{}
	switch on.Kind {
	case yaml.ScalarNode:
		out[on.Value] = true
	case yaml.SequenceNode:
		for _, n := range on.Content {
			out[n.Value] = true
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(on.Content)+1 && i < len(on.Content); i += 2 {
			out[on.Content[i].Value] = true
		}
	}
	return out
}

// isCheckoutAction matches actions/checkout exactly (or a subdir action under
// it), not a typosquat like actions/checkout-evil.
func isCheckoutAction(uses string) bool {
	at := strings.SplitN(strings.TrimSpace(uses), "@", 2)[0]
	return at == "actions/checkout" || strings.HasPrefix(at, "actions/checkout/")
}

// withString reads a `with:` value as a string, coercing non-string scalars
// (a YAML ref decoded as a number/bool still becomes text we can scan).
func withString(with map[string]any, key string) string {
	if v, ok := with[key]; ok && v != nil {
		return fmt.Sprint(v)
	}
	return ""
}

func refIsUntrusted(ref string) bool {
	r := strings.ToLower(ref)
	for _, marker := range []string{
		"pull_request.head", "head.sha", "head.ref", "head_ref", // covers github.head_ref
		"workflow_run.head", "refs/pull/", "event.number",
	} {
		if strings.Contains(r, marker) {
			return true
		}
	}
	return false
}

func isSHA40(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, r := range s { // commit SHAs are valid in upper or lower hex
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
