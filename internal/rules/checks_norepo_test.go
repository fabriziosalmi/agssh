package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// fakeExec writes a tiny executable that runs `body` under /bin/sh and returns
// its path, letting a test stand in for gitleaks/osv-scanner with a chosen exit
// code and output.
func fakeExec(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// fakeGitleaks stands in for the gitleaks binary: it finds the --report-path
// argument, optionally writes reportJSON there, then exits with `exit`. This
// mirrors real gitleaks, whose verdict must be read from the report — not the
// exit code, which is 1 for BOTH "leaks found" and a fatal scan error.
func fakeGitleaks(t *testing.T, reportJSON string, writeReport bool, exit int) string {
	body := `rp=""
while [ $# -gt 0 ]; do
  if [ "$1" = "--report-path" ]; then rp="$2"; fi
  shift
done
`
	if writeReport {
		body += "printf '%s' '" + reportJSON + "' > \"$rp\"\n"
	}
	body += "exit " + fmt.Sprint(exit)
	return fakeExec(t, body)
}

// TestChkNoSecretsMissingDir pins the regression: with no dist/repo to scan
// (e.g. a URL-only MCP scan), AG-SUP-04 must be INCONCLUSIVE — never FAIL, and
// never quietly scan the process working directory.
func TestChkNoSecretsMissingDir(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "does-not-exist")
	out := chkNoSecrets(t.Context(), &CheckCtx{
		Tools:   Toolbox{Gitleaks: "/nonexistent/gitleaks"},
		DistDir: absent, RepoDir: absent,
	})
	if out.Status != Inconclusive {
		t.Errorf("missing dir: got %s, want INCONCLUSIVE", out.Status)
	}
}

// TestChkNoSecretsReportSemantics: the verdict comes from the JSON report, not
// the exit code. Findings -> FAIL; empty/clean -> PASS; a non-zero exit with no
// parseable report (gitleaks' fatal path, which also exits 1) -> INCONCLUSIVE,
// never a manufactured secret FAIL.
func TestChkNoSecretsReportSemantics(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fakeGitleaks relies on /bin/sh")
	}
	dir := t.TempDir() // a real, existing directory to get past the dir guard
	cases := []struct {
		name       string
		reportJSON string
		writeRep   bool
		exit       int
		want       Status
	}{
		{"leaks found", `[{"RuleID":"generic-api-key"}]`, true, 1, Fail},
		{"empty report, clean", `[]`, true, 0, Pass},
		{"no report, clean exit", "", false, 0, Pass},
		{"fatal error (exit 1, no report)", "", false, 1, Inconclusive},
		{"unparseable report", "not json", true, 1, Inconclusive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := chkNoSecrets(t.Context(), &CheckCtx{
				Tools:   Toolbox{Gitleaks: fakeGitleaks(t, tc.reportJSON, tc.writeRep, tc.exit)},
				DistDir: dir,
			})
			if out.Status != tc.want {
				t.Errorf("got %s (%s), want %s", out.Status, out.Err, tc.want)
			}
		})
	}
}

// TestChkNoKnownVulnsMissingRepo: with no repository present, AG-SUP-06 must be
// INCONCLUSIVE and must not let osv-scanner fall back to scanning ".".
func TestChkNoKnownVulnsMissingRepo(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "does-not-exist")
	out := chkNoKnownVulns(t.Context(), &CheckCtx{
		Tools: Toolbox{OSVScanner: "/nonexistent/osv-scanner"}, RepoDir: absent,
	})
	if out.Status != Inconclusive {
		t.Errorf("missing repo: got %s, want INCONCLUSIVE", out.Status)
	}
}

func TestDirExists(t *testing.T) {
	if dirExists("") {
		t.Error(`dirExists("") = true, want false`)
	}
	d := t.TempDir()
	if !dirExists(d) {
		t.Errorf("dirExists(%q) = false, want true", d)
	}
	f := filepath.Join(d, "file")
	_ = os.WriteFile(f, []byte("x"), 0o644)
	if dirExists(f) {
		t.Errorf("dirExists(regular file) = true, want false")
	}
}
