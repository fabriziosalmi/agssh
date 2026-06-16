package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEvalBranchProtection(t *testing.T) {
	full := `{"required_pull_request_reviews":{"required_approving_review_count":1},"required_status_checks":{"strict":true,"contexts":["test"]}}`
	noReviews := `{"required_status_checks":{"strict":true,"contexts":["test"]}}`
	noChecks := `{"required_pull_request_reviews":{"required_approving_review_count":1}}`
	emptyChecks := `{"required_pull_request_reviews":{"required_approving_review_count":1},"required_status_checks":{"strict":true,"contexts":[]}}`

	cases := []struct {
		name   string
		status int
		body   string
		want   Status
	}{
		{"not protected (404)", 404, "", Fail},
		{"fully protected", 200, full, Pass},
		{"missing PR reviews", 200, noReviews, Fail},
		{"missing status checks", 200, noChecks, Fail},
		{"empty status-check contexts", 200, emptyChecks, Fail},
		{"server error", 500, "", Inconclusive},
		{"unparseable 200", 200, "{not json", Inconclusive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if out := evalBranchProtection("main", tc.status, []byte(tc.body)); out.Status != tc.want {
				t.Errorf("got %s, want %s", out.Status, tc.want)
			}
		})
	}
}

func TestGithubSlug(t *testing.T) {
	// Environment override wins.
	t.Setenv("GITHUB_REPOSITORY", "owner/repo")
	if got := githubSlug(""); got != "owner/repo" {
		t.Errorf("env slug = %q, want owner/repo", got)
	}

	// Parse from .git/config for both https and ssh remotes.
	t.Setenv("GITHUB_REPOSITORY", "")
	for _, url := range []string{
		"https://github.com/fabriziosalmi/agssh.git",
		"git@github.com:fabriziosalmi/agssh.git",
		"https://github.com/fabriziosalmi/agssh",
	} {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
			t.Fatal(err)
		}
		cfg := "[remote \"origin\"]\n\turl = " + url + "\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
		if err := os.WriteFile(filepath.Join(dir, ".git", "config"), []byte(cfg), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := githubSlug(dir); got != "fabriziosalmi/agssh" {
			t.Errorf("slug from %q = %q, want fabriziosalmi/agssh", url, got)
		}
	}

	// No remote, no env -> empty (caller maps to INCONCLUSIVE).
	if got := githubSlug(t.TempDir()); got != "" {
		t.Errorf("no remote: got %q, want empty", got)
	}
}
