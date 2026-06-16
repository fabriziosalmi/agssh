package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// AG-CI-05: the default branch is protected (PR review + required status checks).
// This is the one rule that genuinely needs the GitHub API — without a token (and
// a resolvable owner/repo) it stays INCONCLUSIVE, never a silent PASS.
func chkBranchProtection(ctx context.Context, c *CheckCtx) Outcome {
	slug := githubSlug(c.RepoDir)
	if slug == "" {
		return inconclusive("cannot determine GitHub owner/repo (set GITHUB_REPOSITORY or a github.com remote)")
	}
	token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	if token == "" {
		return inconclusive("no GITHUB_TOKEN; AG-CI-05 verifies branch protection via the GitHub API")
	}
	branch, err := ghDefaultBranch(ctx, slug, token)
	if err != nil {
		return inconclusive("GitHub API (repo lookup): " + err.Error())
	}
	body, status, err := ghGetJSON(ctx, "repos/"+slug+"/branches/"+branch+"/protection", token)
	if err != nil {
		return inconclusive("GitHub API (protection): " + err.Error())
	}
	return evalBranchProtection(branch, status, body)
}

// evalBranchProtection is the pure verdict over a branch-protection API response.
// 404 => not protected (FAIL). 200 => must require BOTH PR reviews and status
// checks. Anything else => INCONCLUSIVE (we could not read the server state).
func evalBranchProtection(branch string, status int, body []byte) Outcome {
	switch status {
	case http.StatusNotFound:
		return bad("branch "+branch+" is not protected", "branch protection: required PR reviews + required status checks")
	case http.StatusOK:
		// ok, parse below
	default:
		return inconclusive(fmt.Sprintf("branch-protection lookup for %s returned HTTP %d", branch, status))
	}
	var p struct {
		RequiredPullRequestReviews *struct {
			RequiredApprovingReviewCount int `json:"required_approving_review_count"`
		} `json:"required_pull_request_reviews"`
		RequiredStatusChecks *struct {
			Strict   bool     `json:"strict"`
			Contexts []string `json:"contexts"`
			// Modern GitHub returns required checks here; `contexts` can be empty
			// while `checks` is populated, so we must read both or false-FAIL.
			Checks []struct {
				Context string `json:"context"`
			} `json:"checks"`
		} `json:"required_status_checks"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return inconclusive("branch-protection response not parseable: " + err.Error())
	}
	var missing []string
	if p.RequiredPullRequestReviews == nil || p.RequiredPullRequestReviews.RequiredApprovingReviewCount < 1 {
		missing = append(missing, "required PR reviews (>=1 approval)")
	}
	nChecks := 0
	if p.RequiredStatusChecks != nil {
		nChecks = len(p.RequiredStatusChecks.Contexts)
		if c := len(p.RequiredStatusChecks.Checks); c > nChecks {
			nChecks = c
		}
	}
	if nChecks == 0 {
		missing = append(missing, "required status checks")
	}
	if len(missing) > 0 {
		return bad("branch "+branch+" protected but missing: "+strings.Join(missing, ", "),
			"required PR reviews (>=1) + at least one required status check")
	}
	return okay(fmt.Sprintf("branch %s protected: PR reviews + %d required check(s)", branch, nChecks), "")
}

// githubSlug resolves owner/repo from GITHUB_REPOSITORY (set in Actions) or the
// origin URL in .git/config.
func githubSlug(repoDir string) string {
	if s := strings.TrimSpace(os.Getenv("GITHUB_REPOSITORY")); s != "" {
		return s
	}
	b, err := os.ReadFile(filepath.Join(repoDir, ".git", "config"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if m := ghRemoteRe.FindStringSubmatch(strings.TrimSpace(line)); len(m) == 2 {
			return m[1]
		}
	}
	return ""
}

var ghRemoteRe = regexp.MustCompile(`github\.com[:/]([^/\s]+/[^/\s]+?)(?:\.git)?/?$`)

var ghHTTP = &http.Client{Timeout: 10 * time.Second}

func ghGetJSON(ctx context.Context, path, token string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/"+path, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := ghHTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return b, resp.StatusCode, nil
}

func ghDefaultBranch(ctx context.Context, slug, token string) (string, error) {
	b, status, err := ghGetJSON(ctx, "repos/"+slug, token)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("repo lookup returned HTTP %d", status)
	}
	var r struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := json.Unmarshal(b, &r); err != nil || r.DefaultBranch == "" {
		return "", fmt.Errorf("no default_branch in repo response")
	}
	return r.DefaultBranch, nil
}
