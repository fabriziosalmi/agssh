package rules

import (
	"context"
	"strings"

	"github.com/fabriziosalmi/agssh/internal/csp"
)

// AG-OUT-03: "nothing is uploaded" is enforced at the capability level — the
// browser must be unable to ship user content off-origin. We verify the policy
// denies that capability: connect-src locked AND form-action 'none'/'self'.
func chkInBrowserOnly(_ context.Context, c *CheckCtx) Outcome {
	if c.Doc == nil {
		return inconclusive("surface not fetched")
	}
	pol, _ := docPolicy(c.Doc)
	if !pol.Present {
		return bad("no CSP", "connect-src locked + form-action 'none'/'self'")
	}
	allowed := []string{}
	if c.Level >= 1 {
		allowed = c.Allow.Connect
	}
	connOK, connBad := pol.ConnectLockedTo(allowed)
	fa, hasFA := pol.Directives["form-action"]
	faOK := hasFA && csp.SelfOnly(fa)
	switch {
	case !connOK && !faOK:
		return bad("connect-src admits "+strings.Join(connBad, ",")+"; form-action unrestricted",
			"connect-src locked + form-action 'none'/'self'")
	case !connOK:
		return bad("connect-src admits "+strings.Join(connBad, ","), "connect-src locked")
	case !faOK:
		return bad("form-action missing or admits third-party", "form-action 'none'/'self' (no default-src fallback)")
	}
	return okay("upload capability denied by policy (connect-src + form-action locked)", "")
}
