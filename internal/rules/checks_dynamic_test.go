package rules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fabriziosalmi/agssh/internal/manifest"
)

func TestOfflineProofVerdict(t *testing.T) {
	if offlineProofVerdict("me.test", []string{"me.test", ""}).Status != Pass {
		t.Error("only first-party responses: want PASS")
	}
	if offlineProofVerdict("me.test", []string{"me.test", "evil.test"}).Status != Fail {
		t.Error("a third-party response: want FAIL")
	}
}

func TestPreConsentVerdict(t *testing.T) {
	if preConsentVerdict([]string{"me.test"}).Status != Pass {
		t.Error("no trackers: want PASS")
	}
	if preConsentVerdict([]string{"www.google-analytics.com"}).Status != Fail {
		t.Error("tracker subdomain pre-consent: want FAIL")
	}
}

func TestEgressCanaryVerdict(t *testing.T) {
	if egressCanaryVerdict(true, true).Status != Fail {
		t.Error("canary got a response (wall down): want FAIL")
	}
	if egressCanaryVerdict(true, false).Status != Pass {
		t.Error("canary blocked: want PASS")
	}
	if egressCanaryVerdict(false, false).Status != Pass {
		t.Error("canary never left: want PASS")
	}
}

func TestServiceWorkerVerdict(t *testing.T) {
	self := "me.test"
	if serviceWorkerVerdict(self, nil).Status != Inconclusive {
		t.Error("no SW observed: want INCONCLUSIVE (declared but absent)")
	}
	ok := []swReg{{Scope: "https://me.test/", Script: "https://me.test/sw.js"}}
	if serviceWorkerVerdict(self, ok).Status != Pass {
		t.Error("same-origin SW: want PASS")
	}
	crossScript := []swReg{{Scope: "https://me.test/", Script: "https://cdn.evil/sw.js"}}
	if serviceWorkerVerdict(self, crossScript).Status != Fail {
		t.Error("cross-origin SW script: want FAIL")
	}
	crossScope := []swReg{{Scope: "https://other.test/", Script: "https://me.test/sw.js"}}
	if serviceWorkerVerdict(self, crossScope).Status != Fail {
		t.Error("cross-origin SW scope: want FAIL")
	}
}

func TestStorageVerdict(t *testing.T) {
	allow := []string{"theme"}
	if storageVerdict(allow, storageObs{Local: []string{"theme"}}).Status != Pass {
		t.Error("allow-listed key only: want PASS")
	}
	out := storageVerdict(allow, storageObs{Local: []string{"theme"}, Cookies: []string{"session_token"}})
	if out.Status != Fail || !strings.Contains(out.Evidence.Observed, "session_token") {
		t.Errorf("undeclared key: want FAIL naming session_token, got %s / %q", out.Status, out.Evidence.Observed)
	}
	if storageVerdict(nil, storageObs{}).Status != Pass {
		t.Error("no storage at all: want PASS")
	}
}

// TestClientStorageIntegration drives a real headless browser when one is
// resolvable (Docker image / local install); it SKIPS in a bare CI runner. The
// pure-verdict tests above carry the hermetic guarantee regardless.
func TestClientStorageIntegration(t *testing.T) {
	chrome := DiscoverTools().Chrome
	if chrome == "" {
		t.Skip("no Chrome/Chromium resolvable; skipping browser integration")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body><script>localStorage.setItem('x','1')</script></body></html>`))
	}))
	defer srv.Close()

	undeclared := chkClientStorage(context.Background(), &CheckCtx{
		Surface: manifest.Surface{URL: srv.URL}, Tools: Toolbox{Chrome: chrome},
	})
	if undeclared.Status != Fail {
		t.Errorf("undeclared localStorage key: got %s (%s), want FAIL", undeclared.Status, undeclared.Err)
	}
	allowed := chkClientStorage(context.Background(), &CheckCtx{
		Surface: manifest.Surface{URL: srv.URL},
		Allow:   manifest.Allow{Storage: []string{"x"}},
		Tools:   Toolbox{Chrome: chrome},
	})
	if allowed.Status != Pass {
		t.Errorf("allow-listed localStorage key: got %s (%s), want PASS", allowed.Status, allowed.Err)
	}
}
