package rules

import (
	"context"
	"testing"

	"github.com/fabriziosalmi/agssh/internal/manifest"
)

// hardened is a response that should satisfy the header-family checks.
var hardenedHeaders = map[string]string{
	"Content-Security-Policy":   "default-src 'none'; connect-src 'none'; require-trusted-types-for 'script'; upgrade-insecure-requests",
	"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	"X-Content-Type-Options":    "nosniff",
	"X-Frame-Options":           "DENY",
	"Referrer-Policy":           "no-referrer",
	"Permissions-Policy":        "geolocation=()",
}

func TestStaticCheckersInconclusiveWithoutDoc(t *testing.T) {
	for name, fn := range map[string]Checker{
		"csp": chkCSPPresent, "hsts": chkHSTS, "nosniff": chkNosniff, "sri": chkSRI,
	} {
		if out := fn(context.Background(), &CheckCtx{}); out.Status != Inconclusive {
			t.Errorf("%s with no Doc: got %s, want INCONCLUSIVE (fail-closed)", name, out.Status)
		}
	}
}

func TestChkCSPPresent(t *testing.T) {
	if out := chkCSPPresent(context.Background(), &CheckCtx{Doc: newDoc(200, "", map[string]string{"Content-Security-Policy": "default-src 'none'"})}); out.Status != Pass {
		t.Errorf("header CSP: got %s, want PASS", out.Status)
	}
	metaBody := `<meta http-equiv="Content-Security-Policy" content="default-src 'none'">`
	if out := chkCSPPresent(context.Background(), &CheckCtx{Doc: newDoc(200, metaBody, nil)}); out.Status != Pass {
		t.Errorf("meta CSP: got %s, want PASS", out.Status)
	}
	if out := chkCSPPresent(context.Background(), &CheckCtx{Doc: newDoc(200, "<html></html>", nil)}); out.Status != Fail {
		t.Errorf("no CSP: got %s, want FAIL", out.Status)
	}
}

func TestChkHSTS(t *testing.T) {
	cases := []struct {
		hdr  string
		want Status
	}{
		{"max-age=31536000", Pass},
		{"max-age=100", Fail},
		{"max-age=0", Fail},
		{"", Fail},
	}
	for _, tc := range cases {
		h := map[string]string{}
		if tc.hdr != "" {
			h["Strict-Transport-Security"] = tc.hdr
		}
		if out := chkHSTS(context.Background(), &CheckCtx{Doc: newDoc(200, "", h)}); out.Status != tc.want {
			t.Errorf("HSTS %q: got %s, want %s", tc.hdr, out.Status, tc.want)
		}
	}
}

func TestChkNosniffAndReferrer(t *testing.T) {
	if out := chkNosniff(context.Background(), &CheckCtx{Doc: newDoc(200, "", map[string]string{"X-Content-Type-Options": "nosniff"})}); out.Status != Pass {
		t.Errorf("nosniff present: want PASS, got %s", out.Status)
	}
	if out := chkNosniff(context.Background(), &CheckCtx{Doc: newDoc(200, "", nil)}); out.Status != Fail {
		t.Errorf("nosniff absent: want FAIL, got %s", out.Status)
	}
	if out := chkReferrer(context.Background(), &CheckCtx{Doc: newDoc(200, "", map[string]string{"Referrer-Policy": "unsafe-url"})}); out.Status != Fail {
		t.Errorf("weak referrer: want FAIL, got %s", out.Status)
	}
	if out := chkReferrer(context.Background(), &CheckCtx{Doc: newDoc(200, "", map[string]string{"Referrer-Policy": "no-referrer"})}); out.Status != Pass {
		t.Errorf("strong referrer: want PASS, got %s", out.Status)
	}
}

func TestChkNoopenerPrivacy(t *testing.T) {
	surf := func(body string, privacy bool) *CheckCtx {
		return &CheckCtx{
			Surface: manifest.Surface{URL: "https://me.test", Kind: "site", PrivacySurface: privacy},
			Doc:     docFinal("https://me.test", body),
		}
	}
	ext := `<a target="_blank" href="https://evil.example/x">x</a>`
	if out := chkNoopener(context.Background(), surf(ext, false)); out.Status != Fail {
		t.Errorf("external _blank without rel: want FAIL, got %s", out.Status)
	}
	okBody := `<a target="_blank" rel="noopener" href="https://evil.example/x">x</a>`
	if out := chkNoopener(context.Background(), surf(okBody, false)); out.Status != Pass {
		t.Errorf("noopener present (non-privacy): want PASS, got %s", out.Status)
	}
	// On a privacy surface, noopener alone is insufficient — needs noreferrer.
	if out := chkNoopener(context.Background(), surf(okBody, true)); out.Status != Fail {
		t.Errorf("privacy surface needs noreferrer: want FAIL, got %s", out.Status)
	}
}

func TestChkSRI(t *testing.T) {
	body := `<script src="https://cdn.evil/x.js"></script>`
	if out := chkSRI(context.Background(), &CheckCtx{Doc: docFinal("https://me.test", body)}); out.Status != Fail {
		t.Errorf("cross-origin script without integrity: want FAIL, got %s", out.Status)
	}
	okBody := `<script src="https://cdn.evil/x.js" integrity="sha384-abc"></script>`
	if out := chkSRI(context.Background(), &CheckCtx{Doc: docFinal("https://me.test", okBody)}); out.Status != Pass {
		t.Errorf("cross-origin script with integrity: want PASS, got %s", out.Status)
	}
	rel := `<script src="/local.js"></script>`
	if out := chkSRI(context.Background(), &CheckCtx{Doc: docFinal("https://me.test", rel)}); out.Status != Pass {
		t.Errorf("same-origin script: want PASS, got %s", out.Status)
	}
}

func TestChkCookieAttrs(t *testing.T) {
	good := newDoc(200, "", nil)
	good.Header.Add("Set-Cookie", "sid=1; Secure; HttpOnly; SameSite=Strict")
	if out := chkCookieAttrs(context.Background(), &CheckCtx{Doc: good}); out.Status != Pass {
		t.Errorf("hardened cookie: want PASS, got %s", out.Status)
	}
	weak := newDoc(200, "", nil)
	weak.Header.Add("Set-Cookie", "sid=1; Path=/")
	if out := chkCookieAttrs(context.Background(), &CheckCtx{Doc: weak}); out.Status != Fail {
		t.Errorf("weak cookie: want FAIL, got %s", out.Status)
	}
}

func TestHardenedSurfacePassesHeaderFamily(t *testing.T) {
	doc := newDoc(200, "", hardenedHeaders)
	c := &CheckCtx{Doc: doc, Surface: manifest.Surface{URL: "https://me.test"}}
	for name, fn := range map[string]Checker{
		"nosniff": chkNosniff, "xfo": chkXFO, "referrer": chkReferrer,
		"permissions": chkPermissionsPolicy, "hsts": chkHSTS, "csp": chkCSPPresent,
		"deny-default": chkDenyDefault, "trusted-types": chkTrustedTypes, "upgrade": chkUpgradeInsecure,
	} {
		if out := fn(context.Background(), c); out.Status != Pass {
			t.Errorf("%s on hardened surface: got %s (%s), want PASS", name, out.Status, out.Evidence.Observed)
		}
	}
}
