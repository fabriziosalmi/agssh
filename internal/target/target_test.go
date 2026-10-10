package target

import "testing"

func TestNormalizeURL(t *testing.T) {
	for in, want := range map[string]string{
		"example.org":            "https://example.org",
		" https://example.org/ ": "https://example.org/",
		"http://localhost:8080":  "http://localhost:8080",
	} {
		got, err := NormalizeURL(in)
		if err != nil || got != want {
			t.Errorf("NormalizeURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "ftp://example.org", "https://"} {
		if _, err := NormalizeURL(bad); err == nil {
			t.Errorf("NormalizeURL(%q) must error", bad)
		}
	}
}

func TestRegistrableDomain(t *testing.T) {
	if got := RegistrableDomain("https://api.callimacus.ai:8443/x"); got != "callimacus.ai" {
		t.Errorf("got %q", got)
	}
	if got := RegistrableDomain("http://127.0.0.1/"); got != "" {
		t.Errorf("IP host must have no zone, got %q", got)
	}
}
