// Package target holds the URL helpers shared by the entry points that
// synthesize a manifest from a bare URL (the `agssh scan` subcommand and the
// MCP server), so both normalize a target identically.
package target

import (
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// NormalizeURL requires an absolute http(s) URL with a host. A bare host such as
// "example.org" is upgraded to https://example.org so a caller need not remember
// the scheme; anything with an explicit non-http scheme is rejected.
func NormalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("url is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid url %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("url scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("url %q has no host", raw)
	}
	return u.String(), nil
}

// RegistrableDomain derives the eTLD+1 (the DNS zone) from a surface URL's host,
// stripping the port. Returns "" when the host is an IP or otherwise has no
// registrable domain, in which case the DNS-plane checks stay inconclusive.
func RegistrableDomain(surfURL string) string {
	u, err := url.Parse(surfURL)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	if host == "" {
		return ""
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return etld1
}
