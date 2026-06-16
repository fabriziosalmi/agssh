// Package httpx provides a hardened HTTP client and a fetched-document model
// used by the static checks. It captures response headers verbatim and the
// body, and surfaces both header-delivered and <meta>-delivered CSP so the
// standard's "header vs meta" distinction (Tier A vs Tier B) is observable.
package httpx

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type Client struct {
	hc *http.Client
}

// New builds a client with strict timeouts and a modern TLS floor. It does NOT
// follow redirects silently — the final hop is what we assess.
func New(timeout time.Duration) *Client {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConns:        4,
		IdleConnTimeout:     timeout,
		TLSHandshakeTimeout: timeout,
		DisableKeepAlives:   true,
	}
	return &Client{hc: &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}}
}

// Doc is a fetched surface: its final URL, status, headers and body.
type Doc struct {
	RequestURL string
	FinalURL   string
	Status     int
	Header     http.Header
	Body       []byte
}

func (c *Client) Fetch(ctx context.Context, url string) (*Doc, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "agssh-runner/1.0 (+conformance)")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	return &Doc{
		RequestURL: url,
		FinalURL:   resp.Request.URL.String(),
		Status:     resp.StatusCode,
		Header:     resp.Header,
		Body:       body,
	}, nil
}

// HeaderCSP returns the CSP delivered as an HTTP response header (Tier A).
func (d *Doc) HeaderCSP() string {
	return strings.TrimSpace(d.Header.Get("Content-Security-Policy"))
}

var metaCSPRe = regexp.MustCompile(
	`(?is)<meta[^>]+http-equiv\s*=\s*["']?content-security-policy["']?[^>]+content\s*=\s*["']([^"']*)["']`)

// MetaCSP returns the CSP delivered via <meta http-equiv> (Tier B), if any.
func (d *Doc) MetaCSP() string {
	m := metaCSPRe.FindSubmatch(d.Body)
	if len(m) == 2 {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}

// SameHost reports whether other shares the surface's host.
func SameHost(surfaceURL, other string) bool {
	hs := hostOf(surfaceURL)
	ho := hostOf(other)
	return hs != "" && hs == ho
}

func hostOf(raw string) string {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
	}
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.Index(raw, "@"); i >= 0 {
		raw = raw[i+1:]
	}
	if i := strings.Index(raw, ":"); i >= 0 {
		raw = raw[:i]
	}
	return strings.ToLower(raw)
}
