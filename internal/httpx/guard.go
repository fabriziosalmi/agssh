package httpx

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// BlockedTargetError is returned when a fetch is refused because the target
// resolves to a non-public address. It is distinct so callers (the MCP server)
// can surface a precise "refusing to scan an internal target" message.
type BlockedTargetError struct{ Addr string }

func (e *BlockedTargetError) Error() string {
	return "refusing to connect to non-public address " + e.Addr
}

// NewGuarded builds a Client that behaves like New but refuses, at DIAL time, to
// connect to a non-public IP: loopback, link-local (this includes the cloud
// metadata endpoint 169.254.169.254), RFC1918 private, unique-local, the
// unspecified address, and multicast. Because the check runs on the RESOLVED
// address of every connection, it also covers redirects and DNS-rebinding — a
// hostname that resolves to a public IP at check time but an internal one at
// dial time is still blocked.
//
// Use it whenever the target URL is untrusted (e.g. supplied to an MCP tool by a
// model), so a scan cannot be turned into an SSRF probe of internal services.
// The plain New (no address filtering) stays the default for the CLI, whose
// operator may legitimately scan an internal or air-gapped surface.
func NewGuarded(timeout time.Duration) *Client {
	dialer := &net.Dialer{
		Timeout: timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("refusing to dial unresolved address %q", address)
			}
			if isBlockedIP(ip) {
				return &BlockedTargetError{Addr: ip.String()}
			}
			return nil
		},
	}
	tr := &http.Transport{
		DialContext:         dialer.DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConns:        4,
		IdleConnTimeout:     timeout,
		TLSHandshakeTimeout: timeout,
		DisableKeepAlives:   true,
	}
	return &Client{hc: &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}}
}

// GuardPublicTarget resolves the host of rawURL and returns a non-nil error if it
// is (or resolves to) a non-public address. It gives a caller a clean, early
// rejection before any fetch. A resolution failure is deliberately NOT an error
// here — the fetch will fail on its own — and this is only advisory: the
// authoritative block is the NewGuarded dialer, which also defeats a rebind that
// races this lookup.
func GuardPublicTarget(ctx context.Context, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	return GuardPublicHost(ctx, u.Hostname())
}

// GuardPublicHostPort guards a bare "host" or "host:port" (e.g. a DNS resolver
// argument), rejecting a non-public target the same way GuardPublicTarget does.
func GuardPublicHostPort(ctx context.Context, hostPort string) error {
	hostPort = strings.TrimSpace(hostPort)
	if hostPort == "" {
		return nil
	}
	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}
	return GuardPublicHost(ctx, host)
}

// GuardPublicHost rejects a host that is, or resolves to, a non-public address.
func GuardPublicHost(ctx context.Context, host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return fmt.Errorf("refusing to reach %s: it is a non-public address", ip)
		}
		return nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return fmt.Errorf("refusing to reach %s: it resolves to non-public address %s", host, ip)
		}
	}
	return nil
}

// extraBlockedCIDRs are ranges the net.IP predicates don't cover but that an
// untrusted scan still must not reach: CGNAT, IPv4 "this network", IETF
// protocol/benchmark assignments, and the NAT64 prefixes (which embed an
// arbitrary — possibly internal — IPv4 address).
var extraBlockedCIDRs = parseCIDRs(
	"100.64.0.0/10",  // carrier-grade NAT (RFC 6598)
	"0.0.0.0/8",      // "this network" (RFC 1122) — only 0.0.0.0 is IsUnspecified
	"192.0.0.0/24",   // IETF protocol assignments (RFC 6890)
	"198.18.0.0/15",  // benchmarking (RFC 2544)
	"64:ff9b::/96",   // NAT64 well-known prefix (RFC 6052)
	"64:ff9b:1::/48", // NAT64 local-use (RFC 8215)
)

func parseCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// isBlockedIP reports whether ip is one an untrusted scan must never reach. The
// net.IP predicates cover: 127.0.0.0/8 + ::1 (loopback); 169.254.0.0/16 +
// fe80::/10 (link-local, incl. cloud metadata); 10/8, 172.16/12, 192.168/16 +
// fc00::/7 (private / unique-local); 0.0.0.0 + :: (unspecified); and multicast.
// extraBlockedCIDRs adds CGNAT, 0.0.0.0/8, protocol/benchmark, and NAT64. A nil
// (unparseable) IP is refused — fail-closed.
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsPrivate() ||
		ip.IsUnspecified() ||
		ip.IsMulticast() {
		return true
	}
	for _, n := range extraBlockedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
