package httpx

import (
	"context"
	"net"
	"testing"
)

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", // loopback
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", // IPv4-mapped IPv6
		"169.254.169.254",                       // link-local (cloud metadata)
		"fe80::1",                               // link-local v6
		"10.0.0.1", "172.16.9.9", "192.168.1.1", // RFC1918
		"fc00::1",         // unique-local
		"0.0.0.0",         // unspecified
		"0.1.2.3",         // 0.0.0.0/8 "this network"
		"224.0.0.1",       // multicast
		"100.64.0.1",      // CGNAT (RFC 6598)
		"100.127.255.255", // CGNAT upper edge
		"64:ff9b::a00:1",  // NAT64 embedding 10.0.0.1
		"198.18.0.1",      // benchmarking
	}
	for _, s := range blocked {
		if !isBlockedIP(net.ParseIP(s)) {
			t.Errorf("isBlockedIP(%s) = false, want true", s)
		}
	}
	if !isBlockedIP(nil) {
		t.Errorf("isBlockedIP(nil) = false, want true (fail-closed)")
	}
	public := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:2800:220:1::", "100.63.255.255", "100.128.0.0"}
	for _, s := range public {
		if isBlockedIP(net.ParseIP(s)) {
			t.Errorf("isBlockedIP(%s) = true, want false", s)
		}
	}
}

// TestGuardPublicTargetLiteralIPs uses only IP-literal URLs, so no DNS is needed.
func TestGuardPublicTargetLiteralIPs(t *testing.T) {
	ctx := context.Background()
	for _, u := range []string{
		"http://127.0.0.1/", "http://[::1]:6379/",
		"http://169.254.169.254/latest/meta-data/iam/",
		"http://10.0.0.5/", "http://192.168.1.1/admin",
	} {
		if err := GuardPublicTarget(ctx, u); err == nil {
			t.Errorf("GuardPublicTarget(%q) = nil, want an internal-target error", u)
		}
	}
	for _, u := range []string{"http://8.8.8.8/", "https://1.1.1.1/"} {
		if err := GuardPublicTarget(ctx, u); err != nil {
			t.Errorf("GuardPublicTarget(%q) = %v, want allowed", u, err)
		}
	}
}
