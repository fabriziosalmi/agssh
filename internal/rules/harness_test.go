package rules

import (
	"net"
	"net/http"
	"testing"

	"github.com/fabriziosalmi/agssh/internal/httpx"
	"github.com/fabriziosalmi/agssh/internal/manifest"
	"github.com/miekg/dns"
)

// Shared, hermetic test fixtures for the checkers (issue #1). Nothing here
// touches the network beyond loopback listeners the test itself starts.

// surfaceURL wraps an addr (host:port) into an https surface declaration.
func surfaceURL(addr string) manifest.Surface {
	return manifest.Surface{URL: "https://" + addr}
}

// newDoc builds a fetched-document fixture for static checks.
func newDoc(status int, body string, header map[string]string) *httpx.Doc {
	h := http.Header{}
	for k, v := range header {
		h.Set(k, v)
	}
	return &httpx.Doc{Status: status, Header: h, Body: []byte(body)}
}

// dnsTestServer starts a loopback UDP DNS server with the given handler and
// returns its address for use as CheckCtx.Resolver.
func dnsTestServer(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dns listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// answer is a tiny helper to write a single-message DNS reply.
func answer(w dns.ResponseWriter, req *dns.Msg, rcode int, rrs ...dns.RR) {
	m := new(dns.Msg)
	m.SetRcode(req, rcode)
	m.Answer = rrs
	_ = w.WriteMsg(m)
}
