package rules

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// selfSignedCert builds a throwaway cert/key for the local TLS test listeners.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tlsListener starts a TLS server with the given version bounds and drives the
// handshake for each connection so a raw probe gets a ServerHello or an alert.
func tlsListener(t *testing.T, min, max uint16) net.Listener {
	t.Helper()
	cfg := &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		MinVersion:   min,
		MaxVersion:   max,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake() // emits ServerHello or a fatal alert
				}
				_ = c.Close()
			}(c)
		}
	}()
	return ln
}

func TestOffersLegacyTLS(t *testing.T) {
	legacy := tlsListener(t, tls.VersionTLS10, tls.VersionTLS12)
	modern := tlsListener(t, tls.VersionTLS12, tls.VersionTLS13)

	if accepted, reachable := offersLegacyTLS(legacy.Addr().String(), "127.0.0.1", 3*time.Second); !reachable || !accepted {
		t.Errorf("legacy server: got accepted=%v reachable=%v, want accepted=true", accepted, reachable)
	}
	if accepted, reachable := offersLegacyTLS(modern.Addr().String(), "127.0.0.1", 3*time.Second); !reachable || accepted {
		t.Errorf("modern server: got accepted=%v reachable=%v, want accepted=false", accepted, reachable)
	}
	if _, reachable := offersLegacyTLS("127.0.0.1:1", "127.0.0.1", 1*time.Second); reachable {
		t.Errorf("closed port: want reachable=false")
	}
}

// TestChkTLSFloor is the regression test for the false-PASS bug: a server that
// accepts TLS 1.0 MUST fail, a modern-only server MUST pass.
func TestChkTLSFloor(t *testing.T) {
	legacy := tlsListener(t, tls.VersionTLS10, tls.VersionTLS12)
	modern := tlsListener(t, tls.VersionTLS12, tls.VersionTLS13)

	out := chkTLSFloor(t.Context(), &CheckCtx{Surface: surfaceURL(legacy.Addr().String())})
	if out.Status != Fail {
		t.Errorf("legacy-accepting server: got %s, want FAIL", out.Status)
	}
	out = chkTLSFloor(t.Context(), &CheckCtx{Surface: surfaceURL(modern.Addr().String())})
	if out.Status != Pass {
		t.Errorf("modern-only server: got %s (%s), want PASS", out.Status, out.Err)
	}
}
