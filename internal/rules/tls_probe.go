package rules

import (
	"io"
	"net"
	"time"
)

// offersLegacyTLS probes whether the server at addr will negotiate TLS 1.0/1.1.
// It hand-builds a TLS 1.0 ClientHello and inspects the server's first record so
// the verdict reflects the *server's* policy, not the Go client's (which refuses
// legacy TLS on its own since Go 1.22).
//
// It returns a 3-state result so the caller never turns an ambiguous probe into a
// PASS:
//   - accepted: a ServerHello negotiated TLS <= 1.1 (legacy IS accepted -> FAIL)
//   - conclusive==false: we could not connect, OR the server answered with a
//     non-protocol_version error (e.g. handshake_failure from no cipher overlap),
//     which does NOT prove the version floor. The caller maps this to INCONCLUSIVE.
//   - accepted==false && conclusive==true: the server refused with a clean
//     protocol_version alert (legacy refused -> good).
//
// Crucially, an AEAD/ChaCha-only-but-TLS-1.0-permitting server (a common
// misconfig) sends handshake_failure to our CBC-only ClientHello; treating that
// as "refused" would resurrect the very false-PASS this probe exists to prevent,
// so it is reported as inconclusive instead.
func offersLegacyTLS(addr, sni string, timeout time.Duration) (accepted, conclusive bool) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return false, false // unreachable -> INCONCLUSIVE
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(clientHelloTLS10(sni)); err != nil {
		return false, false
	}

	hdr := make([]byte, 5) // TLS record header: type(1) version(2) length(2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return false, false // RST/EOF before any record -> ambiguous, not provable
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	switch hdr[0] {
	case 21: // alert: read level+description
		if n < 2 {
			return false, false
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(conn, body); err != nil {
			return false, false
		}
		const protocolVersion = 70 // RFC 5246 alert description
		if body[1] == protocolVersion {
			return false, true // server explicitly refuses this version
		}
		return false, false // handshake_failure / other -> can't conclude the floor
	case 22: // handshake
		if n < 6 {
			return false, false
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(conn, body); err != nil {
			return false, false
		}
		if body[0] != 2 { // not a ServerHello
			return false, false
		}
		// ServerHello.server_version sits right after the 4-byte handshake header.
		ver := uint16(body[4])<<8 | uint16(body[5])
		if ver <= 0x0302 { // 0x0301=TLS1.0, 0x0302=TLS1.1
			return true, true // legacy negotiated -> definitive FAIL
		}
		return false, true // negotiated >= 1.2 off a 1.0 hello -> legacy not used
	default:
		return false, false
	}
}

// Static extensions advertised in the legacy probe.
var (
	// supported_groups (0x000a): secp256r1, secp384r1, x25519.
	extSupportedGroups = []byte{0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x1d}
	// ec_point_formats (0x000b): uncompressed.
	extECPointFormats = []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00}
)

// clientHelloTLS10 builds a minimal TLS 1.0 ClientHello record offering legacy
// cipher suites, EC group/point-format extensions, and SNI for the given host.
func clientHelloTLS10(sni string) []byte {
	body := []byte{0x03, 0x01} // client_version = TLS 1.0
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00) // session_id length = 0

	suites := []byte{
		0xc0, 0x09, // ECDHE_ECDSA_WITH_AES_128_CBC_SHA
		0xc0, 0x0a, // ECDHE_ECDSA_WITH_AES_256_CBC_SHA
		0xc0, 0x13, // ECDHE_RSA_WITH_AES_128_CBC_SHA
		0xc0, 0x14, // ECDHE_RSA_WITH_AES_256_CBC_SHA
		0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
		0x00, 0x0a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
	}
	body = append(body, byte(len(suites)>>8), byte(len(suites)))
	body = append(body, suites...)

	body = append(body, 0x01, 0x00) // 1 compression method: null

	// Always advertise EC groups + point formats so a server with an ECDSA cert
	// can pick an ECDHE_ECDSA suite — without these a modern ECDSA-only server
	// answers handshake_failure and we'd wrongly read "legacy refused". SNI is
	// added only for real DNS names (an empty server_name_list is malformed).
	exts := make([]byte, 0, 32)
	exts = append(exts, extSupportedGroups...)
	exts = append(exts, extECPointFormats...)
	exts = append(exts, sniExtension(sni)...)
	body = append(body, byte(len(exts)>>8), byte(len(exts))) // extensions length
	body = append(body, exts...)

	hs := make([]byte, 4+len(body)) // handshake header: type(1) length(3)
	hs[0] = 0x01                    // client_hello
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))
	copy(hs[4:], body)

	rec := make([]byte, 5+len(hs)) // record header: type(1) version(2) length(2)
	rec[0] = 22                    // handshake
	rec[1], rec[2] = 0x03, 0x01    // TLS 1.0 record version
	rec[3] = byte(len(hs) >> 8)
	rec[4] = byte(len(hs))
	copy(rec[5:], hs)
	return rec
}

// sniExtension builds a server_name (SNI) extension for host, or nil when host
// is empty or an IP literal (SNI must carry a DNS name, never an IP, and an
// empty server_name_list is malformed).
func sniExtension(host string) []byte {
	if host == "" || net.ParseIP(host) != nil {
		return nil
	}
	name := []byte(host)
	list := []byte{0x00} // name_type = host_name
	list = append(list, byte(len(name)>>8), byte(len(name)))
	list = append(list, name...)

	data := append([]byte{byte(len(list) >> 8), byte(len(list))}, list...) // server_name_list
	ext := []byte{0x00, 0x00}                                              // extension_type = server_name
	ext = append(ext, byte(len(data)>>8), byte(len(data)))
	ext = append(ext, data...)
	return ext
}
