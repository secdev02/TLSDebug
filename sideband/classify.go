package sideband

import "bytes"

// classifyUDP reports which module owns the first datagram.
//
// WireGuard message types are 1 through 4.
// DTLS content types are 20 through 25.
// A QUIC long header sets the high bit. A QUIC short header sets the
// fixed bit and clears the high bit, so the first byte is 0x40 through 0x7f.
func classifyUDP(pkt []byte) Proto {
	if len(pkt) == 0 {
		return ProtoUDP
	}
	b := pkt[0]
	switch b {
	case 1, 2, 3, 4:
		return ProtoWireGuard
	case 20, 21, 22, 23, 24, 25:
		return ProtoDTLS
	}
	if b&0x80 != 0 || (b&0xc0) == 0x40 {
		return ProtoQUIC
	}
	return ProtoUDP
}

// classifyTCP reports the client-first protocol.
// A TLS handshake record starts with content type 22.
// Postgres SSLRequest is an 8-byte message: length 8 and code 80877103.
func classifyTCP(pkt []byte) Proto {
	if len(pkt) == 0 {
		return ProtoTCP
	}
	if pkt[0] == 22 {
		return ProtoTLS
	}
	if isPostgresSSLRequest(pkt) {
		return ProtoSTARTTLS
	}
	return ProtoTCP
}

func isPostgresSSLRequest(pkt []byte) bool {
	return bytes.Equal(pkt, []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f})
}

// starttlsKind returns smtp, imap, pop3, ftp, or xmpp when banner is a
// cleartext greeting that can upgrade. An empty string means raw TCP.
func starttlsKind(banner []byte) string {
	if len(banner) == 0 {
		return ""
	}
	s := banner
	switch {
	case hasPrefixFold(s, []byte("220")):
		// SMTP and FTP both greet with 220. SMTP mentions ESMTP or SMTP.
		if bytes.Contains(bytes.ToLower(s), []byte("smtp")) || bytes.Contains(bytes.ToLower(s), []byte("esmtp")) {
			return "smtp"
		}
		return "ftp"
	case hasPrefixFold(s, []byte("* OK")), hasPrefixFold(s, []byte("*OK")):
		return "imap"
	case hasPrefixFold(s, []byte("+OK")):
		return "pop3"
	case bytes.Contains(s, []byte("<stream:stream")):
		return "xmpp"
	default:
		return ""
	}
}

func hasPrefixFold(b, prefix []byte) bool {
	if len(b) < len(prefix) {
		return false
	}
	return bytes.EqualFold(b[:len(prefix)], prefix)
}
