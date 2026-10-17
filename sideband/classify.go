package sideband

import (
	"bytes"
	"encoding/binary"
)

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
	case ldapStartTLS(s):
		return "ldap"
	default:
		return ""
	}
}

// ldapStartTLS reports an LDAP StartTLS extended request. The OID is
// 1.3.6.1.4.1.1466.20037, either in BER or as ASCII.
func ldapStartTLS(b []byte) bool {
	if bytes.Contains(b, []byte("1.3.6.1.4.1.1466.20037")) {
		return true
	}
	return bytes.Contains(b, []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x8b, 0x46, 0x81, 0x9c, 0x65})
}

// tlsRecordFields reads a TLS record header. Handshake type is present when
// the record is a handshake and the fragment byte is in this buffer.
func tlsRecordFields(b []byte) map[string]any {
	if len(b) < 5 {
		return map[string]any{"len": len(b)}
	}
	fields := map[string]any{
		"content_type": b[0],
		"version":      binary.BigEndian.Uint16(b[1:3]),
		"record_len":   binary.BigEndian.Uint16(b[3:5]),
	}
	if b[0] == 22 && len(b) > 5 {
		fields["handshake_type"] = b[5]
	}
	return fields
}

// dtlsRecordFields reads a DTLS record header: epoch and 48-bit sequence
// sit where TLS has only a version and length.
func dtlsRecordFields(b []byte) map[string]any {
	if len(b) < 13 {
		return map[string]any{"len": len(b)}
	}
	var seq uint64
	for _, x := range b[5:11] {
		seq = seq<<8 | uint64(x)
	}
	fields := map[string]any{
		"content_type": b[0],
		"version":      binary.BigEndian.Uint16(b[1:3]),
		"epoch":        binary.BigEndian.Uint16(b[3:5]),
		"sequence":     seq,
		"record_len":   binary.BigEndian.Uint16(b[11:13]),
	}
	if b[0] == 22 && len(b) > 13 {
		fields["handshake_type"] = b[13]
	}
	return fields
}

func hasPrefixFold(b, prefix []byte) bool {
	if len(b) < len(prefix) {
		return false
	}
	return bytes.EqualFold(b[:len(prefix)], prefix)
}
