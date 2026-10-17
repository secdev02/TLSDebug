package sideband

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"time"
)

// interceptSTARTTLS relays the cleartext greeting until the client asks to
// upgrade, then terminates TLS on both sides. kind is smtp, imap, pop3, ftp,
// or xmpp, from the origin banner.
func interceptSTARTTLS(flow *Flow, client, origin net.Conn, kind string) error {
	cr := bufio.NewReader(client)
	or := bufio.NewReader(origin)
	flow.Log(DirOriginToProxy, LayerPlain, ProtoSTARTTLS, nil, map[string]any{"application": kind, "phase": "banner"})

	for {
		line, err := readLine(cr)
		if err != nil {
			return err
		}
		flow.Log(DirClientToProxy, LayerPlain, ProtoSTARTTLS, line, map[string]any{"application": kind})
		if _, err := origin.Write(line); err != nil {
			return err
		}
		if isUpgradeCommand(kind, line) {
			resp, err := readReply(or, kind)
			if err != nil {
				return err
			}
			flow.Log(DirOriginToProxy, LayerPlain, ProtoSTARTTLS, resp, map[string]any{"application": kind, "phase": "upgrade"})
			if _, err := client.Write(resp); err != nil {
				return err
			}
			return upgradeTLS(flow, client, origin)
		}
		resp, err := readReply(or, kind)
		if err != nil {
			return err
		}
		flow.Log(DirOriginToProxy, LayerPlain, ProtoSTARTTLS, resp, map[string]any{"application": kind})
		if _, err := client.Write(resp); err != nil {
			return err
		}
	}
}

func upgradeTLS(flow *Flow, client, origin net.Conn) error {
	serverKeys := flow.log.newCapture()
	cfg, err := tlsServerConfig(flow, serverKeys)
	if err != nil {
		return err
	}
	clientTLS := tls.Server(&teeConn{Conn: client, flow: flow, proto: ProtoSTARTTLS}, cfg)
	if err := clientTLS.Handshake(); err != nil {
		return err
	}
	defer clientTLS.Close()
	logTLSState(flow, DirClientToProxy, clientTLS.ConnectionState(), leafFromConfig(cfg), serverKeys.Take())
	originKeys := flow.log.newCapture()
	originTLS := tls.Client(&teeConn{Conn: origin, flow: flow, proto: ProtoSTARTTLS}, tlsClientConfig(flow, originKeys))
	if err := originTLS.Handshake(); err != nil {
		return err
	}
	defer originTLS.Close()
	logTLSState(flow, DirProxyToOrigin, originTLS.ConnectionState(), flow.clientCert, originKeys.Take())
	return splice(flow, ProtoSTARTTLS, clientTLS, originTLS)
}

// interceptPostgres handles the 8-byte SSLRequest. 'S' from the origin means
// both sides upgrade. 'N' means the rest of the session stays raw TCP.
func interceptPostgres(flow *Flow, client net.Conn) error {
	origin, err := net.DialTimeout("tcp", flow.Upstream(), 10*time.Second)
	if err != nil {
		return err
	}
	defer origin.Close()
	req := make([]byte, 8)
	if _, err := io.ReadFull(client, req); err != nil {
		return err
	}
	flow.Log(DirClientToProxy, LayerPlain, ProtoSTARTTLS, req, map[string]any{"application": "postgres"})
	if _, err := origin.Write(req); err != nil {
		return err
	}
	reply := make([]byte, 1)
	if _, err := io.ReadFull(origin, reply); err != nil {
		return err
	}
	flow.Log(DirOriginToProxy, LayerPlain, ProtoSTARTTLS, reply, map[string]any{"application": "postgres"})
	if _, err := client.Write(reply); err != nil {
		return err
	}
	if reply[0] != 'S' {
		return splice(flow, ProtoTCP, client, origin)
	}
	return upgradeTLS(flow, client, origin)
}

func isUpgradeCommand(kind string, line []byte) bool {
	s := strings.TrimSpace(strings.ToUpper(string(line)))
	switch kind {
	case "smtp", "ftp", "pop3":
		return s == "STARTTLS"
	case "imap":
		fields := strings.Fields(s)
		return len(fields) >= 2 && fields[len(fields)-1] == "STARTTLS"
	case "xmpp":
		return strings.Contains(s, "STARTTLS")
	case "ldap":
		return ldapStartTLS(line)
	default:
		return false
	}
}

func readLine(r *bufio.Reader) ([]byte, error) {
	line, err := r.ReadBytes('\n')
	if len(line) > 0 {
		return line, nil
	}
	return nil, err
}

func readReply(r *bufio.Reader, kind string) ([]byte, error) {
	var buf bytes.Buffer
	for {
		line, err := readLine(r)
		if len(line) > 0 {
			buf.Write(line)
		}
		if err != nil {
			if buf.Len() > 0 && err == io.EOF {
				return buf.Bytes(), nil
			}
			return buf.Bytes(), err
		}
		if replyDone(kind, line) {
			return buf.Bytes(), nil
		}
	}
}

func replyDone(kind string, line []byte) bool {
	s := strings.TrimSpace(string(line))
	switch kind {
	case "smtp", "ftp", "pop3":
		// "250-more" continues. "250 done" ends. POP3 is one line.
		if kind == "pop3" {
			return true
		}
		if len(s) >= 4 && s[3] == ' ' {
			return true
		}
		return len(s) < 4
	default:
		return true
	}
}
