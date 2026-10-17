package sideband

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// interceptTLS terminates TLS with a leaf from the proxy CA and dials the
// origin with a normal verifying client. Plaintext is then a raw byte pipe.
func interceptTLS(flow *Flow, client net.Conn) error {
	serverKeys := flow.log.newCapture()
	cfg, err := tlsServerConfig(flow, serverKeys)
	if err != nil {
		return err
	}
	clientTLS := tls.Server(&teeConn{Conn: client, flow: flow, proto: ProtoTLS}, cfg)
	if err := clientTLS.Handshake(); err != nil {
		return fmt.Errorf("client handshake: %w", err)
	}
	defer clientTLS.Close()
	logTLSState(flow, DirClientToProxy, clientTLS.ConnectionState(), leafFromConfig(cfg), serverKeys.Take())

	originTCP, err := net.DialTimeout("tcp", flow.Upstream(), 10*time.Second)
	if err != nil {
		return err
	}
	defer originTCP.Close()
	originKeys := flow.log.newCapture()
	originTLS := tls.Client(&teeConn{Conn: originTCP, flow: flow, proto: ProtoTLS}, tlsClientConfig(flow, originKeys))
	if err := originTLS.Handshake(); err != nil {
		return fmt.Errorf("origin handshake: %w", err)
	}
	defer originTLS.Close()
	logTLSState(flow, DirProxyToOrigin, originTLS.ConnectionState(), flow.clientCert, originKeys.Take())
	return splice(flow, ProtoTLS, clientTLS, originTLS)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func logTLSState(flow *Flow, dir Direction, st tls.ConnectionState, leaf *tls.Certificate, keylog string) {
	fields := map[string]any{
		"version":     st.Version,
		"cipher":      st.CipherSuite,
		"server_name": firstNonEmpty(st.ServerName, serverName(flow.Upstream())),
		"alpn":        st.NegotiatedProtocol,
		"handshake":   "complete",
		"peer_certs":  peerCertFields(st.PeerCertificates),
		"keylog":      keylog,
	}
	if leaf != nil && flow.log != nil {
		pemText := privatePEM(leaf.PrivateKey)
		fields["leaf_private_pem"] = pemText
		_ = flow.log.WriteSecrets(pemText)
		if len(leaf.Certificate) > 0 {
			c := certPEM(leaf.Certificate[0])
			fields["leaf_cert_pem"] = c
			_ = flow.log.WriteSecrets(c)
		}
	}
	if flow.log != nil {
		if peers, ok := fields["peer_certs"].([]map[string]string); ok {
			for _, peer := range peers {
				_ = flow.log.WriteSecrets(peer["pem"])
			}
		}
	}
	flow.Log(dir, LayerPlain, ProtoTLS, nil, fields)
}
