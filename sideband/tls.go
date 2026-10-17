package sideband

import (
	"crypto/tls"
	"net"
	"time"
)

// interceptTLS terminates TLS with a leaf from the proxy CA and dials the
// origin with a normal verifying client. Plaintext is then a raw byte pipe.
func interceptTLS(flow *Flow, client net.Conn) error {
	cfg, err := tlsServerConfig(flow)
	if err != nil {
		return err
	}
	clientTLS := tls.Server(&teeConn{Conn: client, flow: flow, proto: ProtoTLS}, cfg)
	if err := clientTLS.Handshake(); err != nil {
		return err
	}
	defer clientTLS.Close()
	logTLSState(flow, DirClientToProxy, clientTLS.ConnectionState())

	originTCP, err := net.DialTimeout("tcp", flow.Upstream(), 10*time.Second)
	if err != nil {
		return err
	}
	defer originTCP.Close()
	originTLS := tls.Client(&teeConn{Conn: originTCP, flow: flow, proto: ProtoTLS}, tlsClientConfig(flow))
	if err := originTLS.Handshake(); err != nil {
		return err
	}
	defer originTLS.Close()
	logTLSState(flow, DirProxyToOrigin, originTLS.ConnectionState())
	return splice(flow, ProtoTLS, clientTLS, originTLS)
}

func logTLSState(flow *Flow, dir Direction, st tls.ConnectionState) {
	flow.Log(dir, LayerPlain, ProtoTLS, nil, map[string]any{
		"version":     st.Version,
		"cipher":      st.CipherSuite,
		"server_name": st.ServerName,
		"alpn":        st.NegotiatedProtocol,
		"handshake":   "complete",
	})
}
