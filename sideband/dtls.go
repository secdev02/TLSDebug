package sideband

import (
	"crypto/tls"
	"net"

	"github.com/pion/dtls/v3"
)

// ServeDTLS terminates DTLS with the proxy CA and re-originates DTLS upstream.
// Retransmissions stay inside the DTLS stack. Application data is logged as plaintext.
func (s *Server) ServeDTLS(listen string) error {
	addr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return err
	}
	host := serverName(s.Upstream)
	if s.Certs == nil {
		return errNoCerts
	}
	cert, err := s.Certs.Certificate(host)
	if err != nil {
		return err
	}
	auth := dtls.RequestClientCert
	if s.MTLSRequire {
		auth = dtls.RequireAnyClientCert
	}
	ln, err := dtls.Listen("udp", addr, &dtls.Config{
		Certificates: []tls.Certificate{*cert},
		ClientAuth:   auth,
		KeyLogWriter: secretDest{s.Log},
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.dtlsLn = ln
	s.mu.Unlock()
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleDTLS(conn, host, cert)
	}
}

// DTLSAddr is the bound DTLS listener, or nil before ServeDTLS is ready.
func (s *Server) DTLSAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dtlsLn == nil {
		return nil
	}
	return s.dtlsLn.Addr()
}

func (s *Server) handleDTLS(client net.Conn, host string, leaf *tls.Certificate) {
	defer client.Close()
	flow := s.newFlow("udp", client.RemoteAddr().String())
	_ = flow.log.WriteSecrets(privatePEM(leaf.PrivateKey))
	if flow.clientCert != nil {
		_ = flow.log.WriteSecrets(privatePEM(flow.clientCert.PrivateKey))
	}
	if dc, ok := client.(*dtls.Conn); ok {
		if st, ok := dc.ConnectionState(); ok {
			pemText := privatePEM(leaf.PrivateKey)
			_ = flow.log.WriteSecrets(pemText)
			flow.Log(DirClientToProxy, LayerPlain, ProtoDTLS, nil, map[string]any{
				"handshake":        "complete",
				"cipher":           st.CipherSuiteID,
				"peer_certs":       peerCertsFromDER(st.PeerCertificates),
				"leaf_private_pem": pemText,
				"server_name":      host,
			})
		}
	}
	raddr, err := net.ResolveUDPAddr("udp", s.Upstream)
	if err != nil {
		flow.Log(DirProxyToOrigin, LayerWire, ProtoDTLS, nil, map[string]any{"error": err.Error()})
		return
	}
	originKeys := flow.log.newCapture()
	originCfg := &dtls.Config{
		ServerName:   host,
		RootCAs:      s.OriginRoots,
		KeyLogWriter: originKeys,
	}
	if flow.clientCert != nil {
		originCfg.Certificates = []tls.Certificate{*flow.clientCert}
	}
	origin, err := dtls.Dial("udp", raddr, originCfg)
	if err != nil {
		flow.Log(DirProxyToOrigin, LayerWire, ProtoDTLS, nil, map[string]any{"error": err.Error()})
		return
	}
	defer origin.Close()
	if st, ok := origin.ConnectionState(); ok {
		flow.Log(DirProxyToOrigin, LayerPlain, ProtoDTLS, nil, map[string]any{
			"cipher":           st.CipherSuiteID,
			"peer_certs":       peerCertsFromDER(st.PeerCertificates),
			"keylog":           originKeys.Take(),
			"handshake":        "complete",
			"server_name":      host,
			"leaf_private_pem": privatePEM(privateKeyOf(flow.clientCert)),
		})
	}
	_ = splice(flow, ProtoDTLS, client, origin)
}

func privateKeyOf(cert *tls.Certificate) any {
	if cert == nil {
		return nil
	}
	return cert.PrivateKey
}
