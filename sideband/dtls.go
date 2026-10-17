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
	ln, err := dtls.Listen("udp", addr, &dtls.Config{
		Certificates: []tls.Certificate{*cert},
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
		go s.handleDTLS(conn, host)
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

func (s *Server) handleDTLS(client net.Conn, host string) {
	defer client.Close()
	flow := s.newFlow("udp", client.RemoteAddr().String())
	raddr, err := net.ResolveUDPAddr("udp", s.Upstream)
	if err != nil {
		flow.Log(DirProxyToOrigin, LayerWire, ProtoDTLS, nil, map[string]any{"error": err.Error()})
		return
	}
	origin, err := dtls.Dial("udp", raddr, &dtls.Config{
		ServerName: host,
		RootCAs:    s.OriginRoots,
	})
	if err != nil {
		flow.Log(DirProxyToOrigin, LayerWire, ProtoDTLS, nil, map[string]any{"error": err.Error()})
		return
	}
	defer origin.Close()
	_ = splice(flow, ProtoDTLS, client, origin)
}
