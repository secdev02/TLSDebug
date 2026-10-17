package sideband

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"time"
)

// ServeTCP accepts clients and intercepts each one.
// The first bytes choose TLS, STARTTLS, or raw TCP. The upstream address
// is the origin for every flow on this listener.
func (s *Server) ServeTCP() error {
	ln, err := net.Listen("tcp", s.TCPListen)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.tcpLn = ln
	s.mu.Unlock()
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}
		go s.handleTCP(conn)
	}
}

func (s *Server) handleTCP(conn net.Conn) {
	defer conn.Close()
	flow := s.newFlow("tcp", conn.RemoteAddr().String())
	br := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	peek, _ := br.Peek(8)
	_ = conn.SetReadDeadline(time.Time{})
	// Peek leaves the bytes in the buffer. readerConn reads them back.
	stream := &readerConn{Conn: conn, r: br}

	switch classifyTCP(peek) {
	case ProtoTLS:
		_ = interceptTLS(flow, stream)
		return
	case ProtoSTARTTLS:
		_ = interceptPostgres(flow, stream)
		return
	}

	if len(peek) == 0 {
		origin, err := net.DialTimeout("tcp", flow.Upstream(), 10*time.Second)
		if err != nil {
			flow.Log(DirProxyToOrigin, LayerWire, ProtoTCP, nil, map[string]any{"error": err.Error()})
			return
		}
		defer origin.Close()
		obr := bufio.NewReader(origin)
		_ = origin.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		banner, _ := obr.Peek(64)
		_ = origin.SetReadDeadline(time.Time{})
		if kind := starttlsKind(banner); kind != "" {
			bannerLine, err := obr.ReadBytes('\n')
			if err != nil && len(bannerLine) == 0 {
				return
			}
			if _, err := stream.Write(bannerLine); err != nil {
				return
			}
			flow.Log(DirProxyToClient, LayerPlain, ProtoSTARTTLS, bannerLine, map[string]any{"application": kind, "phase": "banner"})
			_ = interceptSTARTTLS(flow, stream, &readerConn{Conn: origin, r: obr}, kind)
			return
		}
		_ = splice(flow, ProtoTCP, stream, &readerConn{Conn: origin, r: obr})
		return
	}
	_ = interceptRawTCP(flow, stream)
}

func interceptRawTCP(flow *Flow, client net.Conn) error {
	origin, err := net.DialTimeout("tcp", flow.Upstream(), 10*time.Second)
	if err != nil {
		flow.Log(DirProxyToOrigin, LayerWire, ProtoTCP, nil, map[string]any{"error": err.Error()})
		return err
	}
	defer origin.Close()
	return splice(flow, ProtoTCP, client, origin)
}

// readerConn is a net.Conn whose reads come from an already-buffered reader.
type readerConn struct {
	net.Conn
	r io.Reader
}

func (c *readerConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// teeConn logs wire bytes as TLS or DTLS consumes them.
type teeConn struct {
	net.Conn
	flow  *Flow
	proto Proto
}

func (c *teeConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.flow.Log(DirClientToProxy, LayerWire, c.proto, p[:n], nil)
	}
	return n, err
}

func (c *teeConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.flow.Log(DirProxyToClient, LayerWire, c.proto, p[:n], nil)
	}
	return n, err
}

func tlsServerConfig(flow *Flow) (*tls.Config, error) {
	host, _, err := net.SplitHostPort(flow.Upstream())
	if err != nil {
		host = flow.Upstream()
	}
	if flow.Certs() == nil {
		return nil, errors.New("sideband: no certificate issuer")
	}
	cert, err := flow.Certs().Certificate(host)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"sideband"},
	}, nil
}

func tlsClientConfig(flow *Flow) *tls.Config {
	host, _, err := net.SplitHostPort(flow.Upstream())
	if err != nil {
		host = flow.Upstream()
	}
	return &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"sideband"},
		RootCAs:    flow.originRoots,
	}
}
