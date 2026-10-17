package sideband

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// ServeQUIC terminates QUIC and re-originates it. 0-RTT is off so early data
// cannot pass the proxy before the handshake. Streams and datagrams are relayed
// after decryption. Wire datagrams are logged with the header form and version.
func (s *Server) ServeQUIC(listen string) error {
	pc, err := net.ListenPacket("udp", listen)
	if err != nil {
		return err
	}
	defer pc.Close()
	tr := &quic.Transport{Conn: &quicLogConn{PacketConn: pc, srv: s}}
	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"sideband"},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			name := hello.ServerName
			if name == "" {
				name = serverName(s.Upstream)
			}
			if s.Certs == nil {
				return nil, errNoCerts
			}
			cert, err := s.Certs.Certificate(name)
			if err != nil {
				return nil, err
			}
			protos := hello.SupportedProtos
			if len(protos) == 0 {
				protos = []string{"sideband"}
			}
			auth := tls.RequestClientCert
			if s.MTLSRequire {
				auth = tls.RequireAnyClientCert
			}
			return &tls.Config{
				Certificates: []tls.Certificate{*cert},
				MinVersion:   tls.VersionTLS13,
				NextProtos:   protos,
				ClientAuth:   auth,
				KeyLogWriter: secretDest{s.Log},
			}, nil
		},
	}
	ln, err := tr.Listen(tlsConf, &quic.Config{Allow0RTT: false, EnableDatagrams: true})
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.quicAddr = pc.LocalAddr()
	s.mu.Unlock()
	defer ln.Close()
	ctx := context.Background()
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			return err
		}
		go s.handleQUIC(ctx, conn)
	}
}

// QUICAddr is the bound QUIC socket, or nil before ServeQUIC is ready.
func (s *Server) QUICAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.quicAddr
}

func (s *Server) handleQUIC(ctx context.Context, client *quic.Conn) {
	flow := s.newFlow("udp", client.RemoteAddr().String())
	state := client.ConnectionState()
	alpn := state.TLS.NegotiatedProtocol
	if alpn == "" {
		alpn = "sideband"
	}
	originKeys := flow.log.newCapture()
	originTLS := &tls.Config{
		ServerName:   serverName(s.Upstream),
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{alpn},
		RootCAs:      s.OriginRoots,
		KeyLogWriter: originKeys,
	}
	if flow.clientCert != nil {
		originTLS.Certificates = []tls.Certificate{*flow.clientCert}
	}
	flow.Log(DirClientToProxy, LayerPlain, ProtoQUIC, nil, map[string]any{
		"alpn":        alpn,
		"version":     uint32(state.Version),
		"header":      "handshake",
		"supported":   true,
		"peer_certs":  peerCertFields(state.TLS.PeerCertificates),
		"server_name": state.TLS.ServerName,
	})
	origin, err := quic.DialAddr(ctx, s.Upstream, originTLS, &quic.Config{Allow0RTT: false, EnableDatagrams: true})
	if err != nil {
		flow.Log(DirProxyToOrigin, LayerWire, ProtoQUIC, nil, map[string]any{"error": err.Error()})
		_ = client.CloseWithError(0, err.Error())
		return
	}
	defer origin.CloseWithError(0, "sideband done")
	defer client.CloseWithError(0, "sideband done")
	flow.Log(DirProxyToOrigin, LayerPlain, ProtoQUIC, nil, map[string]any{
		"handshake":        "complete",
		"keylog":           originKeys.Take(),
		"peer_certs":       peerCertFields(origin.ConnectionState().TLS.PeerCertificates),
		"leaf_private_pem": privatePEM(privateKeyOf(flow.clientCert)),
		"header":           "handshake",
		"supported":        true,
		"version":          uint32(origin.ConnectionState().Version),
	})

	go relayDatagrams(flow, client, origin)
	for {
		stream, err := client.AcceptStream(ctx)
		if err != nil {
			return
		}
		go relayQUICStream(ctx, flow, origin, stream)
	}
}

func relayQUICStream(ctx context.Context, flow *Flow, origin *quic.Conn, client *quic.Stream) {
	defer client.Close()
	out, err := origin.OpenStreamSync(ctx)
	if err != nil {
		return
	}
	defer out.Close()
	flow.Log(DirClientToProxy, LayerPlain, ProtoQUIC, nil, map[string]any{"stream": uint64(client.StreamID())})
	_ = splice(flow, ProtoQUIC, streamConn{client}, streamConn{out})
}

func relayDatagrams(flow *Flow, client, origin *quic.Conn) {
	go func() {
		for {
			msg, err := client.ReceiveDatagram(context.Background())
			if err != nil {
				return
			}
			flow.Log(DirClientToProxy, LayerPlain, ProtoQUIC, msg, map[string]any{"datagram": true})
			_ = origin.SendDatagram(msg)
		}
	}()
	for {
		msg, err := origin.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		flow.Log(DirOriginToProxy, LayerPlain, ProtoQUIC, msg, map[string]any{"datagram": true})
		_ = client.SendDatagram(msg)
	}
}

type quicLogConn struct {
	net.PacketConn
	srv *Server
}

func (c *quicLogConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if n > 0 {
			fields := quicHeaderFields(p[:n])
			if c.srv.Log != nil {
				_ = c.srv.Log.Write(Record{
					FlowID:    0,
					Direction: DirClientToProxy,
					Layer:     LayerWire,
					Proto:     ProtoQUIC,
					Payload:   append([]byte(nil), p[:n]...),
					Fields:    fields,
				})
			}
			if supported, ok := fields["supported"].(bool); ok && !supported {
				continue
			}
		}
		return n, addr, err
	}
}

func (c *quicLogConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.srv.Log != nil && len(p) > 0 {
		_ = c.srv.Log.Write(Record{
			Direction: DirProxyToClient,
			Layer:     LayerWire,
			Proto:     ProtoQUIC,
			Payload:   append([]byte(nil), p...),
			Fields:    quicHeaderFields(p),
		})
	}
	return c.PacketConn.WriteTo(p, addr)
}

// quicHeaderFields reads the header form and, for a long header, the version.
func quicHeaderFields(pkt []byte) map[string]any {
	if len(pkt) == 0 {
		return nil
	}
	fields := map[string]any{"first": pkt[0]}
	if pkt[0]&0x80 != 0 {
		fields["header"] = "long"
		if len(pkt) >= 5 {
			version := binary.BigEndian.Uint32(pkt[1:5])
			fields["version"] = version
			// Version 0 is a version negotiation packet. v1 and v2 are the ones we terminate.
			fields["supported"] = version == 0 || version == 0x00000001 || version == 0x6b3343cf
		}
		if len(pkt) >= 6 {
			dcil := int(pkt[5])
			if dcil <= 20 && len(pkt) >= 6+dcil+1 {
				fields["dcid"] = pkt[6 : 6+dcil]
				scil := int(pkt[6+dcil])
				if scil <= 20 && len(pkt) >= 7+dcil+scil {
					fields["scid"] = pkt[7+dcil : 7+dcil+scil]
				}
			}
		}
		return fields
	}
	fields["header"] = "short"
	fields["supported"] = true
	return fields
}

func serverName(upstream string) string {
	host, _, err := net.SplitHostPort(upstream)
	if err != nil {
		return upstream
	}
	return host
}

// streamConn lets a QUIC stream pass through splice.
type streamConn struct {
	io.ReadWriteCloser
}

func (c streamConn) LocalAddr() net.Addr              { return sidebandAddr{} }
func (c streamConn) RemoteAddr() net.Addr             { return sidebandAddr{} }
func (c streamConn) SetDeadline(time.Time) error      { return nil }
func (c streamConn) SetReadDeadline(time.Time) error  { return nil }
func (c streamConn) SetWriteDeadline(time.Time) error { return nil }

type sidebandAddr struct{}

func (sidebandAddr) Network() string { return "sideband" }
func (sidebandAddr) String() string  { return "sideband" }
