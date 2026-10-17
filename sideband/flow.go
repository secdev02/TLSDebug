package sideband

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var errNoCerts = errors.New("sideband: no certificate issuer")

// FlowMeta is what a module knows before it sees a payload.
type FlowMeta struct {
	Network  string
	Client   string
	Upstream string
}

// Packet is one chunk handed to a module after it has been logged.
type Packet struct {
	Direction Direction
	Layer     Layer
	Proto     Proto
	Payload   []byte
	Fields    map[string]any
}

// CertIssuer mints the leaf the client will verify. The HTTP proxy's CA
// implements this. host is a name or IP, without a port.
type CertIssuer interface {
	Certificate(host string) (*tls.Certificate, error)
}

// Module is one Sideband protocol. Detect looks at the first bytes.
// Handshake terminates the client and dials the origin. Forward carries one
// decrypted record, stream chunk, or datagram toward the other side.
type Module interface {
	Name() string
	Detect(prelude []byte, meta FlowMeta) bool
	Handshake(flow *Flow) error
	Forward(flow *Flow, pkt Packet) error
}

// Flow is one client session and the log records that belong to it.
type Flow struct {
	id          uint32
	meta        FlowMeta
	log         *Logger
	upstream    string
	certs       CertIssuer
	originRoots *x509.CertPool
	client      net.Conn
	origin      net.Conn
	prelude     []byte
	mtlsRequire bool
	clientCert  *tls.Certificate
}

func (f *Flow) ID() uint32 { return f.id }

func (f *Flow) Meta() FlowMeta { return f.meta }

func (f *Flow) Upstream() string { return f.upstream }

func (f *Flow) Certs() CertIssuer { return f.certs }

// Log writes one packet for this flow.
func (f *Flow) Log(dir Direction, layer Layer, proto Proto, payload []byte, fields map[string]any) {
	if f == nil || f.log == nil {
		return
	}
	_ = f.log.Write(Record{
		Time:      time.Now(),
		FlowID:    f.id,
		Direction: dir,
		Layer:     layer,
		Proto:     proto,
		Payload:   payload,
		Fields:    fields,
	})
}

// Server accepts Sideband clients. Empty listen addresses are disabled.
type Server struct {
	TCPListen string
	UDPListen string
	Upstream  string
	Certs     CertIssuer
	Log       *Logger
	// OriginRoots, when set, is the trust store for the origin side.
	// Nil uses the system roots.
	OriginRoots *x509.CertPool
	// MTLSRequire asks the client for a certificate and refuses the handshake
	// when one is not presented.
	MTLSRequire bool
	// ClientCert is presented to the origin when mutual TLS is configured.
	ClientCert *tls.Certificate
	// WG, when set, starts the WireGuard dual tunnel.
	WG *WireGuardConfig

	next     atomic.Uint32
	mu       sync.Mutex
	tcpLn    net.Listener
	udpPC    net.PacketConn
	dtlsLn   net.Listener
	quicAddr net.Addr
}

// TCPAddr is the bound TCP listener, or nil before ServeTCP is ready.
func (s *Server) TCPAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tcpLn == nil {
		return nil
	}
	return s.tcpLn.Addr()
}

// UDPAddr is the bound UDP socket, or nil before ServeUDP is ready.
func (s *Server) UDPAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.udpPC == nil {
		return nil
	}
	return s.udpPC.LocalAddr()
}

func (s *Server) newFlow(network, client string) *Flow {
	id := s.next.Add(1)
	return &Flow{
		id: id,
		meta: FlowMeta{
			Network:  network,
			Client:   client,
			Upstream: s.Upstream,
		},
		log:         s.Log,
		upstream:    s.Upstream,
		certs:       s.Certs,
		originRoots: s.OriginRoots,
		mtlsRequire: s.MTLSRequire,
		clientCert:  s.ClientCert,
	}
}

// prefixConn replays bytes already pulled off a stream so a handshake still
// sees them. The HTTP proxy has the same problem on CONNECT.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}
