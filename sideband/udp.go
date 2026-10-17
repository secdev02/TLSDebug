package sideband

import (
	"net"
	"sync"
	"time"
)

// ServeUDP is the raw UDP intercept. Datagrams are copied to the upstream
// and replies are copied back. Each client address is its own flow.
func (s *Server) ServeUDP() error {
	pc, err := net.ListenPacket("udp", s.UDPListen)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.udpPC = pc
	s.mu.Unlock()
	defer pc.Close()
	var mu sync.Mutex
	flows := map[string]*udpFlow{}
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		pkt := append([]byte(nil), buf[:n]...)
		key := addr.String()
		mu.Lock()
		f := flows[key]
		if f == nil {
			flow := s.newFlow("udp", key)
			f = &udpFlow{flow: flow, addr: addr, pc: pc, ch: make(chan []byte, 32)}
			flows[key] = f
			go f.run(s.Upstream)
		}
		mu.Unlock()
		f.push(pkt)
	}
}

type udpFlow struct {
	flow *Flow
	addr net.Addr
	pc   net.PacketConn
	ch   chan []byte
}

func (f *udpFlow) push(pkt []byte) {
	select {
	case f.ch <- pkt:
	default:
		f.flow.Log(DirClientToProxy, LayerWire, ProtoUDP, pkt, map[string]any{"dropped": true})
	}
}

func (f *udpFlow) run(upstream string) {
	origin, err := net.DialTimeout("udp", upstream, 10*time.Second)
	if err != nil {
		f.flow.Log(DirProxyToOrigin, LayerWire, ProtoUDP, nil, map[string]any{"error": err.Error()})
		return
	}
	defer origin.Close()
	go func() {
		buf := make([]byte, 64*1024)
		for {
			_ = origin.SetReadDeadline(time.Now().Add(2 * time.Minute))
			n, err := origin.Read(buf)
			if n > 0 {
				pkt := append([]byte(nil), buf[:n]...)
				f.flow.Log(DirOriginToProxy, LayerWire, ProtoUDP, pkt, nil)
				_, _ = f.pc.WriteTo(pkt, f.addr)
				f.flow.Log(DirProxyToClient, LayerWire, ProtoUDP, pkt, nil)
			}
			if err != nil {
				return
			}
		}
	}()
	for pkt := range f.ch {
		f.flow.Log(DirClientToProxy, LayerWire, ProtoUDP, pkt, nil)
		_, _ = origin.Write(pkt)
		f.flow.Log(DirProxyToOrigin, LayerWire, ProtoUDP, pkt, nil)
	}
}
