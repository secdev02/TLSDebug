package sideband

import (
	"net"
	"time"
)

// tcpModule, tlsModule, and starttlsModule are the TCP-side modules.
// UDP, DTLS, QUIC, and WireGuard have their own listeners because those
// stacks own the packet socket. They still implement Module so detection
// and forwarding go through one interface.

type tcpModule struct{}

func (tcpModule) Name() string { return "tcp" }

func (tcpModule) Detect(prelude []byte, _ FlowMeta) bool {
	return classifyTCP(prelude) == ProtoTCP
}

func (tcpModule) Handshake(flow *Flow) error {
	origin, err := net.DialTimeout("tcp", flow.Upstream(), 10*time.Second)
	if err != nil {
		flow.Log(DirProxyToOrigin, LayerWire, ProtoTCP, nil, map[string]any{"error": err.Error()})
		return err
	}
	flow.origin = origin
	return nil
}

func (m tcpModule) Forward(flow *Flow, pkt Packet) error {
	return writeLogged(flow, pkt, flow.peer(pkt.Direction))
}

type tlsModule struct{}

func (tlsModule) Name() string { return "tls" }

func (tlsModule) Detect(prelude []byte, _ FlowMeta) bool {
	return classifyTCP(prelude) == ProtoTLS
}

func (tlsModule) Handshake(flow *Flow) error { return interceptTLS(flow, flow.client) }

func (tlsModule) Forward(flow *Flow, pkt Packet) error { return writeLogged(flow, pkt, nil) }

type starttlsModule struct{ kind string }

func (m starttlsModule) Name() string { return "starttls" }

func (m starttlsModule) Detect(prelude []byte, _ FlowMeta) bool {
	return classifyTCP(prelude) == ProtoSTARTTLS || starttlsKind(prelude) != "" || ldapStartTLS(prelude)
}

func (m starttlsModule) Handshake(flow *Flow) error {
	if ldapStartTLS(flow.prelude) || isPostgresSSLRequest(flow.prelude) {
		return interceptPostgres(flow, flow.client)
	}
	return interceptSTARTTLS(flow, flow.client, flow.origin, m.kind)
}

func (m starttlsModule) Forward(flow *Flow, pkt Packet) error { return writeLogged(flow, pkt, nil) }

type udpModule struct{}

func (udpModule) Name() string { return "udp" }

func (udpModule) Detect(prelude []byte, _ FlowMeta) bool { return classifyUDP(prelude) == ProtoUDP }

func (udpModule) Handshake(flow *Flow) error { return nil }

func (udpModule) Forward(flow *Flow, pkt Packet) error {
	fields := pkt.Fields
	if fields == nil {
		fields = map[string]any{}
	}
	fields["len"] = len(pkt.Payload)
	fields["client"] = flow.meta.Client
	fields["upstream"] = flow.upstream
	pkt.Fields = fields
	return writeLogged(flow, pkt, nil)
}

type dtlsModule struct{}

func (dtlsModule) Name() string { return "dtls" }

func (dtlsModule) Detect(prelude []byte, _ FlowMeta) bool { return classifyUDP(prelude) == ProtoDTLS }

func (dtlsModule) Handshake(flow *Flow) error { return nil }

func (dtlsModule) Forward(flow *Flow, pkt Packet) error {
	if pkt.Fields == nil {
		pkt.Fields = dtlsRecordFields(pkt.Payload)
	}
	return writeLogged(flow, pkt, nil)
}

type quicModule struct{}

func (quicModule) Name() string { return "quic" }

func (quicModule) Detect(prelude []byte, _ FlowMeta) bool {
	return classifyUDP(prelude) == ProtoQUIC
}

func (quicModule) Handshake(flow *Flow) error { return nil }

func (quicModule) Forward(flow *Flow, pkt Packet) error {
	if pkt.Fields == nil {
		pkt.Fields = quicHeaderFields(pkt.Payload)
	}
	if v, ok := pkt.Fields["supported"].(bool); ok && !v {
		flow.Log(pkt.Direction, pkt.Layer, ProtoQUIC, pkt.Payload, pkt.Fields)
		return nil
	}
	return writeLogged(flow, pkt, nil)
}

type wireguardModule struct{}

func (wireguardModule) Name() string { return "wireguard" }

func (wireguardModule) Detect(prelude []byte, _ FlowMeta) bool {
	return classifyUDP(prelude) == ProtoWireGuard
}

func (wireguardModule) Handshake(flow *Flow) error { return nil }

func (wireguardModule) Forward(flow *Flow, pkt Packet) error {
	if pkt.Fields == nil {
		pkt.Fields = wireguardFields(pkt.Payload)
	}
	return writeLogged(flow, pkt, nil)
}

func writeLogged(flow *Flow, pkt Packet, dst net.Conn) error {
	flow.Log(pkt.Direction, pkt.Layer, pkt.Proto, pkt.Payload, pkt.Fields)
	if dst == nil {
		return nil
	}
	_, err := dst.Write(pkt.Payload)
	return err
}

func (f *Flow) peer(dir Direction) net.Conn {
	switch dir {
	case DirClientToProxy, DirProxyToOrigin:
		return f.origin
	default:
		return f.client
	}
}
