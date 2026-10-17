package sideband

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// WireGuardConfig is the two key pairs Sideband needs. WireGuard has no
// certificate authority, so the client must peer with the client-facing
// public key, and the real peer must accept the origin-facing public key.
type WireGuardConfig struct {
	ClientPrivate  string
	ClientListen   int
	ClientPeer     string
	ClientAllowed  []string
	OriginPrivate  string
	OriginPeer     string
	OriginEndpoint string
	OriginAllowed  []string
}

// LoadWireGuardConfig reads an ini file with [client] and [origin] sections.
// Keys are standard base64 WireGuard keys.
func LoadWireGuardConfig(path string) (*WireGuardConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cfg := &WireGuardConfig{}
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		switch section {
		case "client":
			switch key {
			case "private_key":
				cfg.ClientPrivate = val
			case "listen_port":
				fmt.Sscanf(val, "%d", &cfg.ClientListen)
			case "peer_public_key":
				cfg.ClientPeer = val
			case "allowed_ips":
				cfg.ClientAllowed = splitList(val)
			}
		case "origin":
			switch key {
			case "private_key":
				cfg.OriginPrivate = val
			case "peer_public_key":
				cfg.OriginPeer = val
			case "endpoint":
				cfg.OriginEndpoint = val
			case "allowed_ips":
				cfg.OriginAllowed = splitList(val)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if cfg.ClientPrivate == "" || cfg.OriginPrivate == "" || cfg.OriginEndpoint == "" {
		return nil, fmt.Errorf("sideband: wireguard config needs client and origin keys and an origin endpoint")
	}
	if cfg.ClientListen == 0 {
		cfg.ClientListen = 51820
	}
	if len(cfg.ClientAllowed) == 0 {
		cfg.ClientAllowed = []string{"0.0.0.0/0", "::/0"}
	}
	if len(cfg.OriginAllowed) == 0 {
		cfg.OriginAllowed = []string{"0.0.0.0/0", "::/0"}
	}
	return cfg, nil
}

func splitList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// startUserspace brings up one WireGuard device on an in-memory TUN.
func startUserspace(ipc string) (*device.Device, *chanTUN, error) {
	tunDev := newChanTUN()
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "sideband-wg "))
	if err := dev.IpcSet(ipc); err != nil {
		dev.Close()
		return nil, nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, nil, err
	}
	return dev, tunDev, nil
}

// ServeWireGuard runs two userspace tunnels and copies decrypted IP packets
// from one to the other. Each copied packet is logged with its IP header.
func (s *Server) ServeWireGuard(cfg *WireGuardConfig) error {
	clientTUN := newChanTUN()
	originTUN := newChanTUN()
	logger := device.NewLogger(device.LogLevelError, "sideband-wg ")
	clientDev := device.NewDevice(clientTUN, conn.NewDefaultBind(), logger)
	originDev := device.NewDevice(originTUN, conn.NewDefaultBind(), logger)
	if err := clientDev.IpcSet(wgIPC(cfg.ClientPrivate, cfg.ClientListen, cfg.ClientPeer, "", cfg.ClientAllowed)); err != nil {
		return err
	}
	if err := originDev.IpcSet(wgIPC(cfg.OriginPrivate, 0, cfg.OriginPeer, cfg.OriginEndpoint, cfg.OriginAllowed)); err != nil {
		return err
	}
	if err := clientDev.Up(); err != nil {
		return err
	}
	if err := originDev.Up(); err != nil {
		return err
	}
	flow := s.newFlow("udp", fmt.Sprintf("wireguard:%d", cfg.ClientListen))
	writeWGKeys(s.Log, flow, cfg)
	go bridgeTUN(flow, DirClientToProxy, clientTUN, originTUN)
	go bridgeTUN(flow, DirOriginToProxy, originTUN, clientTUN)
	select {}
}

func writeWGKeys(log *Logger, flow *Flow, cfg *WireGuardConfig) {
	if cfg == nil {
		return
	}
	text := "WIREGUARD_CLIENT_PRIVATE " + cfg.ClientPrivate + "\nWIREGUARD_ORIGIN_PRIVATE " + cfg.OriginPrivate + "\n"
	_ = log.WriteSecrets(text)
	if flow != nil {
		flow.Log(DirClientToProxy, LayerPlain, ProtoWireGuard, nil, map[string]any{
			"client_private_key": cfg.ClientPrivate,
			"origin_private_key": cfg.OriginPrivate,
		})
	}
}

func bridgeTUN(flow *Flow, dir Direction, src, dst *chanTUN) {
	for pkt := range src.fromDev {
		flow.Log(dir, LayerPlain, ProtoWireGuard, pkt, ipFields(pkt))
		dst.toDev <- pkt
	}
}

func wgIPC(private string, listen int, peer, endpoint string, allowed []string) string {
	priv, _ := keyHex(private)
	pub, _ := keyHex(peer)
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", priv)
	if listen > 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", listen)
	}
	fmt.Fprintf(&b, "public_key=%s\n", pub)
	if endpoint != "" {
		fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	}
	for _, cidr := range allowed {
		fmt.Fprintf(&b, "allowed_ip=%s\n", cidr)
	}
	return b.String()
}

func keyHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// wireguardFields reads the message type and, for transport data, the receiver index.
func wireguardFields(pkt []byte) map[string]any {
	if len(pkt) < 1 {
		return nil
	}
	fields := map[string]any{"type": pkt[0]}
	switch pkt[0] {
	case 1:
		fields["message"] = "initiation"
	case 2:
		fields["message"] = "response"
	case 3:
		fields["message"] = "cookie"
	case 4:
		fields["message"] = "transport"
		if len(pkt) >= 8 {
			fields["receiver"] = binaryUint32(pkt[4:8])
		}
		if len(pkt) >= 16 {
			fields["counter"] = binaryUint64(pkt[8:16])
		}
	}
	return fields
}

func binaryUint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func binaryUint64(b []byte) uint64 {
	var n uint64
	for i := 0; i < 8; i++ {
		n |= uint64(b[i]) << (8 * i)
	}
	return n
}

func ipFields(pkt []byte) map[string]any {
	wg := wireguardFields(pkt)
	if len(pkt) == 0 {
		return wg
	}
	ver := pkt[0] >> 4
	if ver == 4 && len(pkt) >= 20 {
		return map[string]any{
			"ip":    4,
			"src":   net.IP(pkt[12:16]).String(),
			"dst":   net.IP(pkt[16:20]).String(),
			"proto": pkt[9],
		}
	}
	if ver == 6 && len(pkt) >= 40 {
		return map[string]any{
			"ip":   6,
			"src":  net.IP(pkt[8:24]).String(),
			"dst":  net.IP(pkt[24:40]).String(),
			"next": pkt[6],
		}
	}
	if wg != nil {
		return wg
	}
	return map[string]any{"len": len(pkt)}
}

// chanTUN is an in-memory tun.Device. WireGuard reads toDev to encrypt and
// writes decrypted packets to fromDev.
type chanTUN struct {
	toDev   chan []byte
	fromDev chan []byte
	events  chan tun.Event
	closed  chan struct{}
}

func newChanTUN() *chanTUN {
	t := &chanTUN{
		toDev:   make(chan []byte, 64),
		fromDev: make(chan []byte, 64),
		events:  make(chan tun.Event, 1),
		closed:  make(chan struct{}),
	}
	t.events <- tun.EventUp
	return t
}

func (t *chanTUN) File() *os.File { return nil }

func (t *chanTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	case pkt := <-t.toDev:
		n := copy(bufs[0][offset:], pkt)
		sizes[0] = n
		return 1, nil
	}
}

func (t *chanTUN) Write(bufs [][]byte, offset int) (int, error) {
	for i, buf := range bufs {
		pkt := append([]byte(nil), buf[offset:]...)
		select {
		case <-t.closed:
			return i, os.ErrClosed
		case t.fromDev <- pkt:
		}
	}
	return len(bufs), nil
}

func (t *chanTUN) MTU() (int, error)        { return 1420, nil }
func (t *chanTUN) Name() (string, error)    { return "sideband", nil }
func (t *chanTUN) Events() <-chan tun.Event { return t.events }
func (t *chanTUN) BatchSize() int           { return 1 }
func (t *chanTUN) Close() error {
	select {
	case <-t.closed:
	default:
		close(t.closed)
	}
	return nil
}
