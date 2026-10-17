package sideband

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/curve25519"
)

func TestLoggerRoundTrip(t *testing.T) {
	dir := t.TempDir()
	log, err := OpenLogger(dir)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("hello sideband")
	if err := log.Write(Record{
		FlowID:    7,
		Direction: DirClientToProxy,
		Layer:     LayerPlain,
		Proto:     ProtoTCP,
		Payload:   payload,
		Fields:    map[string]any{"k": "v"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(dir, "packets.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var rec jsonRecord
	if err := json.NewDecoder(f).Decode(&rec); err != nil {
		t.Fatal(err)
	}
	if rec.FlowID != 7 || rec.Proto != "tcp" || rec.Direction != "client_to_proxy" || rec.BinLength != len(payload) {
		t.Fatalf("json = %+v", rec)
	}
	got, err := ReadPayload(filepath.Join(dir, "packets.bin"), rec.BinOffset, rec.BinLength)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload = %q", got)
	}
	raw, err := base64.StdEncoding.DecodeString(rec.PayloadB64)
	if err != nil || string(raw) != string(payload) {
		t.Fatalf("inline = %q err=%v", raw, err)
	}
	info, err := os.Stat(filepath.Join(dir, "packets.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
}

func TestClassify(t *testing.T) {
	if classifyTCP([]byte{22, 3, 1, 0, 1}) != ProtoTLS {
		t.Fatal("tls")
	}
	if classifyTCP([]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}) != ProtoSTARTTLS {
		t.Fatal("postgres")
	}
	if classifyTCP([]byte("GET /")) != ProtoTCP {
		t.Fatal("raw tcp")
	}
	if classifyUDP([]byte{4, 0, 0, 0}) != ProtoWireGuard {
		t.Fatal("wg")
	}
	if classifyUDP([]byte{22, 0xfe, 0xfd}) != ProtoDTLS {
		t.Fatal("dtls")
	}
	if classifyUDP([]byte{0xc0, 0, 0, 0, 1}) != ProtoQUIC {
		t.Fatal("quic long")
	}
	if classifyUDP([]byte{0x40, 1, 2}) != ProtoQUIC {
		t.Fatal("quic short")
	}
	if classifyUDP([]byte{0x00, 1}) != ProtoUDP {
		t.Fatal("udp")
	}
	if starttlsKind([]byte("220 mail.example ESMTP ready\r\n")) != "smtp" {
		t.Fatal("smtp")
	}
	fields := quicHeaderFields([]byte{0xc3, 0, 0, 0, 1, 0})
	if fields["header"] != "long" || fields["version"] != uint32(1) {
		t.Fatalf("quic fields = %v", fields)
	}
	wg := wireguardFields([]byte{4, 0, 0, 0, 1, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0})
	if wg["message"] != "transport" || wg["receiver"] != uint32(1) || wg["counter"] != uint64(9) {
		t.Fatalf("wg fields = %v", wg)
	}
	for _, typ := range []byte{1, 2, 3, 4} {
		f := wireguardFields([]byte{typ, 0, 0, 0})
		if f["type"] != typ {
			t.Fatalf("type %d = %v", typ, f)
		}
	}
	tlsFields := tlsRecordFields([]byte{22, 3, 3, 0, 1, 1})
	if tlsFields["content_type"] != byte(22) || tlsFields["handshake_type"] != byte(1) || tlsFields["version"] != uint16(0x0303) {
		t.Fatalf("tls record = %v", tlsFields)
	}
	dtlsFields := dtlsRecordFields([]byte{22, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 7, 0, 1, 1})
	if dtlsFields["epoch"] != uint16(1) || dtlsFields["sequence"] != uint64(7) || dtlsFields["handshake_type"] != byte(1) {
		t.Fatalf("dtls record = %v", dtlsFields)
	}
	if !quicHeaderFields([]byte{0xc0, 0x6b, 0x33, 0x43, 0xcf})["supported"].(bool) {
		t.Fatal("quic v2 should be supported")
	}
	if quicHeaderFields([]byte{0xc0, 0, 0, 0, 0x99})["supported"].(bool) {
		t.Fatal("unknown quic version was supported")
	}
	if !ldapStartTLS([]byte("oid 1.3.6.1.4.1.1466.20037")) {
		t.Fatal("ldap oid")
	}
	meta := FlowMeta{Network: "tcp"}
	if !(tlsModule{}).Detect([]byte{22, 3, 1}, meta) || (tlsModule{}).Name() != "tls" {
		t.Fatal("tls module")
	}
	if !(tcpModule{}).Detect([]byte("GET"), meta) {
		t.Fatal("tcp module")
	}
	flow := &Flow{id: 1, meta: meta, upstream: "example:1"}
	if err := (tcpModule{}).Forward(flow, Packet{Direction: DirClientToProxy, Layer: LayerPlain, Proto: ProtoTCP, Payload: []byte("a")}); err != nil {
		t.Fatal(err)
	}
}

func TestDTLSEcho(t *testing.T) {
	ca, caKey, pool := testCA(t)
	cert := leaf(t, ca, caKey, "127.0.0.1")
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := dtls.Listen("udp", addr, &dtls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	dir := t.TempDir()
	logw, err := OpenLogger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer logw.Close()
	s := &Server{Upstream: ln.Addr().String(), Log: logw, Certs: staticIssuer{cert: cert}, OriginRoots: pool}
	go func() { _ = s.ServeDTLS("127.0.0.1:0") }()
	bound := waitAddr(t, s.DTLSAddr)
	raddr, _ := net.ResolveUDPAddr("udp", bound.String())
	conn, err := dtls.Dial("udp", raddr, &dtls.Config{RootCAs: pool, ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("dtls")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "dtls" {
		t.Fatalf("echo = %q", buf)
	}
	if !strings.Contains(keysText(t, dir), "BEGIN PRIVATE KEY") && !hasSecretLine(keysText(t, dir)) {
		t.Fatal("dtls key log missing key material")
	}
	dtlsFields := dtlsRecordFields([]byte{22, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 7, 0, 1, 1})
	if dtlsFields["epoch"] != uint16(1) || dtlsFields["sequence"] != uint64(7) {
		t.Fatalf("dtls wire header = %v", dtlsFields)
	}
}

func TestQUICEcho(t *testing.T) {
	ca, caKey, pool := testCA(t)
	cert := leaf(t, ca, caKey, "127.0.0.1")
	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"sideband"},
	}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept(t.Context())
			if err != nil {
				return
			}
			go func() {
				defer c.CloseWithError(0, "done")
				st, err := c.AcceptStream(t.Context())
				if err != nil {
					return
				}
				defer st.Close()
				io.Copy(st, st)
			}()
		}
	}()
	dir := t.TempDir()
	logw, err := OpenLogger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer logw.Close()
	s := &Server{Upstream: ln.Addr().String(), Log: logw, Certs: staticIssuer{cert: cert}, OriginRoots: pool}
	go func() { _ = s.ServeQUIC("127.0.0.1:0") }()
	bound := waitAddr(t, s.QUICAddr)
	clientPool := x509.NewCertPool()
	clientPool.AddCert(ca)
	conn, err := quic.DialAddr(t.Context(), bound.String(), &tls.Config{
		RootCAs:    clientPool,
		ServerName: "127.0.0.1",
		NextProtos: []string{"sideband"},
	}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "done")
	st, err := conn.OpenStreamSync(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte("quic")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	st.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "quic" {
		t.Fatalf("echo = %q", buf)
	}
	foundQUIC := false
	for _, rec := range readRecords(t, dir) {
		if rec.Proto != "quic" {
			continue
		}
		if rec.Fields["header"] != nil && rec.Fields["supported"] == true {
			foundQUIC = true
		}
	}
	if !foundQUIC {
		t.Fatal("quic log missing header or supported version")
	}
	if keysText(t, dir) == "" {
		t.Fatal("quic key log is empty")
	}
}

func TestWireGuardLoopback(t *testing.T) {
	proxyPort := freeUDPPort(t)
	serverPort := freeUDPPort(t)
	userPriv, userPub := wgPair(t)
	proxyCPriv, proxyCPub := wgPair(t)
	proxyOPriv, proxyOPub := wgPair(t)
	srvPriv, srvPub := wgPair(t)

	srvDev, srvTUN, err := startUserspace(wgIPC(srvPriv, serverPort, proxyOPub, "", []string{"0.0.0.0/0"}) + "persistent_keepalive_interval=1\n")
	if err != nil {
		t.Fatal(err)
	}
	defer srvDev.Close()
	proxyClient, proxyClientTUN, err := startUserspace(wgIPC(proxyCPriv, proxyPort, userPub, "", []string{"0.0.0.0/0"}))
	if err != nil {
		t.Fatal(err)
	}
	defer proxyClient.Close()
	proxyOrigin, proxyOriginTUN, err := startUserspace(wgIPC(proxyOPriv, 0, srvPub, fmt.Sprintf("127.0.0.1:%d", serverPort), []string{"0.0.0.0/0"}) + "persistent_keepalive_interval=1\n")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyOrigin.Close()
	userDev, userTUN, err := startUserspace(wgIPC(userPriv, 0, proxyCPub, fmt.Sprintf("127.0.0.1:%d", proxyPort), []string{"0.0.0.0/0"}) + "persistent_keepalive_interval=1\n")
	if err != nil {
		t.Fatal(err)
	}
	defer userDev.Close()

	dir := t.TempDir()
	logw, err := OpenLogger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer logw.Close()
	flow := &Flow{id: 1, log: logw, meta: FlowMeta{Client: "wireguard", Upstream: fmt.Sprintf("127.0.0.1:%d", serverPort)}, upstream: fmt.Sprintf("127.0.0.1:%d", serverPort)}
	go bridgeTUN(flow, DirClientToProxy, proxyClientTUN, proxyOriginTUN)
	go bridgeTUN(flow, DirOriginToProxy, proxyOriginTUN, proxyClientTUN)
	time.Sleep(300 * time.Millisecond)

	pkt := make([]byte, 20)
	pkt[0] = 0x45
	pkt[2] = 0
	pkt[3] = 20
	pkt[9] = 17
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})
	userTUN.toDev <- pkt
	writeWGKeys(logw, flow, &WireGuardConfig{ClientPrivate: userPriv, OriginPrivate: proxyOPriv})

	select {
	case got := <-srvTUN.fromDev:
		if len(got) < 20 || got[0]>>4 != 4 {
			t.Fatalf("inner packet = %x", got)
		}
		foundIP := false
		for _, rec := range readRecords(t, dir) {
			if rec.Fields["ip"] == float64(4) && rec.Fields["src"] == "10.0.0.1" && rec.Fields["dst"] == "10.0.0.2" {
				foundIP = true
			}
		}
		if !foundIP {
			t.Fatal("wireguard json missing inner addresses")
		}
		keys := keysText(t, dir)
		if !strings.Contains(keys, userPriv) || !strings.Contains(keys, proxyOPriv) {
			t.Fatal("wireguard key log missing private keys")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("wireguard packet did not cross the proxy")
	}
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	return port
}

func wgPair(t *testing.T) (privB64, pubB64 string) {
	t.Helper()
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub)
}

func TestTCPEcho(t *testing.T) {
	origin := echoServer(t, "tcp")
	dir := t.TempDir()
	log, err := OpenLogger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	s := &Server{TCPListen: "127.0.0.1:0", Upstream: origin, Log: log}
	go s.ServeTCP()
	addr := waitAddr(t, s.TCPAddr)
	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q", buf)
	}
	rec := findRecord(readRecords(t, dir), "tcp", []byte("ping"), dir, t)
	if rec.Fields["len"] == nil || rec.Fields["offset"] == nil {
		t.Fatalf("tcp fields = %v", rec.Fields)
	}
}

func TestUDPEcho(t *testing.T) {
	origin := echoServer(t, "udp")
	dir := t.TempDir()
	log, err := OpenLogger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	s := &Server{UDPListen: "127.0.0.1:0", Upstream: origin, Log: log}
	go func() { _ = s.ServeUDP() }()
	addr := waitAddr(t, s.UDPAddr)
	conn, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "pong" {
		t.Fatalf("echo = %q", buf[:n])
	}
	rec := findRecord(readRecords(t, dir), "udp", []byte("pong"), dir, t)
	if rec.Fields["len"] == nil || rec.Fields["client"] == nil {
		t.Fatalf("udp fields = %v", rec.Fields)
	}
}

func TestTLSEcho(t *testing.T) {
	ca, caKey, caPool := testCA(t)
	originCert := leaf(t, ca, caKey, "127.0.0.1")
	origin := tlsEcho(t, originCert)
	dir := t.TempDir()
	logw, err := OpenLogger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer logw.Close()
	s := &Server{
		TCPListen:   "127.0.0.1:0",
		Upstream:    origin,
		Log:         logw,
		Certs:       staticIssuer{cert: leaf(t, ca, caKey, "127.0.0.1")},
		OriginRoots: caPool,
	}
	go s.ServeTCP()
	addr := waitAddr(t, s.TCPAddr)
	clientCertPool := x509.NewCertPool()
	clientCertPool.AddCert(ca)
	conn, err := tls.Dial("tcp", addr.String(), &tls.Config{
		RootCAs:    clientCertPool,
		ServerName: "127.0.0.1",
		NextProtos: []string{"sideband"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("tls!")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "tls!" {
		t.Fatalf("echo = %q", buf)
	}
	recs := readRecords(t, dir)
	found := false
	for _, rec := range recs {
		if rec.Fields["server_name"] == "127.0.0.1" && rec.Fields["cipher"] != nil && strings.Contains(stringField(rec.Fields["leaf_private_pem"]), "BEGIN PRIVATE KEY") {
			found = true
		}
	}
	if !found {
		t.Fatal("tls handshake log missing server name, cipher, or leaf key")
	}
	if !hasSecretLine(keysText(t, dir)) {
		t.Fatal("tls key log missing a session secret")
	}
}

func TestSTARTTLS(t *testing.T) {
	ca, caKey, caPool := testCA(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Write([]byte("220 localhost ESMTP ready\r\n"))
		br := bufio.NewReader(c)
		line, _ := br.ReadString('\n')
		if line != "EHLO me\r\n" {
			c.Write([]byte("500 no\r\n"))
			return
		}
		c.Write([]byte("250-localhost\r\n250 STARTTLS\r\n"))
		line, _ = br.ReadString('\n')
		if line != "STARTTLS\r\n" {
			c.Write([]byte("500 no\r\n"))
			return
		}
		c.Write([]byte("220 go ahead\r\n"))
		tlsConn := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{leaf(t, ca, caKey, "127.0.0.1")}})
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		buf := make([]byte, 4)
		io.ReadFull(tlsConn, buf)
		tlsConn.Write(buf)
	}()

	dir := t.TempDir()
	logw, err := OpenLogger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer logw.Close()
	s := &Server{
		TCPListen:   "127.0.0.1:0",
		Upstream:    ln.Addr().String(),
		Log:         logw,
		Certs:       staticIssuer{cert: leaf(t, ca, caKey, "127.0.0.1")},
		OriginRoots: caPool,
	}
	go s.ServeTCP()
	addr := waitAddr(t, s.TCPAddr)
	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	banner, err := br.ReadString('\n')
	if err != nil || banner == "" {
		t.Fatal(err)
	}
	conn.Write([]byte("EHLO me\r\n"))
	br.ReadString('\n')
	br.ReadString('\n')
	conn.Write([]byte("STARTTLS\r\n"))
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	tlsConn := tls.Client(conn, &tls.Config{RootCAs: func() *x509.CertPool { p := x509.NewCertPool(); p.AddCert(ca); return p }(), ServerName: "127.0.0.1"})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	tlsConn.Write([]byte("mail"))
	buf := make([]byte, 4)
	tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(tlsConn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "mail" {
		t.Fatalf("echo = %q", buf)
	}
	found := false
	for _, rec := range readRecords(t, dir) {
		if rec.Fields["server_name"] == "127.0.0.1" && rec.Fields["cipher"] != nil {
			found = true
		}
	}
	if !found {
		t.Fatal("starttls handshake was not logged")
	}
	if !strings.Contains(keysText(t, dir), "BEGIN PRIVATE KEY") {
		t.Fatal("starttls key log missing leaf private key")
	}
}

type staticIssuer struct{ cert tls.Certificate }

func (s staticIssuer) Certificate(host string) (*tls.Certificate, error) { return &s.cert, nil }

func waitAddr(t *testing.T, get func() net.Addr) net.Addr {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a := get(); a != nil {
			return a
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("listener did not bind")
	return nil
}

func echoServer(t *testing.T, network string) string {
	t.Helper()
	if network == "tcp" {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() { defer c.Close(); io.Copy(c, c) }()
			}
		}()
		return ln.Addr().String()
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc.LocalAddr().String()
}

func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sideband test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return cert, key, pool
}

func leaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{name},
	}
	if ip := net.ParseIP(name); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der, ca.Raw},
		PrivateKey:  key,
	}
}

func tlsEcho(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}
