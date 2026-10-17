package sideband

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
)

func TestMTLS(t *testing.T) {
	ca, caKey, pool := testCA(t)
	serverCert := leaf(t, ca, caKey, "127.0.0.1")
	userCert := leaf(t, ca, caKey, "user-client")
	proxyClient := leaf(t, ca, caKey, "proxy-client")

	seen := make(chan string, 1)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			cn := ""
			if len(cs.PeerCertificates) > 0 {
				cn = cs.PeerCertificates[0].Subject.CommonName
			}
			select {
			case seen <- cn:
			default:
			}
			return nil
		},
	})
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
			buf := make([]byte, 4)
			io.ReadFull(c, buf)
			c.Write(buf)
			c.Close()
		}
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
		OriginRoots: pool,
		ClientCert:  &proxyClient,
	}
	go s.ServeTCP()
	addr := waitAddr(t, s.TCPAddr)
	clientPool := pool
	conn, err := tls.Dial("tcp", addr.String(), &tls.Config{
		RootCAs:      clientPool,
		ServerName:   "127.0.0.1",
		NextProtos:   []string{"sideband"},
		Certificates: []tls.Certificate{userCert},
	})
	if err != nil {
		select {
		case msg := <-seen:
			t.Fatalf("dial: %v; origin: %s", err, msg)
		case <-time.After(time.Second):
			t.Fatalf("dial: %v", err)
		}
	}
	defer conn.Close()
	conn.Write([]byte("mtls"))
	buf := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}

	select {
	case cn := <-seen:
		if cn != "proxy-client" {
			t.Fatalf("origin saw client CN %q", cn)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("origin did not report a client certificate")
	}

	recs := readRecords(t, dir)
	foundUser := false
	for _, rec := range recs {
		peers, _ := rec.Fields["peer_certs"].([]any)
		for _, peer := range peers {
			m, _ := peer.(map[string]any)
			if strings.Contains(stringField(m["subject"]), "user-client") {
				foundUser = true
			}
		}
	}
	if !foundUser {
		t.Fatal("packet log missing the real client certificate")
	}
	keys := keysText(t, dir)
	if !strings.Contains(keys, "BEGIN PRIVATE KEY") || !hasSecretLine(keys) {
		t.Fatalf("key log missing private key or session secret:\n%s", keys)
	}
	if !strings.Contains(keys, "user-client") && !strings.Contains(keys, "BEGIN CERTIFICATE") {
		t.Fatal("key log missing a certificate")
	}
}

func TestDTLSMTLS(t *testing.T) {
	ca, caKey, pool := testCA(t)
	serverCert := leaf(t, ca, caKey, "127.0.0.1")
	userCert := leaf(t, ca, caKey, "dtls-user")
	proxyClient := leaf(t, ca, caKey, "dtls-proxy")
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan string, 1)
	ln, err := dtls.Listen("udp", addr, &dtls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   dtls.RequireAnyClientCert,
		VerifyConnection: func(st *dtls.State) error {
			cn := ""
			if len(st.PeerCertificates) > 0 {
				if name, err := parseCertCN(st.PeerCertificates[0]); err == nil {
					cn = name
				}
			}
			select {
			case seen <- cn:
			default:
			}
			return nil
		},
	})
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
		buf := make([]byte, 4)
		io.ReadFull(c, buf)
		c.Write(buf)
	}()

	dir := t.TempDir()
	logw, err := OpenLogger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer logw.Close()
	s := &Server{
		Upstream:    ln.Addr().String(),
		Log:         logw,
		Certs:       staticIssuer{cert: leaf(t, ca, caKey, "127.0.0.1")},
		OriginRoots: pool,
		ClientCert:  &proxyClient,
	}
	go func() { _ = s.ServeDTLS("127.0.0.1:0") }()
	bound := waitAddr(t, s.DTLSAddr)
	raddr, _ := net.ResolveUDPAddr("udp", bound.String())
	conn, err := dtls.Dial("udp", raddr, &dtls.Config{
		RootCAs:      pool,
		ServerName:   "127.0.0.1",
		Certificates: []tls.Certificate{userCert},
	})
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
	select {
	case cn := <-seen:
		if cn != "dtls-proxy" {
			t.Fatalf("origin saw client CN %q", cn)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dtls origin did not report a client certificate")
	}
	keys := keysText(t, dir)
	if !strings.Contains(keys, "BEGIN PRIVATE KEY") {
		t.Fatal("dtls key log missing private key")
	}
}

func parseCertCN(der []byte) (string, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	return cert.Subject.CommonName, nil
}

func stringField(v any) string {
	s, _ := v.(string)
	return s
}
