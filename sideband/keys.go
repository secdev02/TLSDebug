package sideband

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"sync"
)

// captureWriter stores NSS key-log lines for one handshake and appends them
// to sideband.keys. crypto/tls calls Write during the handshake.
type captureWriter struct {
	dst io.Writer
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *captureWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.buf.Write(p)
	w.mu.Unlock()
	if w.dst == nil {
		return len(p), nil
	}
	return w.dst.Write(p)
}

func (w *captureWriter) Take() string {
	if w == nil {
		return ""
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.buf.String()
	w.buf.Reset()
	return s
}

type secretDest struct{ l *Logger }

func (d secretDest) Write(p []byte) (int, error) {
	if err := d.l.WriteSecrets(string(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}

// newCapture returns a writer for one handshake. Lines are copied into
// sideband.keys and can be read back with Take after the handshake returns.
func (l *Logger) newCapture() *captureWriter {
	if l == nil {
		return &captureWriter{}
	}
	return &captureWriter{dst: secretDest{l}}
}

func privatePEM(key any) string {
	if key == nil {
		return ""
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func certPEM(der []byte) string {
	if len(der) == 0 {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func peerCertFields(certs []*x509.Certificate) []map[string]string {
	if len(certs) == 0 {
		return nil
	}
	out := make([]map[string]string, 0, len(certs))
	for _, cert := range certs {
		sum := sha256.Sum256(cert.Raw)
		out = append(out, map[string]string{
			"subject": cert.Subject.String(),
			"sha256":  hex.EncodeToString(sum[:]),
			"pem":     certPEM(cert.Raw),
		})
	}
	return out
}

func peerCertsFromDER(ders [][]byte) []map[string]string {
	var certs []*x509.Certificate
	for _, der := range ders {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}
	return peerCertFields(certs)
}

func leafFromConfig(cfg *tls.Config) *tls.Certificate {
	if cfg == nil || len(cfg.Certificates) == 0 {
		return nil
	}
	return &cfg.Certificates[0]
}
