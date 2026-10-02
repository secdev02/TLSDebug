package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testCertificate(t *testing.T, commonName string) (*x509.Certificate, []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestPEMContainsFingerprintMatchesExactCertificate(t *testing.T) {
	_, firstPEM := testCertificate(t, "first")
	second, secondPEM := testCertificate(t, "second")
	bundle := append(firstPEM, secondPEM...)

	if !pemContainsFingerprint(bundle, certificateFingerprint(second)) {
		t.Fatal("expected bundle to contain second certificate fingerprint")
	}
	if pemContainsFingerprint(firstPEM, certificateFingerprint(second)) {
		t.Fatal("subject-independent fingerprint check accepted the wrong certificate")
	}
}

func TestCertificateFingerprintFile(t *testing.T) {
	cert, certPEM := testCertificate(t, "file")
	path := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(path, certPEM, 0600); err != nil {
		t.Fatal(err)
	}

	actual, err := certificateFingerprintFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if actual != certificateFingerprint(cert) {
		t.Fatalf("fingerprint mismatch: got %s", actual)
	}
}
