package opentunnel

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestGenerateRequestIncludesKeyAndExactWildcardSANs(t *testing.T) {
	key, csrPEM, err := generateRequest("demo.opentunnel.xyz")
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode([]byte(key))
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Fatal("not PKCS8")
	}
	if _, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err != nil {
		t.Fatal(err)
	}
	csrBlock, _ := pem.Decode([]byte(csrPEM))
	if csrBlock == nil {
		t.Fatal("missing CSR")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "demo.opentunnel.xyz" || len(csr.DNSNames) != 2 || csr.DNSNames[0] != "demo.opentunnel.xyz" || csr.DNSNames[1] != "*.demo.opentunnel.xyz" {
		t.Fatalf("CSR %#v", csr)
	}
}

func TestParseCertificateRequiresExactAndWildcardSANs(t *testing.T) {
	keyPEM, _, err := generateRequest("demo.opentunnel.xyz")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(keyPEM))
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("not an ECDSA key")
	}
	for _, dns := range [][]string{{"demo.opentunnel.xyz"}, {"*.demo.opentunnel.xyz"}, {"wrong.example"}, {"demo.opentunnel.xyz", "route.demo.opentunnel.xyz"}} {
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: new(big.Int).SetInt64(1), Subject: pkix.Name{CommonName: dns[0]}, DNSNames: dns, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}, &x509.Certificate{SerialNumber: new(big.Int).SetInt64(1), Subject: pkix.Name{CommonName: dns[0]}, DNSNames: dns, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		identity := Identity{Hostname: "demo.opentunnel.xyz", PrivateKey: keyPEM, Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
		if _, err := parseCertificate(identity); err == nil {
			t.Fatalf("accepted DNS names %#v", dns)
		}
	}
}

func TestParseCertificateAcceptsMatchingKeyAndSANs(t *testing.T) {
	keyPEM, _, err := generateRequest("demo.opentunnel.xyz")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(keyPEM))
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("not an ECDSA key")
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "demo.opentunnel.xyz"}, DNSNames: []string{"demo.opentunnel.xyz", "*.demo.opentunnel.xyz"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	identity := Identity{Hostname: "demo.opentunnel.xyz", PrivateKey: keyPEM, Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	if _, err := parseCertificate(identity); err != nil {
		t.Fatal(err)
	}
}
