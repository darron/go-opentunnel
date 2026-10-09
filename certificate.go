package opentunnel

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

func generateRequest(hostname string) (privateKey, csr string, err error) {
	if hostname == "" || strings.ContainsAny(hostname, "/\\?@#") {
		return "", "", fmt.Errorf("%w: invalid hostname", ErrInvalid)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname, "*." + hostname}, SignatureAlgorithm: x509.ECDSAWithSHA256}, key)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), nil
}

func parseCertificate(identity Identity) (*tls.Certificate, error) {
	cert, err := parseCertificateMaterial(identity)
	if err != nil {
		return nil, err
	}
	if !time.Now().Before(cert.Leaf.NotAfter) {
		return nil, ErrCertificateExpired
	}
	return cert, nil
}

// parseCertificateMaterial permits an expired leaf only for bridge attachment
// that triggers server renewal. Handshakes still require a currently valid leaf.
func parseCertificateMaterial(identity Identity) (*tls.Certificate, error) {
	if identity.Hostname == "" || identity.PrivateKey == "" || identity.Certificate == "" {
		return nil, fmt.Errorf("%w: incomplete certificate identity", ErrInvalid)
	}
	cert, err := tls.X509KeyPair([]byte(identity.Certificate+"\n"+identity.Chain), []byte(identity.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("%w: invalid certificate key pair", ErrInvalid)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	if time.Now().Before(leaf.NotBefore) {
		return nil, fmt.Errorf("%w: certificate outside validity period", ErrInvalid)
	}
	if err := leaf.VerifyHostname(identity.Hostname); err != nil {
		return nil, fmt.Errorf("%w: certificate hostname mismatch", ErrInvalid)
	}
	if err := leaf.VerifyHostname("route." + identity.Hostname); err != nil {
		return nil, fmt.Errorf("%w: certificate wildcard mismatch", ErrInvalid)
	}
	hasWildcard := false
	for _, name := range leaf.DNSNames {
		if strings.EqualFold(name, "*."+identity.Hostname) {
			hasWildcard = true
			break
		}
	}
	if !hasWildcard {
		return nil, fmt.Errorf("%w: certificate missing wildcard SAN", ErrInvalid)
	}
	cert.Leaf = leaf
	return &cert, nil
}

// requestForExistingKey reuses the stored key during recovery, preserving
// credentials and active channels until issuance succeeds.
func requestForExistingKey(hostname, privateKey string) (string, error) {
	b, _ := pem.Decode([]byte(privateKey))
	if b == nil {
		return "", fmt.Errorf("%w: invalid private key", ErrInvalid)
	}
	key, e := x509.ParsePKCS8PrivateKey(b.Bytes)
	if e != nil {
		return "", fmt.Errorf("%w: invalid private key", ErrInvalid)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return "", fmt.Errorf("%w: unsupported private key", ErrInvalid)
	}
	der, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname, "*." + hostname}}, signer)
	if e != nil {
		return "", e
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}
