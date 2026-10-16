package opentunnel

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
)

const maxCACertBytes = 1 << 20

// NewHTTPClientWithCACert returns a client that trusts the system roots and the
// certificates in a PEM file. It verifies certificate chains and hostnames as
// usual. Use it with NewAPI for direct control API access; ClientOptions.CACertFile
// applies the same trust to a Client's API and relay connections.
// The file must contain only CERTIFICATE blocks and whitespace, up to 1 MiB.
// The returned client has no timeout; NewAPI supplies its operation timeout.
func NewHTTPClientWithCACert(path string) (*http.Client, error) {
	return httpClientWithCACert(nil, path)
}

func httpClientWithCACert(client *http.Client, path string) (*http.Client, error) {
	certificates, err := readCACertificates(path)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{}
	}
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	transport, ok := base.(*http.Transport)
	if !ok || transport == nil {
		return nil, fmt.Errorf("%w: ca-cert requires an *http.Transport", ErrInvalid)
	}
	// Reject legacy TLS hooks too: they bypass TLSClientConfig.
	if transport.DialTLSContext != nil || transport.DialTLS != nil { //nolint:staticcheck // SA1019: deprecated hooks are still honored by net/http.
		return nil, fmt.Errorf("%w: ca-cert cannot configure a custom TLS dialer", ErrInvalid)
	}
	transport = transport.Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		return nil, fmt.Errorf("%w: ca-cert requires TLS verification", ErrInvalid)
	}
	roots := transport.TLSClientConfig.RootCAs
	if roots == nil {
		roots, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("%w: cannot load system CA certificates", ErrInvalid)
		}
	} else {
		roots = roots.Clone()
	}
	for _, certificate := range certificates {
		roots.AddCert(certificate)
	}
	transport.TLSClientConfig.RootCAs = roots
	copy := *client
	copy.Transport = transport
	return &copy, nil
}

func readCACertificates(path string) ([]*x509.Certificate, error) {
	invalid := func(reason string) error { return fmt.Errorf("%w: ca-cert %s", ErrInvalid, reason) }
	// Reject special files before opening them (in particular, blocking FIFOs).
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, invalid("must be a readable regular PEM file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, invalid("cannot be read")
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxCACertBytes+1))
	if err != nil || len(data) > maxCACertBytes {
		return nil, invalid("cannot be read or exceeds 1 MiB")
	}
	var certificates []*x509.Certificate
	for data = bytes.TrimSpace(data); len(data) > 0; data = bytes.TrimSpace(data) {
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, invalid("must contain only CERTIFICATE PEM blocks")
		}
		endMarker := []byte("-----END CERTIFICATE-----")
		end := bytes.Index(data, endMarker)
		if end < 0 {
			return nil, invalid("contains invalid PEM")
		}
		end += len(endMarker)
		encoded := data[:end]
		// pem.Decode normally skips malformed blocks. Decode exactly one block
		// so a later valid certificate cannot hide a broken earlier one.
		block, rest := pem.Decode(encoded)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || bytes.Count(encoded, []byte("-----BEGIN")) != 1 {
			return nil, invalid("contains invalid PEM")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, invalid("contains an invalid certificate")
		}
		certificates = append(certificates, certificate)
		data = data[end:]
	}
	if len(certificates) == 0 {
		return nil, invalid("contains no certificates")
	}
	return certificates, nil
}
