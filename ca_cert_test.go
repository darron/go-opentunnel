package opentunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func writeTestCA(t *testing.T, a *testAuthority) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCACertFileRejectsInvalidBundles(t *testing.T) {
	a := newTestAuthority(t)
	valid := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.cert.Raw})
	for name, data := range map[string][]byte{
		"empty": {}, "garbage": []byte("no certificate"),
		"invalid DER":                pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")}),
		"private key":                pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("invalid")}),
		"trailing junk":              append(append([]byte{}, valid...), []byte("junk")...),
		"leading junk":               append([]byte("junk\n"), valid...),
		"invalid block before valid": append([]byte("-----BEGIN CERTIFICATE-----\ninvalid!\n-----END CERTIFICATE-----\n"), valid...),
		"oversized":                  []byte(strings.Repeat(" ", (1<<20)+1)),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			_, err := NewClient(ClientOptions{CACertFile: path, Storage: NewMemoryStorage()})
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("expected ErrInvalid, got %v", err)
			}
		})
	}
	for _, path := range []string{filepath.Join(t.TempDir(), "missing"), t.TempDir()} {
		if _, err := NewHTTPClientWithCACert(path); !errors.Is(err, ErrInvalid) {
			t.Fatalf("path %q: %v", path, err)
		}
	}
}

func TestCACertFileClonesCallerTransport(t *testing.T) {
	a, b := newTestAuthority(t), newTestAuthority(t)
	roots := a.roots.Clone()
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, MaxIdleConns: 37}
	caller := &http.Client{Transport: transport}
	client, err := httpClientWithCACert(caller, writeTestCA(t, b))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("missing HTTP transport")
	}
	if client == caller || got == transport || got.TLSClientConfig == transport.TLSClientConfig || got.TLSClientConfig.RootCAs == roots {
		t.Fatal("caller-owned configuration was not cloned")
	}
	expectedRoots := a.roots.Clone()
	expectedRoots.AddCert(b.cert)
	if got.MaxIdleConns != 37 || got.TLSClientConfig.MinVersion != tls.VersionTLS12 || !roots.Equal(a.roots) || !got.TLSClientConfig.RootCAs.Equal(expectedRoots) {
		t.Fatal("existing transport or roots changed")
	}
	transport.TLSClientConfig.InsecureSkipVerify = true // Deliberately unsafe caller input must not weaken this option.
	if _, err := httpClientWithCACert(caller, writeTestCA(t, b)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsafe transport accepted: %v", err)
	}
	caller.Transport = &http.Transport{DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("custom TLS dial") }}
	if _, err := httpClientWithCACert(caller, writeTestCA(t, b)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("custom TLS dial accepted: %v", err)
	}
	legacy := &http.Transport{}
	legacy.DialTLS = func(string, string) (net.Conn, error) { return nil, errors.New("legacy TLS dial") } //nolint:staticcheck // SA1019: regression for the still-honored legacy bypass.
	caller.Transport = legacy
	if _, err := httpClientWithCACert(caller, writeTestCA(t, b)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("legacy TLS dial accepted: %v", err)
	}
	caller.Transport = &roundTripFunc{}
	if _, err := httpClientWithCACert(caller, writeTestCA(t, b)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("opaque transport accepted: %v", err)
	}
}

func TestCACertFileIgnoresAmbientEnvironment(t *testing.T) {
	t.Setenv("OPENTUNNEL_CA_CERT", filepath.Join(t.TempDir(), "missing.pem"))
	client, err := NewClient(ClientOptions{Storage: NewMemoryStorage()})
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
}

func TestCACertFileMultipleCertificatesAndRedirectBoundary(t *testing.T) {
	a, b := newTestAuthority(t), newTestAuthority(t)
	data := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.cert.Raw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.cert.Raw})...)
	path := filepath.Join(t.TempDir(), "bundle.pem")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	certificates, err := readCACertificates(path)
	if err != nil || len(certificates) != 2 || !certificates[0].Equal(a.cert) || !certificates[1].Equal(b.cert) {
		t.Fatalf("multi-certificate bundle: %v", err)
	}
	var destinationHits int
	destination := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { destinationHits++ }))
	defer destination.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, http.StatusFound) }))
	defer source.Close()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: source.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ClientOptions{API: source.URL, CACertFile: path, Storage: NewMemoryStorage()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	_, err = client.API().Get(t.Context(), "test", "redirect-canary")
	if err == nil || destinationHits != 0 || strings.Contains(err.Error(), "redirect-canary") {
		t.Fatalf("custom CA weakened redirect boundary: %v", err)
	}
}

func TestCACertFileVerifiesHTTPS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := NewHTTPClientWithCACert(path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal(response.Status)
	}
	other, err := NewHTTPClientWithCACert(writeTestCA(t, newTestAuthority(t)))
	if err != nil {
		t.Fatal(err)
	}
	defer other.CloseIdleConnections()
	if response, err := other.Do(request.Clone(t.Context())); err == nil {
		_ = response.Body.Close()
		t.Fatal("untrusted server accepted")
	}
}

func newTLSRelay(t *testing.T) (*relayFixture, string) {
	t.Helper()
	f := newRelay(t)
	outer := newTestAuthority(t)
	key, csr, err := generateRequest("localhost")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := outer.issue(csr, 2)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair([]byte(issued.State.Certificate+issued.State.Chain), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(f.api.serve))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	t.Cleanup(server.Close)
	server.URL = strings.Replace(server.URL, "127.0.0.1", "localhost", 1)
	f.api.server = server
	return f, writeTestCA(t, outer)
}

func TestCACertFileAPIAndRelayWithSeparateVisitorCA(t *testing.T) {
	f, caFile := newTLSRelay(t)
	server := f.api.server
	client, err := NewClient(ClientOptions{API: server.URL, CACertFile: caFile, Storage: NewMemoryStorage()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	_ = connectTest(t, client, Routes{"@": echoTarget(t)})
	relay := f.next(t)
	visitor := relay.public(t, 1, "demo.test") // Verified with the independent visitor CA.
	payload := bytes.Repeat([]byte("custom CA, normal visitor TLS\n"), 4096)
	go func() { _, _ = visitor.Write(payload) }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(visitor, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("forwarded bytes changed")
	}

	// Added trust must still enforce hostname verification for HTTPS and WSS.
	httpClient, err := NewHTTPClientWithCACert(caFile)
	if err != nil {
		t.Fatal(err)
	}
	defer httpClient.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	badHost := strings.Replace(server.URL, "localhost", "127.0.0.1", 1)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, badHost, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response, err := httpClient.Do(request); err == nil {
		_ = response.Body.Close()
		t.Fatal("HTTPS hostname mismatch accepted")
	}
	for _, tc := range []struct{ name, url, ca string }{
		{"hostname", strings.Replace(badHost, "https:", "wss:", 1), caFile},
		{"untrusted", strings.Replace(server.URL, "https:", "wss:", 1), writeTestCA(t, newTestAuthority(t))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewHTTPClientWithCACert(tc.ca)
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			ws, response, err := websocket.Dial(ctx, tc.url+"/api/tunnel/demo/connect", &websocket.DialOptions{HTTPClient: client, Subprotocols: []string{"opentunnel"}})
			if response != nil && response.Body != nil {
				_ = response.Body.Close()
			}
			if err == nil {
				_ = ws.CloseNow()
				t.Fatal("invalid relay certificate accepted")
			}
		})
	}
}
