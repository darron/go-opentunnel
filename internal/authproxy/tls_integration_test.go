package authproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type closeObserver struct {
	net.Conn
	closed chan<- struct{}
	once   sync.Once
}

func (c *closeObserver) Close() error {
	c.once.Do(func() {
		select {
		case c.closed <- struct{}{}:
		default:
		}
	})
	return c.Conn.Close()
}

type connWithObservedNetConn struct {
	net.Conn
	raw net.Conn
}

func (c *connWithObservedNetConn) NetConn() net.Conn { return c.raw }

func TestTLSStreamRevocationAbortsBlockedClientAndReleasesLease(t *testing.T) {
	var backendBytes atomic.Int64
	backendStarted := make(chan struct{})
	backendDone := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(backendDone)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		if err := http.NewResponseController(w).Flush(); err != nil {
			return
		}
		close(backendStarted)
		chunk := make([]byte, 32<<10)
		for {
			n, err := w.Write(chunk)
			backendBytes.Add(int64(n))
			if err != nil {
				return
			}
			if err := http.NewResponseController(w).Flush(); err != nil {
				return
			}
			select {
			case <-r.Context().Done():
				return
			default:
			}
		}
	}))
	defer backend.Close()

	cfg := fixtureConfig()
	cfg.Binding.Hostname = "example.com"
	cfg.Upstream = backend.URL
	tokens := NewTokenStore(filepath.Join(secureTempDir(t), "tokens.json"), cfg)
	h, err := NewHandler(Options{Config: cfg, TokenStore: tokens})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()

	front := httptest.NewUnstartedServer(h)
	var connContexts atomic.Int32
	var sawTLSNetConn atomic.Bool
	transportAborted := make(chan struct{}, 1)
	front.Config.ConnContext = func(ctx context.Context, conn net.Conn) context.Context {
		connContexts.Add(1)
		provider, ok := conn.(interface{ NetConn() net.Conn })
		if !ok {
			return WithClientConnection(ctx, conn)
		}
		sawTLSNetConn.Store(true)
		observedRaw := &closeObserver{Conn: provider.NetConn(), closed: transportAborted}
		return WithClientConnection(ctx, &connWithObservedNetConn{Conn: conn, raw: observedRaw})
	}
	front.StartTLS()
	defer front.Close()

	roots := x509.NewCertPool()
	roots.AddCert(front.Certificate())
	tlsConfig := &tls.Config{RootCAs: roots, ServerName: cfg.Binding.Hostname, MinVersion: tls.VersionTLS12}
	transport := &http.Transport{
		ForceAttemptHTTP2: false,
		DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Keep the normal OS receive window. waitForBlockedTLSWrite proves that
			// writes stall; shrinking SO_RCVBUF instead measures platform-specific
			// draining of bytes queued before the connection is closed.
			raw, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			conn := tls.Client(raw, tlsConfig.Clone())
			if err := conn.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return conn, nil
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	secret, id, err := tokens.Create(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, front.URL+"/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = cfg.Binding.Hostname
	req.Header.Set("Authorization", "Bearer "+secret)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("TLS stream returned %d", res.StatusCode)
	}
	select {
	case <-backendStarted:
	case <-time.After(time.Second):
		t.Fatal("backend stream did not start")
	}
	if connContexts.Load() == 0 {
		t.Fatal("TLS server did not attach the client connection to request context")
	}
	if !sawTLSNetConn.Load() {
		t.Fatal("TLS server connection did not expose its raw transport")
	}
	waitForBlockedTLSWrite(t, h, &backendBytes)
	revokedAt := time.Now()
	if err := tokens.Revoke(id); err != nil {
		t.Fatal(err)
	}
	select {
	case <-transportAborted:
	case <-time.After(2 * time.Second):
		t.Fatal("revocation did not close the client TLS transport")
	}
	deadline := time.Now().Add(2 * time.Second)
	for activeLeaseCount(h) != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if count := activeLeaseCount(h); count != 0 {
		t.Fatalf("revocation left %d blocked handler lease(s)", count)
	}
	select {
	case <-backendDone:
	case <-time.After(2 * time.Second):
		t.Fatal("revocation did not cancel the blocked upstream stream")
	}

	readDone := make(chan error, 1)
	go func() { _, err := io.Copy(io.Discard, res.Body); readDone <- err }()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("blocked TLS client saw a clean stream end instead of transport abort")
		}
		if ctx.Err() != nil || time.Since(revokedAt) >= 5*time.Second {
			t.Fatalf("client observed request timeout instead of transport abort: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked TLS client did not observe transport abort")
	}
}

func waitForBlockedTLSWrite(t *testing.T, h *Handler, written *atomic.Int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	last := written.Load()
	stableSince := time.Now()
	for time.Now().Before(deadline) {
		if activeLeaseCount(h) != 1 {
			t.Fatalf("stream has %d active leases, want 1", activeLeaseCount(h))
		}
		current := written.Load()
		if current != last {
			last = current
			stableSince = time.Now()
		} else if current >= 32<<10 && time.Since(stableSince) >= 100*time.Millisecond {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("backend output did not block while client stopped reading; wrote %d bytes", written.Load())
}

func activeLeaseCount(h *Handler) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.active)
}
