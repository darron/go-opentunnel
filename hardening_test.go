package opentunnel

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestTunnelHandshakeRouteIsolation(t *testing.T) {
	for _, tc := range []struct{ name, relay, visitor string }{
		{"root into admin", "admin.demo.test", "demo.test"},
		{"admin into root", "demo.test", "admin.demo.test"},
		{"no visitor SNI", "demo.test", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRelay(t)
			c := tunnelClient(t, f, TransportOptions{})
			x := connectTest(t, c, Routes{"@": echoTarget(t), "admin": echoTarget(t)})
			s := f.next(t)
			cfg := &tls.Config{RootCAs: f.api.authority.roots, ServerName: tc.visitor, MinVersion: tls.VersionTLS12}
			if tc.visitor == "" {
				// #nosec G402 -- Send no SNI; VerifyConnection still verifies the test CA and hostname.
				cfg.InsecureSkipVerify = true
				cfg.VerifyConnection = func(cs tls.ConnectionState) error {
					_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: "demo.test", Roots: f.api.authority.roots})
					return err
				}
			}
			conn := tls.Client(s.publicRaw(t, 1, tc.relay), cfg)
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			if err := conn.HandshakeContext(t.Context()); err == nil {
				t.Fatal("relay-selected route accepted a different TLS hostname")
			}
			waitStatus(t, x, func(st Status) bool { return st.Connections == 0 })
			good := s.public(t, 2, "demo.test")
			if _, err := good.Write([]byte("root-isolated")); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 13)
			if _, err := io.ReadFull(good, b); err != nil || string(b) != "root-isolated" {
				t.Fatalf("healthy route: %q %v", b, err)
			}
		})
	}
}

func TestConnectStartupContextDoesNotOwnLifetime(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	ctx, cancel := context.WithCancel(t.Context())
	x, err := c.Connect(ctx, ConnectOptions{Routes: Routes{"@": echoTarget(t)}})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	s := f.next(t)
	pub := s.public(t, 1, "demo.test")
	if _, err := pub.Write([]byte("live")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(pub, b); err != nil || string(b) != "live" {
		t.Fatalf("startup cancellation stopped tunnel: %q %v", b, err)
	}
	if err := x.Close(); err != nil {
		t.Fatal(err)
	}
	if err := x.Err(); err != nil {
		t.Fatalf("normal Close error: %v", err)
	}
}

func TestConnectExplicitLifetimeCancellation(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	life, cancel := context.WithCancel(t.Context())
	defer cancel()
	x, err := c.Connect(t.Context(), ConnectOptions{Routes: Routes{"@": echoTarget(t)}, Lifetime: life})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-x.Done():
	case <-time.After(time.Second):
		t.Fatal("explicit lifetime cancellation did not stop connection")
	}
	if !errors.Is(x.Err(), context.Canceled) {
		t.Fatalf("lifetime error: %v", x.Err())
	}
}

func TestConnectLifetimeCancellationDuringStartupJoinsWorkers(t *testing.T) {
	f := newRelay(t)
	accepted := make(chan struct{})
	f.api.bridge = func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"opentunnel"}})
		if err != nil {
			return
		}
		defer func() { _ = ws.CloseNow() }()
		close(accepted)
		for {
			if _, _, err := ws.Read(r.Context()); err != nil {
				return
			}
		}
	}
	c := tunnelClient(t, f, TransportOptions{})
	life, cancel := context.WithCancel(t.Context())
	defer cancel()
	target := echoTarget(t)
	result := make(chan error, 1)
	go func() {
		x, err := c.Connect(t.Context(), ConnectOptions{Routes: Routes{"@": target}, Lifetime: life})
		if x != nil {
			_ = x.Close()
		}
		result <- err
	}()
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("startup never reached bridge attachment")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("startup lifetime cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("lifetime cancellation did not interrupt startup")
	}
	c.mu.Lock()
	remaining := len(c.connections)
	c.mu.Unlock()
	if remaining != 0 {
		t.Fatal("Connect returned before unregistering its connection")
	}
}

func TestHardeningTransportOptionsRejectNegativeDurations(t *testing.T) {
	for _, options := range []TransportOptions{{IdleTimeout: -time.Second}, {CertificateRetryInterval: -time.Second}} {
		c, err := NewClient(ClientOptions{Storage: NewMemoryStorage(), Transport: options})
		if c != nil {
			_ = c.Close()
		}
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("negative hardening duration accepted: %v", err)
		}
	}
}

func TestConnectRejectsOverlappingRoutes(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	_ = connectTest(t, c, Routes{"@": echoTarget(t)})
	duplicate, err := c.Connect(t.Context(), ConnectOptions{Routes: Routes{"@": echoTarget(t)}})
	if !errors.Is(err, ErrRouteInUse) {
		if duplicate != nil {
			_ = duplicate.Close()
		}
		t.Fatalf("duplicate route error: %v", err)
	}
	disjoint, err := c.Connect(t.Context(), ConnectOptions{Routes: Routes{"api": echoTarget(t)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := disjoint.SetRoutes(Routes{"@": echoTarget(t)}); !errors.Is(err, ErrRouteInUse) {
		t.Fatalf("route change conflict: %v", err)
	}
	if _, ok := disjoint.Status().Routes["api"]; !ok {
		t.Fatal("rejected update changed route snapshot")
	}
}

func TestJSONOmitsUnsetEventTimes(t *testing.T) {
	for _, v := range []any{Event{Type: "connecting"}, Status{State: "connecting"}} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "0001-") {
			t.Fatalf("unset timestamp exposed: %s", b)
		}
	}
}

func TestRuntimeFailedCertificateRecoversSameKey(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	x := connectTest(t, c, Routes{"@": echoTarget(t)})
	_ = f.next(t)
	old := x.Identity()
	submissions := f.api.submissions.Load()
	f.api.mu.Lock()
	f.api.cert = CertificateInfo{ID: "failed", State: CertificateState{Type: "failed", Reason: "test failure"}}
	f.api.mu.Unlock()
	if err := x.refreshOnce(); err != nil {
		t.Fatal(err)
	}
	if err := x.refreshOnce(); err != nil {
		t.Fatal(err)
	}
	updated := x.Identity()
	if updated.Certificate == old.Certificate || updated.PrivateKey != old.PrivateKey || updated.ID != old.ID {
		t.Fatal("failed certificate did not recover with the same identity/key")
	}
	if f.api.submissions.Load() != submissions+1 {
		t.Fatal("failed issuance was not re-requested once")
	}
}

func TestRemoveDuringStuckCertificateRecovery(t *testing.T) {
	f := newRelay(t)
	var stuck atomic.Bool
	f.api.onSubmit = func() {
		if stuck.Load() {
			f.api.hold.Store(true)
		}
	}
	c := tunnelClient(t, f, TransportOptions{CertificateRefreshInterval: 5 * time.Millisecond})
	x := connectTest(t, c, Routes{"@": echoTarget(t)})
	_ = f.next(t)
	submissions := f.api.submissions.Load()
	f.api.mu.Lock()
	f.api.cert = CertificateInfo{ID: "failed", State: CertificateState{Type: "failed", Reason: "test failure"}}
	stuck.Store(true)
	f.api.mu.Unlock()
	deadline := time.Now().Add(time.Second)
	for f.api.submissions.Load() == submissions && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if f.api.submissions.Load() != submissions+1 {
		t.Fatal("recovery never requested a replacement certificate")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := c.Remove(ctx, "default"); err != nil {
		t.Fatalf("stuck issuance blocked Remove: %v", err)
	}
	select {
	case <-x.Done():
	default:
		t.Fatal("Remove returned before connection workers stopped")
	}
	id, err := c.Get(t.Context(), "default")
	if err != nil || id != nil {
		t.Fatalf("credentials survived removal: identity present=%v err=%v", id != nil, err)
	}
}

func TestFailedCertificateRecoveryIsThrottledAcrossConnections(t *testing.T) {
	f := newRelay(t)
	var fail atomic.Bool
	f.api.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/certificate") {
			_ = json.NewEncoder(w).Encode(CertificateInfo{ID: "failed", State: CertificateState{Type: "failed", Reason: "test failure"}})
			return
		}
		f.api.serve(w, r)
	})
	c := tunnelClient(t, f, TransportOptions{})
	x := connectTest(t, c, Routes{"@": echoTarget(t)})
	_ = f.next(t)
	y := connectTest(t, c, Routes{"api": echoTarget(t)})
	_ = f.next(t)
	submissions := f.api.submissions.Load()
	fail.Store(true)
	for i := 0; i < 5; i++ {
		_ = x.refreshOnce()
		_ = y.refreshOnce()
	}
	if got := f.api.submissions.Load() - submissions; got != 1 {
		t.Fatalf("failed issuance submitted %d CSRs within one retry interval; want 1", got)
	}
}

func TestCertificateRecoveryRetriesAndResetsAfterRenewal(t *testing.T) {
	f := newRelay(t)
	var fail atomic.Bool
	f.api.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/certificate") {
			_ = json.NewEncoder(w).Encode(CertificateInfo{ID: "failed", State: CertificateState{Type: "failed", Reason: "test failure"}})
			return
		}
		f.api.serve(w, r)
	})
	const retry = 500 * time.Millisecond
	c := tunnelClient(t, f, TransportOptions{CertificateRetryInterval: retry})
	x := connectTest(t, c, Routes{"@": echoTarget(t)})
	_ = f.next(t)
	old := x.Identity()
	submissions := f.api.submissions.Load()
	f.api.mu.Lock()
	f.api.cert = CertificateInfo{ID: "failed", State: CertificateState{Type: "failed", Reason: "test failure"}}
	f.api.mu.Unlock()
	fail.Store(true)
	if err := x.refreshOnce(); err != nil {
		t.Fatal(err)
	}
	if err := x.refreshOnce(); !errors.Is(err, ErrCertificateIssuance) {
		t.Fatalf("cooldown error: %v", err)
	}
	if got := f.api.submissions.Load() - submissions; got != 1 {
		t.Fatalf("submissions before retry interval: %d", got)
	}
	if err := sleepContext(t.Context(), retry); err != nil {
		t.Fatal(err)
	}
	if err := x.refreshOnce(); err != nil {
		t.Fatalf("retry after interval: %v", err)
	}
	if got := f.api.submissions.Load() - submissions; got != 2 {
		t.Fatalf("submissions after retry interval: %d", got)
	}
	fail.Store(false)
	if err := x.refreshOnce(); err != nil {
		t.Fatal(err)
	}
	if x.Identity().Certificate == old.Certificate {
		t.Fatal("replacement certificate was not installed")
	}
	fail.Store(true)
	if err := x.refreshOnce(); err != nil {
		t.Fatalf("new failure retained completed recovery's cooldown: %v", err)
	}
	if got := f.api.submissions.Load() - submissions; got != 3 {
		t.Fatalf("submissions after successful renewal and new failure: %d", got)
	}
}

func expiredFixtureCertificate(t *testing.T, a *testAPI, expiry time.Time) CertificateInfo {
	t.Helper()
	block, _ := pem.Decode([]byte(a.csr))
	if block == nil {
		t.Fatal("missing fixture CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(90), Subject: csr.Subject, DNSNames: csr.DNSNames, NotBefore: expiry.Add(-time.Hour), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, a.authority.cert, csr.PublicKey, a.authority.key)
	if err != nil {
		t.Fatal(err)
	}
	return CertificateInfo{ID: "old", State: CertificateState{Type: "ready", Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), Chain: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.authority.cert.Raw})), Expiry: expiry}}
}

func TestExpiredIdentityAttachesToTriggerServerRenewal(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{CertificateDueInterval: 5 * time.Millisecond})
	old, err := c.Create(t.Context(), "", ProvisionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	expired := expiredFixtureCertificate(t, f.api, time.Now().Add(-time.Minute))
	f.api.mu.Lock()
	f.api.cert = expired
	f.api.mu.Unlock()
	old.Certificate = expired.State.Certificate
	old.Chain = expired.State.Chain
	old.CertificateExpiry = expired.State.Expiry
	if err := c.store.Save(t.Context(), "default", *old); err != nil {
		t.Fatal(err)
	}
	submissions := f.api.submissions.Load()
	f.api.bridge = func(w http.ResponseWriter, r *http.Request) {
		f.accept(w, r)
		f.api.mu.Lock()
		defer f.api.mu.Unlock()
		renewed, err := f.api.authority.issue(f.api.csr, 91)
		if err != nil {
			t.Error(err)
			return
		}
		f.api.cert = renewed
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	x, err := c.Connect(ctx, ConnectOptions{Routes: Routes{"@": echoTarget(t)}})
	if err != nil {
		t.Fatal(err)
	}
	if x.Identity().Certificate == old.Certificate {
		t.Fatal("Connect returned before the expired certificate was replaced")
	}
	if x.Identity().ID != old.ID || x.Identity().PrivateKey != old.PrivateKey {
		t.Fatal("expiry recovery replaced tunnel or key")
	}
	if f.api.submissions.Load() != submissions {
		t.Fatal("normal server renewal unnecessarily resubmitted a CSR")
	}
	_ = f.next(t).public(t, 1, "demo.test")
}

func TestEstablishedChannelIdleLimitReleasesCapacity(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{IdleTimeout: 100 * time.Millisecond, MaxConnections: 1})
	x := connectTest(t, c, Routes{"@": echoTarget(t)})
	s := f.next(t)
	pub := s.public(t, 1, "demo.test")
	if _, err := pub.Write([]byte("idle")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(pub, b); err != nil {
		t.Fatal(err)
	}
	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()
	for {
		select {
		case event := <-x.Events():
			if event.Type != "connection-closed" {
				continue
			}
			if !strings.Contains(event.Error, "idle timeout") {
				t.Fatalf("idle closure lacks reason: %+v", event)
			}
			good := s.public(t, 2, "demo.test")
			if _, err := good.Write([]byte("capacity")); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 8)
			if _, err := io.ReadFull(good, b); err != nil || string(b) != "capacity" {
				t.Fatalf("capacity was not released: %q %v", b, err)
			}
			return
		case <-timeout.C:
			t.Fatal("idle established channel retained capacity")
		}
	}
}

func TestActiveChannelRenewsIdleDeadline(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{IdleTimeout: 250 * time.Millisecond})
	_ = connectTest(t, c, Routes{"@": echoTarget(t)})
	pub := f.next(t).public(t, 1, "demo.test")
	for range 7 {
		if _, err := pub.Write([]byte("active")); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 6)
		if _, err := io.ReadFull(pub, b); err != nil || string(b) != "active" {
			t.Fatalf("active channel closed: %q %v", b, err)
		}
		timer := time.NewTimer(75 * time.Millisecond)
		select {
		case <-timer.C:
		case <-t.Context().Done():
			timer.Stop()
			t.Fatal(t.Context().Err())
		}
	}
}

func TestRapidlyFlappingBridgeBacksOff(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{BackoffMin: time.Millisecond, BackoffMax: time.Second})
	x := connectTest(t, c, Routes{"@": echoTarget(t)})
	for want := 1; want <= 2; want++ {
		f.next(t).close()
		timeout := time.NewTimer(time.Second)
		for {
			select {
			case event := <-x.Events():
				if event.Type != "reconnecting" {
					continue
				}
				timeout.Stop()
				if event.Attempt != want {
					t.Fatalf("short-lived attachment reset backoff: attempt %d, want %d", event.Attempt, want)
				}
			case <-timeout.C:
				t.Fatal("no retry after bridge loss")
			}
			break
		}
	}
}

func TestRuntimeExpiryStopsNewHandshakesButPreservesStreams(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{CertificateDueInterval: 25 * time.Millisecond})
	old, err := c.Create(t.Context(), "", ProvisionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	short := expiredFixtureCertificate(t, f.api, time.Now().Add(2*time.Second))
	f.api.mu.Lock()
	f.api.cert = short
	f.api.mu.Unlock()
	old.Certificate = short.State.Certificate
	old.Chain = short.State.Chain
	old.CertificateExpiry = short.State.Expiry
	if err := c.store.Save(t.Context(), "default", *old); err != nil {
		t.Fatal(err)
	}
	x := connectTest(t, c, Routes{"@": echoTarget(t)})
	s := f.next(t)
	established := s.public(t, 1, "demo.test")
	waitStatus(t, x, func(st Status) bool { return st.State == "waiting-certificate" })
	// #nosec G402 -- Bypass expiry client-side to prove the SDK rejects expired handshakes itself.
	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: "demo.test", MinVersion: tls.VersionTLS12}
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		leaf := cs.PeerCertificates[0]
		if err := leaf.VerifyHostname("demo.test"); err != nil {
			return err
		}
		return leaf.CheckSignatureFrom(f.api.authority.cert)
	}
	invalid := tls.Client(s.publicRaw(t, 2, "demo.test"), cfg)
	defer func() { _ = invalid.Close() }()
	_ = invalid.SetDeadline(time.Now().Add(time.Second))
	if err := invalid.HandshakeContext(t.Context()); err == nil {
		t.Fatal("SDK served an expired certificate to a client that ignored expiry")
	}
	if _, err := established.Write([]byte("existing")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 8)
	if _, err := io.ReadFull(established, b); err != nil || string(b) != "existing" {
		t.Fatalf("expiry interrupted established TLS: %q %v", b, err)
	}
	f.api.mu.Lock()
	renewed, err := f.api.authority.issue(f.api.csr, 92)
	f.api.cert = renewed
	f.api.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	waitStatus(t, x, func(st Status) bool { return st.State == "connected" })
	_ = s.public(t, 3, "demo.test")
}

func TestValidIdentityConnectsDuringCertificateAPIOutage(t *testing.T) {
	f := newRelay(t)
	var outage atomic.Bool
	original := f.api.bridge
	f.api.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/connect") {
			original(w, r)
			return
		}
		if outage.Load() && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/certificate") {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		f.api.serve(w, r)
	})
	c := tunnelClient(t, f, TransportOptions{})
	if _, err := c.Create(t.Context(), "", ProvisionOptions{}); err != nil {
		t.Fatal(err)
	}
	outage.Store(true)
	x := connectTest(t, c, Routes{"@": echoTarget(t)})
	_ = f.next(t).public(t, 1, "demo.test")
	if x.Status().State != "connected" {
		t.Fatalf("valid local identity could not connect: %+v", x.Status())
	}
}
