package opentunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestAggregateInboundBudgetIsSharedAndReleasedExactlyOnce(t *testing.T) {
	opts, err := transportDefaults(TransportOptions{MaxInboundBytes: 6, MaxInboundTotalBytes: 6})
	if err != nil {
		t.Fatal(err)
	}
	x := &Connection{ctx: t.Context(), client: &Client{options: opts}}
	s := newSession(x, Routes{"@": "unused"})
	t.Cleanup(s.cancel)
	a := newBridgeConn(s, 1, "first", opts.MaxInboundBytes)
	b := newBridgeConn(s, 2, "second", opts.MaxInboundBytes)

	if !a.push([]byte("1234")) {
		t.Fatal("first channel unexpectedly rejected")
	}
	if b.push([]byte("abc")) {
		t.Fatal("channels retained more than the session aggregate limit")
	}
	if got := s.inboundBytes.Load(); got != 4 {
		t.Fatalf("reserved bytes after rejected push = %d, want 4", got)
	}

	buf := make([]byte, 2)
	if n, err := a.Read(buf); n != 2 || err != nil {
		t.Fatalf("read = %d, %v", n, err)
	}
	if !b.push([]byte("abc")) {
		t.Fatal("read bytes were not returned to the aggregate budget")
	}
	if got := s.inboundBytes.Load(); got != 5 {
		t.Fatalf("reserved bytes after read and push = %d, want 5", got)
	}

	a.abort(io.ErrUnexpectedEOF)
	a.abort(io.ErrUnexpectedEOF)
	if got := s.inboundBytes.Load(); got != 3 {
		t.Fatalf("abort released retained bytes more or less than once: %d", got)
	}
	buf = make([]byte, 3)
	if n, err := b.Read(buf); n != 3 || err != nil {
		t.Fatalf("second read = %d, %v", n, err)
	}
	b.abort(io.ErrUnexpectedEOF)
	if got := s.inboundBytes.Load(); got != 0 {
		t.Fatalf("aggregate reservation leaked: %d", got)
	}
}

func TestAggregateInboundBudgetDefaultsAndRejectsNegativeValues(t *testing.T) {
	opts, err := transportDefaults(TransportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if opts.MaxInboundTotalBytes != 64*1024*1024 {
		t.Fatalf("default aggregate inbound budget = %d, want 67108864", opts.MaxInboundTotalBytes)
	}
	if _, err := transportDefaults(TransportOptions{MaxInboundTotalBytes: -1}); err == nil {
		t.Fatal("negative aggregate inbound budget accepted")
	}
}

func TestStandaloneBridgeReservationAccountingReturnsToZero(t *testing.T) {
	for _, limit := range []int64{0, -1} {
		s := &session{ctx: t.Context(), inboundLimit: limit}
		b := newBridgeConn(s, 1, "peer", 8)
		if !b.push([]byte("1234")) {
			t.Fatalf("standalone bridge with limit %d rejected data", limit)
		}
		if got := s.inboundBytes.Load(); got != 4 {
			t.Fatalf("standalone reservation with limit %d = %d, want 4", limit, got)
		}
		b.abort(io.ErrUnexpectedEOF)
		if got := s.inboundBytes.Load(); got != 0 {
			t.Fatalf("standalone reservation with limit %d after abort = %d, want 0", limit, got)
		}
	}
}

func TestConcurrentInboundReservationsNeverExceedLimitOrLeak(t *testing.T) {
	opts, err := transportDefaults(TransportOptions{MaxInboundBytes: 256, MaxInboundTotalBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	x := &Connection{ctx: t.Context(), client: &Client{options: opts}}
	s := newSession(x, Routes{"@": "unused"})
	t.Cleanup(s.cancel)
	var exceeded atomic.Bool
	var wg sync.WaitGroup
	for id := uint32(1); id <= 32; id++ {
		wg.Add(1)
		go func(id uint32) {
			defer wg.Done()
			for range 50 {
				b := newBridgeConn(s, id, "peer", opts.MaxInboundBytes)
				for range 8 {
					if !b.push(bytes.Repeat([]byte{'x'}, 64)) {
						break
					}
					if s.inboundBytes.Load() > int64(opts.MaxInboundTotalBytes) {
						exceeded.Store(true)
					}
					buf := make([]byte, 17)
					if _, err := b.Read(buf); err != nil {
						t.Errorf("partial read: %v", err)
						break
					}
				}
				b.abort(io.ErrUnexpectedEOF)
			}
		}(id)
	}
	wg.Wait()
	if exceeded.Load() {
		t.Fatal("concurrent reservations exceeded aggregate limit")
	}
	if got := s.inboundBytes.Load(); got != 0 {
		t.Fatalf("concurrent reservations leaked %d bytes", got)
	}
}

func TestRelayMetadataCannotExposeTokenOrControlText(t *testing.T) {
	for _, tc := range []struct {
		name     string
		metadata func(string) string
	}{
		{name: "tunnel token", metadata: func(token string) string { return "peer=" + token }},
		{name: "control characters", metadata: func(string) string { return "peer\r\nforged" }},
		{name: "oversized", metadata: func(string) string { return strings.Repeat("x", 1024) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRelay(t)
			metadata := tc.metadata(f.api.token)
			f.mu.Lock()
			f.sessionID = metadata
			f.peer = metadata
			f.routes = []string{"@", metadata}
			f.mu.Unlock()

			c := tunnelClient(t, f, TransportOptions{})
			l := listenTest(t, c, ListenOptions{Routes: []string{"@"}})
			s := f.next(t)
			status := l.Status()
			if unsafeRelayMetadata(status.Session, f.api.token) {
				t.Fatal("relay session metadata remained unsafe in Status")
			}

			connected := nextEventType(t, l.Events(), "connected")
			if unsafeRelayMetadata(connected.Session, f.api.token) {
				t.Fatal("relay session metadata remained unsafe in Event")
			}
			for _, route := range connected.Routes {
				if unsafeRelayMetadata(route, f.api.token) {
					t.Fatal("relay route metadata remained unsafe in Event")
				}
			}

			_ = s.public(t, 1, "demo.test")
			accepted := acceptTest(t, l)
			if unsafeRelayMetadata(accepted.RemoteAddr().String(), f.api.token) {
				t.Fatal("relay peer metadata remained unsafe in RemoteAddr")
			}
			opened := nextEventType(t, l.Events(), "connection-opened")
			if unsafeRelayMetadata(opened.Peer, f.api.token) {
				t.Fatal("relay peer metadata remained unsafe in Event")
			}
		})
	}
}

func TestRelayMetadataPreservesNormalDiagnostics(t *testing.T) {
	f := newRelay(t)
	f.mu.Lock()
	f.sessionID = "session-42"
	f.peer = "198.51.100.8:443"
	f.routes = []string{"@", "api"}
	f.mu.Unlock()
	c := tunnelClient(t, f, TransportOptions{})
	l := listenTest(t, c, ListenOptions{Routes: []string{"@"}})
	s := f.next(t)
	if got := l.Status().Session; got != "session-42" {
		t.Fatalf("normal session metadata changed: %q", got)
	}
	connected := nextEventType(t, l.Events(), "connected")
	if connected.Session != "session-42" || strings.Join(connected.Routes, ",") != "@,api" {
		t.Fatalf("normal connected event changed: %+v", connected)
	}
	_ = s.public(t, 1, "demo.test")
	accepted := acceptTest(t, l)
	if got := accepted.RemoteAddr().String(); got != "198.51.100.8:443" {
		t.Fatalf("normal peer metadata changed: %q", got)
	}
	opened := nextEventType(t, l.Events(), "connection-opened")
	if opened.Peer != "198.51.100.8:443" {
		t.Fatalf("normal peer event changed: %+v", opened)
	}
}

func TestRelayEventRoutesAreBounded(t *testing.T) {
	for _, tc := range []struct {
		name      string
		count     int
		route     string
		wantCount int
		wantBytes int
	}{
		{name: "count cap", count: 300, route: "r", wantCount: 256, wantBytes: 256},
		{name: "byte cap", count: 200, route: strings.Repeat("r", 200), wantCount: 81, wantBytes: 16_200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRelay(t)
			f.mu.Lock()
			f.routes = make([]string, tc.count)
			for i := range f.routes {
				f.routes[i] = tc.route
			}
			f.mu.Unlock()
			c := tunnelClient(t, f, TransportOptions{})
			l := listenTest(t, c, ListenOptions{Routes: []string{"@"}})
			_ = f.next(t)
			event := nextEventType(t, l.Events(), "connected")
			total := 0
			for _, route := range event.Routes {
				total += len(route)
			}
			if len(event.Routes) != tc.wantCount || total != tc.wantBytes {
				t.Fatalf("connected event routes = %d entries/%d bytes, want %d/%d", len(event.Routes), total, tc.wantCount, tc.wantBytes)
			}
		})
	}
}

func TestAggregateInboundOverflowResetsOneChannelAndReleasesSessionBudget(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{MaxInboundBytes: 256 * 1024, MaxInboundTotalBytes: 48 * 1024})
	l := listenTest(t, c, ListenOptions{Routes: []string{"@"}})
	s := f.next(t)
	public := s.public(t, 1, "demo.test")
	server := acceptTest(t, l)
	writeDone := make(chan error, 1)
	go func() {
		_, err := public.Write(bytes.Repeat([]byte{'x'}, 96*1024))
		writeDone <- err
	}()
	reset := s.nextControl(t, "reset")
	if reset.Conn != 1 {
		t.Fatalf("aggregate overflow reset connection %d, want 1", reset.Conn)
	}
	_ = server.Close()
	waitStatus(t, l.connection, func(status Status) bool { return status.Connections == 0 })

	healthyPublic := s.public(t, 2, "demo.test")
	healthyServer := acceptTest(t, l)
	if _, err := healthyPublic.Write([]byte("healthy")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len("healthy"))
	if _, err := io.ReadFull(healthyServer, reply); err != nil || string(reply) != "healthy" {
		t.Fatalf("new channel after aggregate reset = %q, %v", reply, err)
	}
	if status := l.Status(); status.State != "connected" {
		t.Fatalf("aggregate overflow stopped session: %+v", status)
	}
	select {
	case <-writeDone: //nolint:errcheck // Overflow must unblock the writer; its result is not asserted.
	case <-time.After(6 * time.Second):
		t.Fatal("overflowed public writer did not stop")
	}
}

func TestTLSHandshakeDiagnosticDoesNotExposeClientALPN(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	x := connectTest(t, c, Routes{"@": echoTarget(t)})
	s := f.next(t)
	protocols := make([]string, 0, 122)
	protocols = append(protocols, "token-"+f.api.token, "line\r\nforged")
	for range 120 {
		protocols = append(protocols, strings.Repeat("x", 250))
	}
	raw := s.publicRaw(t, 77, "demo.test")
	visitor := tls.Client(raw, &tls.Config{
		RootCAs:    f.api.authority.roots,
		ServerName: "demo.test",
		MinVersion: tls.VersionTLS12,
		NextProtos: protocols,
	})
	_ = visitor.SetDeadline(time.Now().Add(5 * time.Second))
	if err := visitor.HandshakeContext(t.Context()); err == nil {
		t.Fatal("unsupported ALPN handshake succeeded")
	}
	_ = visitor.Close()

	event := nextConnectionEvent(t, x.Events(), 77)
	if event.Error != "TLS handshake failed" {
		t.Fatalf("TLS diagnostic = %q", event.Error)
	}
	if unsafeRelayMetadata(event.Error, f.api.token) {
		t.Fatal("TLS diagnostic retained unsafe client input")
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > 512 || bytes.Contains(encoded, []byte(f.api.token)) || bytes.Contains(encoded, []byte("forged")) {
		t.Fatalf("serialized close event retained unsafe client input: %d bytes", len(encoded))
	}
}

func TestTLSHandshakeDiagnosticPreservesTrustedClassification(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
		is   error
	}{
		{name: "route mismatch", err: ErrRouteMismatch, want: "TLS handshake failed: " + ErrRouteMismatch.Error(), is: ErrRouteMismatch},
		{name: "expired certificate", err: ErrCertificateExpired, want: "TLS handshake failed: " + ErrCertificateExpired.Error(), is: ErrCertificateExpired},
		{name: "invalid certificate", err: ErrInvalid, want: "TLS handshake failed: " + ErrInvalid.Error(), is: ErrInvalid},
		{name: "timeout", err: context.DeadlineExceeded, want: "TLS handshake timed out: " + context.DeadlineExceeded.Error(), is: context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tlsHandshakeFailure(tc.err)
			if got.Error() != tc.want {
				t.Fatalf("diagnostic = %q, want %q", got, tc.want)
			}
			if !errors.Is(got, tc.is) {
				t.Fatalf("diagnostic does not retain %v", tc.is)
			}
		})
	}
}

func TestCertificateRefreshAppliesChainOnlyChange(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	x := manualRefreshConnection(t, c)
	original := x.Identity()
	updatedChain := original.Chain + original.Chain
	f.api.mu.Lock()
	f.api.cert = CertificateInfo{ID: "chain-update", State: CertificateState{
		Type:        "ready",
		Certificate: original.Certificate,
		Chain:       updatedChain,
		Expiry:      original.CertificateExpiry,
	}}
	f.api.mu.Unlock()

	if err := x.refreshOnce(); err != nil {
		t.Fatal(err)
	}
	if got := x.Identity().Chain; got != updatedChain {
		t.Fatal("certificate refresh ignored a chain-only change")
	}
	stored, err := c.store.Load(t.Context(), "default")
	if err != nil || stored == nil || stored.Chain != updatedChain {
		t.Fatalf("stored chain was not refreshed: present=%v err=%v", stored != nil, err)
	}
	serverRaw, clientRaw := net.Pipe()
	serverTLS := tls.Server(serverRaw, channelTLS(x.cert))
	clientTLS := tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // Local certificate-chain probe.
	serverDone := make(chan error, 1)
	go func() { serverDone <- serverTLS.HandshakeContext(t.Context()) }()
	if err := clientTLS.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if got := len(clientTLS.ConnectionState().PeerCertificates); got != 3 {
		t.Fatalf("served certificate chain contains %d certificates, want 3", got)
	}
	_ = clientRaw.Close()
	_ = serverRaw.Close()
}

func TestConnectAndListenRecoverFailedRemoteCertificateInBackground(t *testing.T) {
	for _, mode := range []string{"connect", "listen"} {
		t.Run(mode, func(t *testing.T) {
			f := newRelay(t)
			c := tunnelClient(t, f, TransportOptions{})
			original, err := c.Ensure(t.Context(), "")
			if err != nil {
				t.Fatal(err)
			}
			baseSubmissions := f.api.submissions.Load()
			f.api.mu.Lock()
			f.api.cert = CertificateInfo{ID: "failed", State: CertificateState{Type: "failed", Reason: "test renewal failure"}}
			f.api.mu.Unlock()

			var running *Connection
			if mode == "connect" {
				running, err = c.Connect(t.Context(), ConnectOptions{Routes: Routes{"@": echoTarget(t)}})
			} else {
				var listener *Listener
				listener, err = c.Listen(t.Context(), ListenOptions{Routes: []string{"@"}})
				if listener != nil {
					running = listener.connection
				}
			}
			if err != nil {
				t.Fatalf("%s with valid local certificate: %v", mode, err)
			}
			_ = f.next(t)
			_ = nextEventType(t, running.Events(), "certificate-recovery-started")
			_ = nextEventType(t, running.Events(), "certificate-renewed")

			updated := running.Identity()
			if updated.Certificate == original.Certificate {
				t.Fatal("background recovery did not install a replacement certificate")
			}
			if updated.PrivateKey != original.PrivateKey || updated.ID != original.ID || updated.Token != original.Token {
				t.Fatal("background recovery replaced stable identity credentials")
			}
			oldCert, err := parseCertificate(*original)
			if err != nil {
				t.Fatal(err)
			}
			newCert, err := parseCertificate(updated)
			if err != nil {
				t.Fatal(err)
			}
			oldPublic, err := x509.MarshalPKIXPublicKey(oldCert.Leaf.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			newPublic, err := x509.MarshalPKIXPublicKey(newCert.Leaf.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(oldPublic, newPublic) {
				t.Fatal("replacement CSR used a different key")
			}
			stored, err := c.store.Load(t.Context(), "default")
			if err != nil || stored == nil || stored.Certificate != updated.Certificate || stored.PrivateKey != original.PrivateKey {
				t.Fatalf("recovered identity was not persisted: present=%v err=%v", stored != nil, err)
			}
			pending, err := c.store.LoadPending(t.Context(), "default")
			if err != nil || pending != nil {
				t.Fatalf("completed recovery retained pending state: present=%v err=%v", pending != nil, err)
			}
			if got := f.api.submissions.Load() - baseSubmissions; got != 1 {
				t.Fatalf("background recovery submitted %d CSRs, want 1", got)
			}
		})
	}
}

func TestIdleDetectionDoesNotWaitForLongerHeartbeatInterval(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	s := &session{ctx: ctx, cancel: cancel}
	s.lastReceived.Store(time.Now().Add(-6 * time.Second).UnixNano())
	done := make(chan struct{})
	go func() {
		s.heartbeat(60_000, 5_000)
		close(done)
	}()

	select {
	case <-ctx.Done():
	case <-time.After(250 * time.Millisecond):
		t.Fatal("idle session remained live until its longer heartbeat interval")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("heartbeat worker did not stop after idle cancellation")
	}
}

func TestHeartbeatPingUsesPriorityQueueWhenDataQueueIsFull(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s := &session{
		ctx:            ctx,
		cancel:         cancel,
		owner:          &Connection{client: &Client{options: TransportOptions{WriteTimeout: 5 * time.Second}}},
		queue:          make(chan outbound, 1),
		controls:       make(chan outbound, 1),
		readerControls: make(chan outbound, 1),
	}
	s.queue <- outbound{}
	s.lastReceived.Store(time.Now().UnixNano())
	done := make(chan struct{})
	go func() {
		s.heartbeat(1, 45_000)
		close(done)
	}()

	select {
	case ping := <-s.readerControls:
		message, ok := decodeControl(ping.data)
		if !ok || message.Type != "ping" {
			t.Fatalf("priority message = %q", ping.data)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("heartbeat blocked behind the full data queue")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("heartbeat did not stop after cancellation")
	}
}

func TestPongUsesPriorityQueueWhenDataQueueIsFull(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s := &session{ctx: ctx, cancel: cancel, queue: make(chan outbound, 1), controls: make(chan outbound, 1), readerControls: make(chan outbound, 1)}
	s.queue <- outbound{}
	done := make(chan struct{})
	go func() {
		s.replyToPing(42)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("pong blocked behind the full data queue")
	}
	select {
	case pong := <-s.readerControls:
		message, ok := decodeControl(pong.data)
		if !ok || message.Type != "pong" || message.TimeSent != 42 {
			t.Fatalf("priority message = %q", pong.data)
		}
	default:
		t.Fatal("pong was not placed on the priority queue")
	}
}

func TestRejectedOpenUsesPriorityQueueWhenDataQueueIsFull(t *testing.T) {
	for _, tc := range []struct {
		name string
		code string
		sni  string
		set  func(*Connection, *session)
	}{
		{name: "unknown route", code: "unknown_route", sni: "missing.demo.test", set: func(*Connection, *session) {}},
		{name: "connection capacity", code: "too_many_connections", sni: "demo.test", set: func(x *Connection, s *session) {
			x.routes = Routes{"@": "unused"}
			s.channels[9] = &channel{}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			x := &Connection{
				ctx:      ctx,
				client:   &Client{options: TransportOptions{MaxConnections: 1, WriteTimeout: 5 * time.Second}},
				identity: Identity{Hostname: "demo.test"},
				routes:   Routes{"@": "unused"},
			}
			s := &session{owner: x, ctx: ctx, cancel: cancel, queue: make(chan outbound, 1), controls: make(chan outbound, 1), readerControls: make(chan outbound, 1), channels: make(map[uint32]*channel)}
			s.queue <- outbound{}
			tc.set(x, s)
			done := make(chan struct{})
			go func() {
				s.open(controlMessage{Type: "open", Conn: 7, SNI: tc.sni})
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(100 * time.Millisecond):
				t.Fatal("open rejection blocked behind the full data queue")
			}
			select {
			case reset := <-s.readerControls:
				message, ok := decodeControl(reset.data)
				if !ok || message.Type != "reset" || message.Conn != 7 || message.Code != tc.code {
					t.Fatalf("priority reset = %q", reset.data)
				}
			default:
				t.Fatal("open rejection did not enqueue a priority reset")
			}
		})
	}
}

func TestRejectedOpenWaitsForPriorityQueueWithoutCancellingSession(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	x := &Connection{
		ctx:      ctx,
		client:   &Client{options: TransportOptions{MaxConnections: 1, WriteTimeout: time.Second}},
		identity: Identity{Hostname: "demo.test"},
		routes:   Routes{"@": "unused"},
	}
	s := &session{owner: x, ctx: ctx, cancel: cancel, queue: make(chan outbound, 1), controls: make(chan outbound, 1), readerControls: make(chan outbound, 1), channels: make(map[uint32]*channel)}
	s.queue <- outbound{}
	s.readerControls <- outbound{ctx: ctx}
	done := make(chan struct{})
	go func() {
		s.open(controlMessage{Type: "open", Conn: 7, SNI: "missing.demo.test"})
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("rejected open dropped or cancelled instead of applying priority backpressure")
	case <-time.After(50 * time.Millisecond):
	}
	select {
	case <-ctx.Done():
		t.Fatal("temporary priority backpressure cancelled the session")
	default:
	}
	<-s.readerControls
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("rejected open did not continue when priority capacity became available")
	}
	select {
	case reset := <-s.readerControls:
		message, ok := decodeControl(reset.data)
		if !ok || message.Type != "reset" || message.Code != "unknown_route" {
			t.Fatalf("priority reset = %q", reset.data)
		}
	default:
		t.Fatal("rejected open did not enqueue its reset")
	}
}

func TestReaderControlBackpressureReservesTeardownCapacityAndCancelsPromptly(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	s := &session{
		ctx:            ctx,
		cancel:         cancel,
		controls:       make(chan outbound, 1),
		readerControls: make(chan outbound, 1),
	}
	s.readerControls <- outbound{ctx: ctx}
	readerDone := make(chan struct{})
	go func() {
		s.enqueueReaderControl(controlMessage{Type: "pong", TimeSent: 42})
		close(readerDone)
	}()
	select {
	case <-readerDone:
		t.Fatal("reader control did not apply bounded backpressure")
	case <-time.After(50 * time.Millisecond):
	}

	s.enqueueControl(controlMessage{Type: "reset", Conn: 7, Code: "client_io_error"})
	select {
	case queued := <-s.controls:
		message, ok := decodeControl(queued.data)
		if !ok || message.Type != "reset" || message.Conn != 7 {
			t.Fatalf("reserved teardown control = %q", queued.data)
		}
	default:
		t.Fatal("reader backpressure consumed teardown capacity")
	}
	select {
	case <-ctx.Done():
		t.Fatal("reader backpressure cancelled a healthy session")
	default:
	}

	cancel()
	select {
	case <-readerDone:
	case <-time.After(time.Second):
		t.Fatal("blocked reader control did not stop after session cancellation")
	}
}

func TestHeartbeatCoalescesAndSkipsFullReaderQueue(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s := &session{
		ctx:            ctx,
		cancel:         cancel,
		controls:       make(chan outbound, 1),
		readerControls: make(chan outbound, 1),
	}
	s.readerControls <- outbound{ctx: ctx}
	s.enqueueHeartbeat()
	if s.heartbeatPending.Load() {
		t.Fatal("skipped heartbeat remained pending")
	}
	select {
	case <-ctx.Done():
		t.Fatal("full reader queue cancelled the session on a heartbeat tick")
	default:
	}
	select {
	case message := <-s.controls:
		t.Fatalf("heartbeat consumed teardown capacity: %q", message.data)
	default:
	}

	<-s.readerControls
	s.enqueueHeartbeat()
	s.enqueueHeartbeat()
	if got := len(s.readerControls); got != 1 {
		t.Fatalf("coalesced heartbeat queue length = %d, want 1", got)
	}
	if !s.heartbeatPending.Load() {
		t.Fatal("queued heartbeat was not marked pending")
	}
	queued := <-s.readerControls
	message, ok := decodeControl(queued.data)
	if !ok || message.Type != "ping" || !queued.heartbeat {
		t.Fatalf("queued heartbeat = %q", queued.data)
	}
}

func TestLiveHeartbeatRearmsAfterWriterSendsPing(t *testing.T) {
	f := newRelay(t)
	f.mu.Lock()
	f.heartbeat = 1_000
	f.idle = 45_000
	f.noPong = true
	f.mu.Unlock()
	c := tunnelClient(t, f, TransportOptions{})
	l := listenTest(t, c, ListenOptions{Routes: []string{"@"}})
	s := f.next(t)

	first := s.nextControl(t, "ping")
	if err := s.control(controlMessage{Type: "pong", TimeSent: first.TimeSent}); err != nil {
		t.Fatal(err)
	}
	second := s.nextControl(t, "ping")
	if second.TimeSent <= first.TimeSent {
		t.Fatalf("heartbeat timestamps did not advance: first=%d second=%d", first.TimeSent, second.TimeSent)
	}
	if s.ctx.Err() != nil || l.Status().State != "connected" {
		t.Fatalf("heartbeat re-arm stopped healthy session: relay=%v status=%+v", s.ctx.Err(), l.Status())
	}
	select {
	case <-f.sessions:
		t.Fatal("heartbeat re-arm caused relay reattachment")
	default:
	}
}

func TestLiveRelayControlBurstsDoNotCancelHealthySession(t *testing.T) {
	for _, tc := range []struct {
		name string
		send func(*relaySession, uint32) error
		want string
	}{
		{name: "pings", want: "pong", send: func(s *relaySession, i uint32) error {
			return s.control(controlMessage{Type: "ping", TimeSent: int64(i)})
		}},
		{name: "unknown opens", want: "reset", send: func(s *relaySession, i uint32) error {
			return s.control(controlMessage{Type: "open", Conn: i + 1, Peer: "198.51.100.8:443", SNI: "missing.demo.test", ALPN: "http/1.1"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRelay(t)
			c := tunnelClient(t, f, TransportOptions{})
			l := listenTest(t, c, ListenOptions{Routes: []string{"@"}})
			s := f.next(t)
			const burst uint32 = 5000
			for i := uint32(0); i < burst; i++ {
				if err := tc.send(s, i); err != nil {
					t.Fatalf("send control %d: %v", i, err)
				}
			}
			timer := time.NewTimer(10 * time.Second)
			defer timer.Stop()
			seen := uint32(0)
			for seen < burst {
				select {
				case message := <-s.controls:
					if message.Type == tc.want {
						seen++
					}
				case <-timer.C:
					t.Fatalf("received %d of %d %s controls", seen, burst, tc.want)
				}
			}
			if s.ctx.Err() != nil {
				t.Fatal("healthy relay session was cancelled by a valid control burst")
			}
			if status := l.Status(); status.State != "connected" {
				t.Fatalf("control burst changed listener state: %+v", status)
			}
			select {
			case <-f.sessions:
				t.Fatal("control burst caused a relay reattachment")
			default:
			}
		})
	}
}

func TestLiveRejectedOpenBurstCannotStarveRealChannelTeardown(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	l := listenTest(t, c, ListenOptions{Routes: []string{"@"}})
	s := f.next(t)
	const rejected uint32 = 5000
	const realConnBase uint32 = 100_000
	const realEvery uint32 = 50
	const realCount = rejected / realEvery
	for i := uint32(0); i < rejected; i++ {
		if i%realEvery == 0 {
			id := realConnBase + i/realEvery
			if err := s.control(controlMessage{Type: "open", Conn: id, Peer: "198.51.100.8:443", SNI: "demo.test", ALPN: "http/1.1"}); err != nil {
				t.Fatalf("send real open %d: %v", id, err)
			}
			if err := s.ws.Write(s.ctx, websocket.MessageBinary, encodeFrame(id, []byte("not a TLS client"))); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.control(controlMessage{Type: "open", Conn: i + 1, Peer: "198.51.100.8:443", SNI: "missing.demo.test", ALPN: "http/1.1"}); err != nil {
			t.Fatalf("send rejected open %d: %v", i, err)
		}
	}
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	unknown, teardown := uint32(0), uint32(0)
	for unknown < rejected || teardown < realCount {
		select {
		case message := <-s.controls:
			if message.Type != "reset" {
				continue
			}
			switch {
			case message.Conn >= realConnBase && message.Code == "client_io_error":
				teardown++
			case message.Code == "unknown_route":
				unknown++
			}
		case <-timer.C:
			t.Fatalf("received %d/%d rejected-open resets; teardown=%d/%d", unknown, rejected, teardown, realCount)
		}
	}
	if s.ctx.Err() != nil {
		t.Fatal("reader burst plus real channel teardown cancelled the healthy session")
	}
	if status := l.Status(); status.State != "connected" {
		t.Fatalf("mixed burst changed listener state: %+v", status)
	}
	select {
	case <-f.sessions:
		t.Fatal("mixed burst caused a relay reattachment")
	default:
	}
}

func nextConnectionEvent(t *testing.T, events <-chan Event, conn uint32) Event {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case event := <-events:
			if event.Type == "connection-closed" && event.Conn == conn {
				return event
			}
		case <-timer.C:
			t.Fatalf("no connection-closed event for %d", conn)
		}
	}
}

func nextEventType(t *testing.T, events <-chan Event, eventType string) Event {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case event := <-events:
			if event.Type == eventType {
				return event
			}
		case <-timer.C:
			t.Fatalf("no %s event", eventType)
		}
	}
}

func unsafeRelayMetadata(value, token string) bool {
	if len(value) > 256 || (token != "" && strings.Contains(value, token)) {
		return true
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return true
		}
	}
	return false
}
