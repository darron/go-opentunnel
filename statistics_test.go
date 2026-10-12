package opentunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// These tests catch header-only duration measurement, lost validation errors,
// duplicate completion and totals reconstructed from lossy events/live owners.
func TestAPIStatisticsCompletedRequests(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		wantErrors uint64
	}{
		{"success", `{"id":"demo","hostname":"demo.test","state":"online"}`, 200, 0},
		{"rejected", `{"_tag":"not_found"}`, 404, 1},
		{"malformed JSON", `{`, 200, 1},
		{"invalid fields", `{}`, 200, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			c, err := NewClient(ClientOptions{API: server.URL, Storage: NewMemoryStorage()})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			_, err = c.API().Get(t.Context(), "demo", "token")
			if (err != nil) != (tc.wantErrors != 0) {
				t.Fatalf("error = %v", err)
			}
			s := c.API().Stats()
			if s.APIRequests != 1 || s.APIErrors != tc.wantErrors || s.APIDuration <= 0 {
				t.Fatalf("stats = %+v", s)
			}
			if got := c.Stats(); got != s {
				t.Fatalf("client stats = %+v, API = %+v", got, s)
			}
			_, _ = c.API().Get(nil, "demo", "token") //nolint:staticcheck // Nil is intentional: verify rejected inputs are not counted.
			if c.API().Stats() != s {
				t.Fatal("nil context counted")
			}
		})
	}
}

func TestAPIStatisticsIncludeBodyReadAndTimeout(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(map[bool]string{false: "delayed body", true: "body timeout"}[timeout], func(t *testing.T) {
			release := make(chan struct{})
			headers := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				if err := http.NewResponseController(w).Flush(); err != nil {
					t.Error(err)
					return
				}
				close(headers)
				select {
				case <-release:
					_, _ = io.WriteString(w, `{"id":"demo","hostname":"demo.test","state":"online"}`)
				case <-r.Context().Done():
				}
			}))
			defer server.Close()
			defer close(release)
			a, err := NewAPI(server.URL, nil, 100*time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { _, err := a.Get(t.Context(), "demo", "token"); done <- err }()
			<-headers
			if got := a.Stats(); got.APIRequests != 0 {
				t.Fatalf("incomplete request counted: %+v", got)
			}
			if !timeout {
				time.Sleep(25 * time.Millisecond)
				release <- struct{}{}
			}
			err = <-done
			if (err != nil) != timeout {
				t.Fatalf("error=%v", err)
			}
			got := a.Stats()
			wantErrors := uint64(0)
			minDuration := 25 * time.Millisecond
			if timeout {
				wantErrors = 1
				minDuration = 90 * time.Millisecond
			}
			if got.APIRequests != 1 || got.APIErrors != wantErrors || got.APIDuration < minDuration {
				t.Fatalf("stats=%+v", got)
			}
		})
	}
}

func TestAPIStatisticsTransportFailure(t *testing.T) {
	a, err := NewAPI("https://api.test", &http.Client{Transport: &roundTripFunc{fn: func(*http.Request) (*http.Response, error) { return nil, errors.New("transport failed") }}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	err = a.Remove(t.Context(), "demo", "token")
	if err == nil {
		t.Fatal("expected transport failure")
	}
	if got := a.Stats(); got.APIRequests != 1 || got.APIErrors != 1 || got.APIDuration <= 0 {
		t.Fatalf("stats=%+v", got)
	}
}

type wireCountConn struct {
	net.Conn
	read, write atomic.Uint64
}

func (c *wireCountConn) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	if n > 0 {
		c.read.Add(uint64(n))
	}
	return n, e
}
func (c *wireCountConn) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	if n > 0 {
		c.write.Add(uint64(n))
	}
	return n, e
}

func waitStats(t *testing.T, source interface{ Stats() Stats }, predicate func(Stats) bool) Stats {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		s := source.Stats()
		if predicate(s) {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("statistics did not converge: %+v", s)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestStatisticsRelayPayloadAndRetainedTotals(t *testing.T) {
	for _, mode := range []string{"connect", "listen"} {
		t.Run(mode, func(t *testing.T) {
			f := newRelay(t)
			c := tunnelClient(t, f, TransportOptions{EventBuffer: 1, MaxConnections: 1})
			var x *Connection
			var l *Listener
			if mode == "connect" {
				x = connectTest(t, c, Routes{"@": echoTarget(t)})
			} else {
				l = listenTest(t, c, ListenOptions{Routes: []string{"@"}})
				x = l.connection
			}
			relay := f.next(t)
			raw := &wireCountConn{Conn: relay.publicRaw(t, 1, "demo.test")}
			visitor := tls.Client(raw, &tls.Config{RootCAs: f.api.authority.roots, ServerName: "demo.test", MinVersion: tls.VersionTLS12})
			_ = visitor.SetDeadline(time.Now().Add(3 * time.Second))
			if err := visitor.HandshakeContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			var accepted *tls.Conn
			var copied chan struct{}
			if l != nil {
				waitStats(t, x, func(s Stats) bool { return s.ActiveConnections == 1 })
				deadline := time.Now().Add(time.Second)
				for len(l.pending) != 1 {
					if time.Now().After(deadline) {
						t.Fatal("pending visitor missing")
					}
					time.Sleep(time.Millisecond)
				}
				accepted = acceptTest(t, l)
				copied = make(chan struct{})
				go func() { _, _ = io.Copy(accepted, accepted); close(copied) }()
			}
			_, err := visitor.Write([]byte("payload"))
			if err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 7)
			if _, err = io.ReadFull(visitor, buf); err != nil || string(buf) != "payload" {
				t.Fatalf("echo=%q error=%v", buf, err)
			}
			if err := relay.control(controlMessage{Type: "open", Conn: 2, SNI: "demo.test"}); err != nil {
				t.Fatal(err)
			}
			relay.nextControl(t, "reset")
			s := waitStats(t, x, func(s Stats) bool {
				return s.ConnectionsRejected == 1 && s.BytesReceived == raw.write.Load() && s.BytesSent == raw.read.Load()
			})
			if s.BridgeAttempts != 1 || s.BridgeAttachments != 1 || s.BridgeFailures != 0 || s.Reconnects != 0 || s.ActiveBridges != 1 || s.ConnectionsOpened != 1 || s.ConnectionsClosed != 0 || s.ActiveConnections != 1 || s.DroppedEvents == 0 {
				t.Fatalf("active stats=%+v", s)
			}
			// Concurrent snapshots while workers are forwarding and tearing down.
			var snapshots sync.WaitGroup
			snapshots.Add(1)
			stop := make(chan struct{})
			go func() {
				defer snapshots.Done()
				for {
					select {
					case <-stop:
						return
					default:
						_ = x.Stats()
						_ = c.Stats()
						_ = c.API().Stats()
					}
				}
			}()
			_ = x.Close()
			close(stop)
			snapshots.Wait()
			_ = visitor.Close()
			if accepted != nil {
				_ = accepted.Close()
				<-copied
			}
			after := x.Stats()
			if after.ActiveBridges != 0 || after.ActiveConnections != 0 || after.InboundBufferedBytes != 0 || after.ConnectionsClosed != 1 || after.BridgeFailures != 0 {
				t.Fatalf("closed stats=%+v", after)
			}
			total := c.Stats()
			if total.BridgeAttempts != after.BridgeAttempts || total.BytesSent != after.BytesSent || total.BytesReceived != after.BytesReceived || total.DroppedEvents != after.DroppedEvents || total.ConnectionsClosed != 1 || total.ActiveBridges != 0 || total.ActiveConnections != 0 || total.InboundBufferedBytes != 0 {
				t.Fatalf("client stats=%+v, connection=%+v", total, after)
			}
			if total.APIRequests != c.API().Stats().APIRequests || total.APIRequests == 0 || after.APIRequests != 0 {
				t.Fatal("API scope incorrect")
			}
		})
	}
}

func TestStatisticsAttachFailureAndReconnect(t *testing.T) {
	t.Run("failed attach", func(t *testing.T) {
		f := newRelay(t)
		f.mu.Lock()
		f.attachCode = "bad_token"
		f.mu.Unlock()
		c := tunnelClient(t, f, TransportOptions{EventBuffer: 1})
		_, err := c.Connect(t.Context(), ConnectOptions{Routes: Routes{"@": echoTarget(t)}})
		if err == nil {
			t.Fatal("expected attach failure")
		}
		s := c.Stats()
		if s.BridgeAttempts != 1 || s.BridgeFailures != 1 || s.BridgeAttachments != 0 || s.ActiveBridges != 0 || s.Reconnects != 0 {
			t.Fatalf("stats=%+v", s)
		}
	})
	t.Run("reconnect", func(t *testing.T) {
		f := newRelay(t)
		c := tunnelClient(t, f, TransportOptions{EventBuffer: 1})
		x := connectTest(t, c, Routes{"@": echoTarget(t)})
		f.next(t).close()
		_ = f.next(t)
		s := waitStats(t, x, func(s Stats) bool { return s.BridgeAttachments == 2 })
		if s.BridgeAttempts != 2 || s.Reconnects != 1 || s.BridgeFailures != 0 || s.ActiveBridges != 1 {
			t.Fatalf("stats=%+v", s)
		}
		_ = x.Close()
		if c.Stats().ActiveBridges != 0 {
			t.Fatal("active bridge retained after close")
		}
	})
}

func TestStatisticsInboundBufferAndEvents(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c := &Client{}
	x := &Connection{client: c, ctx: ctx, events: make(chan Event, 1)}
	s := newSession(x, nil)
	s.inboundLimit = 8
	b := newBridgeConn(s, 1, "peer", 8)
	if !b.push([]byte("12345")) || b.push([]byte("6789")) {
		t.Fatal("buffer admission incorrect")
	}
	if got := x.Stats(); got.InboundBufferedBytes != 5 {
		t.Fatalf("stats=%+v", got)
	}
	_, _ = b.Read(make([]byte, 2))
	if x.Stats().InboundBufferedBytes != 3 {
		t.Fatal("read did not release bytes")
	}
	x.emit(Event{Type: "connection-opened"})
	x.emit(Event{Type: "connection-closed"})
	x.emit(Event{Type: "connecting"})
	if got := x.Stats(); got.DroppedEvents != 2 || got.ConnectionsOpened != 0 || got.ConnectionsClosed != 0 || got.BridgeAttempts != 0 {
		t.Fatalf("events changed operational counters=%+v", got)
	}
	b.abort(net.ErrClosed)
	b.abort(net.ErrClosed)
	if x.Stats().InboundBufferedBytes != 0 || c.Stats().InboundBufferedBytes != 0 || c.Stats().DroppedEvents != 2 {
		t.Fatal("buffer or event total incorrect")
	}
}

// A real socket closure after the first relay frame catches counters that only
// update after an entire logical bridgeConn.Write succeeds.
func TestStatisticsSuccessfulChunksBeforeSendFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = ws.CloseNow() }()
		_, _, _ = ws.Read(r.Context())
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ws, response, err := websocket.Dial(ctx, server.URL, nil)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws.CloseNow() }()
	c := &Client{options: TransportOptions{WriteTimeout: time.Second}}
	x := &Connection{client: c, ctx: ctx}
	s := newSession(x, nil)
	s.ws = ws
	writerDone := make(chan struct{})
	go func() { defer close(writerDone); s.writer() }()
	b := newBridgeConn(s, 1, "peer", 1024)
	data := make([]byte, 8<<20)
	n, err := b.Write(data)
	s.cancel()
	<-writerDone
	b.abort(net.ErrClosed)
	if err == nil || n <= 0 || n >= len(data) || n%32768 != 0 {
		t.Fatalf("partial send: n=%d error=%v", n, err)
	}
	successfulBytes := uint64(n) // #nosec G115 -- n is checked positive and below the bounded 8 MiB input above.
	if got := x.Stats(); got.BytesSent != successfulBytes || c.Stats().BytesSent != successfulBytes {
		t.Fatalf("successful chunks: n=%d stats=%+v", n, got)
	}
}

func TestAPIStatisticsSemanticValidationAcrossMethods(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		invoke     func(*API) error
		wantErrors uint64
	}{
		{"create valid", `{"tunnel":{"id":"demo","hostname":"demo.test","state":"offline"},"token":"test"}`, 201, func(a *API) error { _, e := a.Create(t.Context()); return e }, 0},
		{"create invalid", `{}`, 201, func(a *API) error { _, e := a.Create(t.Context()); return e }, 1},
		{"bind valid", `{"id":"cert","state":{"type":"issuing"}}`, 202, func(a *API) error { _, e := a.BindCertificate(t.Context(), "demo", "token", "csr"); return e }, 0},
		{"bind invalid", `{"id":"cert","state":{"type":"challenge"}}`, 202, func(a *API) error { _, e := a.BindCertificate(t.Context(), "demo", "token", "csr"); return e }, 1},
		{"certificate valid", `{"id":"cert","state":{"type":"issuing"}}`, 200, func(a *API) error { _, e := a.Certificate(t.Context(), "demo", "token"); return e }, 0},
		{"certificate invalid", `{"id":"cert","state":{"type":"ready"}}`, 200, func(a *API) error { _, e := a.Certificate(t.Context(), "demo", "token"); return e }, 1},
		{"remove valid", "", 204, func(a *API) error { return a.Remove(t.Context(), "demo", "token") }, 0},
		{"remove invalid", "", 403, func(a *API) error { return a.Remove(t.Context(), "demo", "token") }, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			a, e := NewAPI(server.URL, nil, time.Second)
			if e != nil {
				t.Fatal(e)
			}
			e = tc.invoke(a)
			if (e != nil) != (tc.wantErrors != 0) {
				t.Fatalf("error=%v", e)
			}
			if got := a.Stats(); got.APIRequests != 1 || got.APIErrors != tc.wantErrors || got.APIDuration <= 0 {
				t.Fatalf("stats=%+v", got)
			}
		})
	}
}

func TestStatisticsHandshakeAdmissionAndRejections(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{EventBuffer: 1})
	x := connectTest(t, c, Routes{"@": echoTarget(t)})
	relay := f.next(t)
	raw := relay.publicRaw(t, 1, "demo.test")
	defer func() { _ = raw.Close() }()
	initial := waitStats(t, x, func(s Stats) bool { return s.ActiveConnections == 1 })
	if initial.ConnectionsOpened != 1 || initial.ConnectionsClosed != 0 || initial.BytesReceived != 0 {
		t.Fatalf("pre-handshake stats=%+v", initial)
	}
	if err := relay.control(controlMessage{Type: "open", Conn: 2, SNI: "unknown.demo.test"}); err != nil {
		t.Fatal(err)
	}
	relay.nextControl(t, "reset")
	if err := relay.control(controlMessage{Type: "open", Conn: 1, SNI: "demo.test"}); err != nil {
		t.Fatal(err)
	}
	s := waitStats(t, x, func(s Stats) bool { return s.ConnectionsRejected == 2 && s.ConnectionsClosed == 1 })
	if s.ConnectionsOpened != 1 || s.ActiveConnections != 0 {
		t.Fatalf("rejected admissions counted as opened: %+v", s)
	}
	_ = x.Close()
	if c.Stats().ConnectionsRejected != 2 || c.Stats().ConnectionsClosed != 1 {
		t.Fatal("admission totals discarded on close")
	}
}
