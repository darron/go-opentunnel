package opentunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// renewalSaveGate blocks renewal Save until released or cancelled, so a failing
// test cannot strand the refresh worker.
type renewalSaveGate struct {
	Storage
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func lifecycleTCPTarget(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = conn.Close() }()
				handle(conn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		wg.Wait()
	})
	return listener.Addr().String()
}

func (s *renewalSaveGate) Save(ctx context.Context, profile string, id Identity) error {
	if s.armed.Load() {
		s.once.Do(func() { close(s.entered) })
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.Storage.Save(ctx, profile, id)
}

func TestLifecycleRenewalSaveCannotResurrectRemovedIdentity(t *testing.T) {
	f := newRelay(t)
	gate := &renewalSaveGate{Storage: NewMemoryStorage(), entered: make(chan struct{}), release: make(chan struct{})}
	c, err := NewClient(ClientOptions{API: f.api.server.URL, Storage: gate, Transport: TransportOptions{
		CertificatePollInterval: 5 * time.Millisecond, CertificateRefreshInterval: 5 * time.Millisecond,
		BackoffMin: 5 * time.Millisecond, BackoffMax: 20 * time.Millisecond,
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	x := connectTest(t, c, Routes{"api": echoTarget(t)})
	_ = f.next(t)

	f.api.mu.Lock()
	cert, err := f.api.authority.issue(f.api.csr, 3)
	if err == nil {
		// Arm before publishing: refresh can save as soon as the API lock is released.
		gate.armed.Store(true)
		f.api.cert = cert
	}
	f.api.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-gate.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("renewal did not enter the Save barrier")
	}

	removed := make(chan error, 1)
	go func() { removed <- c.Remove(context.Background(), "") }()
	// Refresh holds the profile lock during Save. Remove must wait for release.
	select {
	case err := <-removed:
		t.Fatalf("Remove completed while renewal Save was blocked: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(gate.release)
	select {
	case err := <-removed:
		if err != nil {
			t.Fatalf("Remove: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Remove did not finish after renewal Save was released")
	}
	select {
	case <-x.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("connection did not stop during removal")
	}
	if id, err := c.Get(context.Background(), ""); err != nil || id != nil {
		t.Fatalf("renewal resurrected removed identity: identity=%v err=%v", id != nil, err)
	}
}

func TestLifecycleRemoteResetStopsBlockedUpstreamAndLeavesBridgeUsable(t *testing.T) {
	f := newRelay(t)
	blocked := make(chan struct{})
	target := lifecycleTCPTarget(t, func(conn net.Conn) {
		close(blocked)
		<-t.Context().Done()
	})
	c := tunnelClient(t, f, TransportOptions{WriteTimeout: time.Second})
	x := connectTest(t, c, Routes{"slow": target, "api": echoTarget(t)})
	s := f.next(t)
	slow := s.public(t, 1, "slow.demo.test")
	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("slow upstream was not attached")
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := slow.Write(bytes.Repeat([]byte("blocked-upstream"), 512*1024))
		writeDone <- err
	}()
	if err := s.control(controlMessage{Type: "reset", Conn: 1, Code: "peer_gone"}); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, x, func(status Status) bool { return status.Connections == 0 })
	select {
	case <-writeDone: //nolint:errcheck // Reset must unblock the writer; its result is not asserted.
	case <-time.After(2 * time.Second):
		t.Fatal("public writer remained blocked after remote reset")
	}
	healthy := s.public(t, 2, "api.demo.test")
	if _, err := healthy.Write([]byte("healthy")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len("healthy"))
	if _, err := io.ReadFull(healthy, reply); err != nil || string(reply) != "healthy" {
		t.Fatalf("healthy route after reset: %q %v", reply, err)
	}
}

func TestLifecycleFinalRouteNamesWinSessionTeardownRace(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	target := echoTarget(t)
	for i := 0; i < 4; i++ {
		x := connectTest(t, c, Routes{"old": target})
		old := f.next(t)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); old.close() }()
		go func() {
			defer wg.Done()
			if err := x.SetRoutes(Routes{"final": target}); err != nil && !errors.Is(err, ErrClosed) {
				t.Errorf("SetRoutes: %v", err)
			}
		}()
		wg.Wait()
		current := f.next(t)
		if len(current.routes) != 1 || current.routes[0] != "final" {
			t.Fatalf("iteration %d attached routes %v, want [final]", i, current.routes)
		}
		public := current.public(t, uint32(i+1), "final.demo.test")
		if _, err := public.Write([]byte("route-race")); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, len("route-race"))
		if _, err := io.ReadFull(public, reply); err != nil || string(reply) != "route-race" {
			t.Fatalf("iteration %d final route did not forward: %q %v", i, reply, err)
		}
		if err := x.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLifecycleOutboundQueueCancellationWhenRelayStopsReading(t *testing.T) {
	f := newRelay(t)
	paused := make(chan struct{})
	// Stop reading bridge frames after TLS completes and the pause marker arrives.
	f.api.bridge = func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"opentunnel"}})
		if err != nil {
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		s := &relaySession{fixture: f, ws: ws, ctx: ctx, cancel: cancel, channels: make(map[uint32]*relayChannel), controls: make(chan controlMessage, 8)}
		f.mu.Lock()
		f.all = append(f.all, s)
		f.mu.Unlock()
		_, b, err := ws.Read(ctx)
		m, ok := decodeControl(b)
		if err != nil || !ok || m.Type != "attach" {
			s.close()
			return
		}
		s.routes = m.Routes
		if err := s.control(controlMessage{Type: "attached", Session: "stalled-reader", Routes: m.Routes, HeartbeatMS: 15000, IdleTimeoutMS: 45000}); err != nil {
			s.close()
			return
		}
		f.sessions <- s
		for {
			kind, b, err := ws.Read(ctx)
			if err != nil {
				return
			}
			if kind == websocket.MessageBinary {
				id, payload, ok := decodeFrame(b)
				if !ok {
					continue
				}
				s.mu.Lock()
				channel := s.channels[id]
				s.mu.Unlock()
				if channel != nil {
					select {
					case channel.input <- relayChunk{data: append([]byte(nil), payload...)}:
					case <-ctx.Done():
						return
					}
				}
				continue
			}
			if kind != websocket.MessageText {
				continue
			}
			var control struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(b, &control) == nil && control.Type == "pause_reader" {
				close(paused)
				<-ctx.Done()
				return
			}
		}
	}
	c := tunnelClient(t, f, TransportOptions{WriteTimeout: 5 * time.Second})
	x := connectTest(t, c, Routes{"api": echoTarget(t)})
	s := f.next(t)
	public := s.public(t, 1, "api.demo.test")
	if _, err := public.Write([]byte("prime the upstream echo")); err != nil {
		t.Fatal(err)
	}

	var active *session
	x.mu.Lock()
	active = x.session
	x.mu.Unlock()
	if active == nil {
		t.Fatal("attached session disappeared")
	}
	if err := active.control(controlMessage{Type: "pause_reader"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-paused:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not acknowledge reader pause")
	}
	producerDone := make(chan error, 40)
	payload := bytes.Repeat([]byte("backpressure"), 64*1024)
	for range 40 {
		go func() { producerDone <- active.send(websocket.MessageBinary, payload) }()
	}
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for len(active.queue) != cap(active.queue) {
		select {
		case <-deadline.C:
			t.Fatal("outbound queue did not fill while relay stopped reading")
		case <-time.After(time.Millisecond):
		}
	}
	if err := x.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-x.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("connection workers did not join after cancellation")
	}
	joined := time.NewTimer(2 * time.Second)
	defer joined.Stop()
	for range 40 {
		select {
		case <-producerDone: //nolint:errcheck // Cancellation must join every producer regardless of write result.
		case <-joined.C:
			t.Fatal("blocked outbound producers did not stop after cancellation")
		}
	}
}
