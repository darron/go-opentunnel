package opentunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// This real relay/TLS/backend regression must fail on a client that retains
// a stalled half-closed connection indefinitely.
func TestHalfCloseStalledVisitorReleasesCapacity(t *testing.T) {
	backend, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = backend.Close() }()
	accepted := make(chan net.Conn, 2)
	eof := make(chan error, 2)
	go func() {
		for {
			socket, e := backend.Accept()
			if e != nil {
				return
			}
			accepted <- socket
			go func() { _, e := io.Copy(io.Discard, socket); eof <- e }()
		}
	}()
	options := TransportOptions{MaxConnections: 1, HalfCloseTimeout: 120 * time.Millisecond}
	f := newRelay(t)
	c := tunnelClient(t, f, options)
	x := connectTest(t, c, Routes{"api": backend.Addr().String()})
	s := f.next(t)
	public := s.public(t, 1, "api.demo.test")
	socket := <-accepted
	defer func() { _ = socket.Close() }()
	if err := public.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-eof:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("backend did not observe visitor EOF")
	}
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for x.Status().Connections != 0 {
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("stalled half-close retained admission: %+v", x.Stats())
		}
	}
	if stats := x.Stats(); stats.ActiveConnections != 0 || stats.InboundBufferedBytes != 0 || stats.ConnectionsClosed != 1 {
		t.Fatalf("teardown stats: %+v", stats)
	}
	again := s.public(t, 2, "api.demo.test")
	next := <-accepted
	defer func() { _ = next.Close(); _ = again.Close() }()
	if x.Stats().ConnectionsOpened != 2 {
		t.Fatalf("capacity not reused: %+v", x.Stats())
	}
}

func halfCloseBackend(t *testing.T) (net.Listener, <-chan *net.TCPConn) {
	t.Helper()
	backend, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *net.TCPConn, 4)
	go func() {
		for {
			conn, err := backend.Accept()
			if err != nil {
				return
			}
			tcp, ok := conn.(*net.TCPConn)
			if !ok {
				_ = conn.Close()
				return
			}
			accepted <- tcp
		}
	}()
	t.Cleanup(func() { _ = backend.Close() })
	return backend, accepted
}

func TestHalfCloseStalledBackendReleasesCapacity(t *testing.T) {
	backend, accepted := halfCloseBackend(t)
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{MaxConnections: 1, HalfCloseTimeout: 150 * time.Millisecond})
	x := connectTest(t, c, Routes{"api": backend.Addr().String()})
	s := f.next(t)
	public := s.public(t, 1, "api.demo.test")
	socket := <-accepted
	defer func() { _ = socket.Close() }()
	if err := socket.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if body, err := io.ReadAll(public); err != nil || len(body) != 0 {
		t.Fatalf("backend EOF: %q %v", body, err)
	}
	waitStatus(t, x, func(status Status) bool { return status.Connections == 0 })
	if stats := x.Stats(); stats.ConnectionsClosed != 1 || stats.ActiveConnections != 0 || stats.InboundBufferedBytes != 0 {
		t.Fatalf("teardown: %+v", stats)
	}
	_ = s.public(t, 2, "api.demo.test")
	next := <-accepted
	defer func() { _ = next.Close() }()
	if x.Stats().ConnectionsOpened != 2 {
		t.Fatal("backend half-close did not release capacity")
	}
}

func TestHalfCloseTrafficExtendsInactivityBothDirections(t *testing.T) {
	for _, visitorFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "visitorEOF", false: "backendEOF"}[visitorFirst], func(t *testing.T) {
			backend, accepted := halfCloseBackend(t)
			f := newRelay(t)
			c := tunnelClient(t, f, TransportOptions{HalfCloseTimeout: 400 * time.Millisecond})
			x := connectTest(t, c, Routes{"api": backend.Addr().String()})
			s := f.next(t)
			public := s.public(t, 1, "api.demo.test")
			socket := <-accepted
			defer func() { _ = socket.Close() }()
			_ = socket.SetDeadline(time.Now().Add(6 * time.Second))
			// An already quiet fully open stream must not inherit an expired epoch.
			quiet := time.NewTimer(800 * time.Millisecond)
			<-quiet.C
			if x.Status().Connections != 1 {
				t.Fatal("fully open quiet stream timed out")
			}
			if visitorFirst {
				if err := public.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if body, err := io.ReadAll(socket); err != nil || len(body) != 0 {
					t.Fatalf("visitor EOF: %q %v", body, err)
				}
			} else {
				if err := socket.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if body, err := io.ReadAll(public); err != nil || len(body) != 0 {
					t.Fatalf("backend EOF: %q %v", body, err)
				}
			}
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			var writer io.Writer = socket
			var reader io.Reader = public
			if !visitorFirst {
				writer = public
				reader = socket
			}
			for i := 0; i < 13; i++ {
				<-ticker.C
				payload := []byte{byte(i)}
				if _, err := writer.Write(payload); err != nil {
					t.Fatalf("active half-close write %d: %v", i, err)
				}
				var got [1]byte
				if _, err := io.ReadFull(reader, got[:]); err != nil || got[0] != byte(i) {
					t.Fatalf("active half-close read %d: %v %v", i, got, err)
				}
				if x.Status().Connections != 1 {
					t.Fatal("active half-close expired")
				}
			}
			if visitorFirst {
				if err := socket.CloseWrite(); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := public.CloseWrite(); err != nil {
					t.Fatal(err)
				}
			}
			waitStatus(t, x, func(status Status) bool { return status.Connections == 0 })
			for _, stats := range []Stats{x.Stats(), c.Stats()} {
				if stats.ActiveConnections != 0 || stats.InboundBufferedBytes != 0 {
					t.Fatalf("workers not drained: %+v", stats)
				}
			}
		})
	}
}

func TestHalfCloseListenerExplicitObservation(t *testing.T) {
	for _, local := range []bool{false, true} {
		t.Run(map[bool]string{false: "relayEnd", true: "localRawCloseWrite"}[local], func(t *testing.T) {
			f := newRelay(t)
			c := tunnelClient(t, f, TransportOptions{MaxConnections: 1, HalfCloseTimeout: 150 * time.Millisecond})
			l, err := c.Listen(t.Context(), ListenOptions{Routes: []string{"@"}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = l.Close() }()
			s := f.next(t)
			_ = s.public(t, 1, "demo.test")
			conn, err := l.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			secure, ok := conn.(*tls.Conn)
			if !ok {
				t.Fatalf("accepted type = %T", conn)
			}
			if local {
				raw, ok := secure.NetConn().(*bridgeConn)
				if !ok {
					t.Fatalf("accepted raw type = %T", secure.NetConn())
				}
				if err := raw.CloseWrite(); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := s.control(controlMessage{Type: "end", Conn: 1}); err != nil {
					t.Fatal(err)
				}
			}
			waitStatus(t, l.connection, func(status Status) bool { return status.Connections == 0 })
			if l.connection.Stats().ActiveConnections != 0 || c.Stats().InboundBufferedBytes != 0 {
				t.Fatal("listener did not drain")
			}
			_ = s.public(t, 2, "demo.test")
			again, err := l.Accept()
			if err != nil {
				t.Fatal(err)
			}
			_ = again.Close()
			if l.connection.Stats().ConnectionsOpened != 2 {
				t.Fatal("listener capacity not reused")
			}
		})
	}
}

func TestHalfCloseListenerActiveTrafficAndTLSObservationBoundary(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{HalfCloseTimeout: 400 * time.Millisecond})
	l, err := c.Listen(t.Context(), ListenOptions{Routes: []string{"@"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	s := f.next(t)
	public := s.public(t, 1, "demo.test")
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := public.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	// CloseWrite only sends encrypted close_notify: an unconsumed TLS alert
	// cannot be observed by the raw transport watchdog.
	quiet := time.NewTimer(800 * time.Millisecond)
	<-quiet.C
	if l.Status().Connections != 1 {
		t.Fatal("unconsumed encrypted close_notify inferred as relay end")
	}
	if err := s.control(controlMessage{Type: "end", Conn: 1}); err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for i := 0; i < 13; i++ {
		<-ticker.C
		if _, err := conn.Write([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
		var got [1]byte
		if _, err := io.ReadFull(public, got[:]); err != nil || got[0] != byte(i) {
			t.Fatalf("listener stream lost bytes: %v %v", got, err)
		}
	}
	waitStatus(t, l.connection, func(status Status) bool { return status.Connections == 0 })
}

func TestHalfCloseTimeoutDefaultsValidationAndCancelJoins(t *testing.T) {
	opts, err := transportDefaults(TransportOptions{})
	if err != nil || opts.HalfCloseTimeout != time.Minute || opts.IdleTimeout != 0 {
		t.Fatalf("defaults: %+v %v", opts, err)
	}
	if _, err := transportDefaults(TransportOptions{HalfCloseTimeout: -1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("negative timeout: %v", err)
	}
	opts, err = transportDefaults(TransportOptions{HalfCloseTimeout: time.Hour})
	if err != nil || opts.HalfCloseTimeout != time.Hour {
		t.Fatalf("override: %+v %v", opts, err)
	}
	backend, accepted := halfCloseBackend(t)
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{HalfCloseTimeout: time.Hour})
	x := connectTest(t, c, Routes{"api": backend.Addr().String()})
	s := f.next(t)
	public := s.public(t, 1, "api.demo.test")
	socket := <-accepted
	defer func() { _ = socket.Close() }()
	if err := public.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, socket); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = x.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close failed to join half-close watcher/copy workers")
	}
	select {
	case <-x.Done():
	default:
		t.Fatal("Close returned before Done")
	}
	if stats := x.Stats(); stats.ActiveConnections != 0 || stats.InboundBufferedBytes != 0 {
		t.Fatalf("cancel did not drain: %+v", stats)
	}
}

// Successful intermediate bridge chunks must renew half-close inactivity while
// the enclosing application Write is still blocked. Explicit completions model
// the package writer's successful network writes, not application completion.
func TestHalfClosePartialTransportWriteExtendsInactivity(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c := &Client{options: TransportOptions{WriteTimeout: 3 * time.Second, HalfCloseTimeout: 400 * time.Millisecond}}
	x := &Connection{client: c, ctx: ctx}
	s := newSession(x, nil)
	raw := newBridgeConn(s, 1, "peer", 1024)
	ch := &channel{ctx: ctx, cancel: cancel, session: s, raw: raw}
	active := &activityConn{Conn: raw, activity: newStreamActivity()}
	active.activity.halfClose()
	done := make(chan struct{})
	go func() { defer close(done); ch.watchActivity(active.activity) }()
	defer func() { cancel(); raw.abort(net.ErrClosed); <-done; raw.writeWorkers.Wait() }()
	result := make(chan error, 1)
	data := make([]byte, 13*32768)
	go func() {
		n, err := active.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		result <- err
	}()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for i := 0; i < 13; i++ {
		var message outbound
		select {
		case message = <-s.queue:
		case err := <-result:
			t.Fatalf("application write aborted before transport chunk %d: %v", i, err)
		case <-time.After(3 * time.Second):
			t.Fatal("missing transport write")
		}
		<-ticker.C
		message.result <- nil
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("application write failed to complete")
	}
}

func TestHalfCloseTransportProgressPreservesApplicationIdleTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c := &Client{options: TransportOptions{WriteTimeout: 3 * time.Second, IdleTimeout: 250 * time.Millisecond, HalfCloseTimeout: time.Second}}
	x := &Connection{client: c, ctx: ctx}
	s := newSession(x, nil)
	raw := newBridgeConn(s, 1, "peer", 1024)
	ch := &channel{ctx: ctx, cancel: cancel, session: s, raw: raw}
	active := &activityConn{Conn: raw, activity: newStreamActivity()}
	active.activity.halfClose()
	done := make(chan struct{})
	go func() { defer close(done); ch.watchActivity(active.activity) }()
	defer func() { cancel(); raw.abort(net.ErrClosed); <-done; raw.writeWorkers.Wait() }()
	result := make(chan error, 1)
	go func() { _, err := active.Write(make([]byte, 20*32768)); result <- err }()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	progress := 0
	for {
		select {
		case message := <-s.queue:
			select {
			case <-ticker.C:
				message.result <- nil
				progress++
			case <-deadline.C:
				t.Fatal("application idle timeout failed")
			}
		case err := <-result:
			if err == nil || progress == 0 {
				t.Fatalf("application write result=%v progress=%d", err, progress)
			}
			raw.mu.Lock()
			cause := raw.err
			raw.mu.Unlock()
			if !errors.Is(cause, ErrIdleTimeout) {
				t.Fatalf("wrong timeout cause: %v", cause)
			}
			return
		case <-deadline.C:
			t.Fatal("transport progress incorrectly refreshed application idle clock")
		}
	}
}
