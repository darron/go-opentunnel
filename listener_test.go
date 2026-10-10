package opentunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/coder/websocket"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func listenTest(t *testing.T, c *Client, o ListenOptions) *Listener {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	l, err := c.Listen(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func acceptTest(t *testing.T, l *Listener) *tls.Conn {
	t.Helper()
	result := make(chan net.Conn, 1)
	errs := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			errs <- err
			return
		}
		result <- conn
	}()
	select {
	case conn := <-result:
		secure, ok := conn.(*tls.Conn)
		if !ok {
			_ = conn.Close()
			t.Fatalf("Accept returned %T", conn)
		}
		t.Cleanup(func() { _ = secure.Close() })
		return secure
	case err := <-errs:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("Accept blocked")
	}
	return nil
}

func TestListenerHTTPPreservesTLSAndPeer(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	l := listenTest(t, c, ListenOptions{Routes: []string{"@", "api"}})
	s := f.next(t)
	server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || !r.TLS.HandshakeComplete || r.TLS.ServerName != "api.demo.test" {
			t.Error("verified TLS state missing")
			http.Error(w, "HTTPS required", http.StatusBadRequest)
			return
		}
		if r.RemoteAddr != "127.0.0.1" {
			t.Errorf("peer = %q", r.RemoteAddr)
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "test", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode("https://" + r.TLS.ServerName + r.URL.Path)
	})}
	served := make(chan error, 1)
	go func() { served <- server.Serve(l) }()
	t.Cleanup(func() { _ = server.Close(); <-served })
	public := s.public(t, 1, "api.demo.test")
	_, err := io.WriteString(public, "GET /origin HTTP/1.1\r\nHost: api.demo.test\r\nConnection: close\r\nX-Forwarded-For: forged\r\nX-Forwarded-Proto: http\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(public), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var origin string
	if err == nil {
		err = json.Unmarshal(body, &origin)
	}
	if err != nil || origin != "https://api.demo.test/origin" {
		t.Fatalf("origin: %s %v", body, err)
	}
	if cookies := resp.Cookies(); len(cookies) != 1 || !cookies[0].Secure {
		t.Fatalf("cookies: %+v", cookies)
	}
}

func TestListenerAcceptTLSReconnectAndClose(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	l := listenTest(t, c, ListenOptions{Routes: []string{"@"}})
	s := f.next(t)
	_ = s.public(t, 1, "demo.test")
	secure := acceptTest(t, l)
	if !secure.ConnectionState().HandshakeComplete {
		t.Fatal("unverified TLS")
	}
	if l.Addr().String() != "demo.test" {
		t.Fatal(l.Addr())
	}
	s.close()
	next := f.next(t)
	_ = secure.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := secure.Read(make([]byte, 1)); err == nil {
		t.Fatal("old channel remained open")
	}
	_ = next.public(t, 2, "demo.test")
	active := acceptTest(t, l)
	blocked := make(chan error, 1)
	go func() { _, err := l.Accept(); blocked <- err }()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-blocked; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept close: %v", err)
	}
	if _, err := active.Read(make([]byte, 1)); err == nil {
		t.Fatal("active I/O survived Close")
	}
	select {
	case <-l.Done():
	default:
		t.Fatal("Close did not join workers")
	}
	if l.Err() != nil {
		t.Fatal(l.Err())
	}
	if id, err := c.Get(t.Context(), ""); err != nil || id == nil {
		t.Fatal("identity lost", err)
	}
}

func TestListenerLifetimeAndFatalAttach(t *testing.T) {
	for _, fatal := range []bool{false, true} {
		t.Run(fmt.Sprint(fatal), func(t *testing.T) {
			f := newRelay(t)
			c := tunnelClient(t, f, TransportOptions{})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			l := listenTest(t, c, ListenOptions{Routes: []string{"@"}, Lifetime: ctx})
			s := f.next(t)
			result := make(chan error, 1)
			go func() { _, err := l.Accept(); result <- err }()
			if fatal {
				f.mu.Lock()
				f.attachCode = "bad_token"
				f.mu.Unlock()
				s.close()
			} else {
				cancel()
			}
			select {
			case err := <-result:
				if fatal {
					var attach *AttachError
					if !errors.As(err, &attach) || attach.Code != "bad_token" {
						t.Fatal(err)
					}
				} else if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Accept did not stop")
			}
			select {
			case <-l.Done():
			default:
				t.Fatal("terminal Accept returned before join")
			}
		})
	}
}

func TestListenerValidationAndRouteOwnership(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	for _, routes := range [][]string{nil, {"Bad"}, {"@", "@"}, {"a.b"}} {
		if _, err := c.Listen(t.Context(), ListenOptions{Routes: routes}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("routes %v: %v", routes, err)
		}
	}
	l := listenTest(t, c, ListenOptions{Routes: []string{"@"}})
	_ = f.next(t)
	if _, err := c.Connect(t.Context(), ConnectOptions{Routes: Routes{"@": echoTarget(t)}}); !errors.Is(err, ErrRouteInUse) {
		t.Fatal(err)
	}
	x := connectTest(t, c, Routes{"api": echoTarget(t)})
	_ = f.next(t)
	if err := l.SetRoutes([]string{"api"}); !errors.Is(err, ErrRouteInUse) {
		t.Fatal(err)
	}
	if err := x.SetRoutes(Routes{"@": echoTarget(t)}); !errors.Is(err, ErrRouteInUse) {
		t.Fatal(err)
	}
	if err := l.SetRoutes([]string{"web"}); err != nil {
		t.Fatal(err)
	}
	s := f.next(t)
	if strings.Join(s.routes, ",") != "web" {
		t.Fatal(s.routes)
	}
	if err := l.SetRoutes(nil); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, l.connection, func(s Status) bool { return s.State == "waiting-routes" })
}

func TestListenerWrongSNIAndAdmission(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{MaxConnections: 1, HandshakeTimeout: 100 * time.Millisecond})
	l := listenTest(t, c, ListenOptions{Routes: []string{"@", "api"}})
	s := f.next(t)
	raw := s.publicRaw(t, 1, "demo.test")
	wrong := tls.Client(raw, &tls.Config{RootCAs: f.api.authority.roots, ServerName: "api.demo.test", MinVersion: tls.VersionTLS12})
	_ = wrong.SetDeadline(time.Now().Add(time.Second))
	if err := wrong.HandshakeContext(t.Context()); err == nil {
		t.Fatal("mismatched TLS SNI accepted")
	}
	_ = wrong.Close()
	if reset := s.nextControl(t, "reset"); reset.Conn != 1 {
		t.Fatal(reset)
	}
	waitStatus(t, l.connection, func(s Status) bool { return s.Connections == 0 })
	_ = s.public(t, 2, "demo.test") // queued, not yet accepted
	_ = s.control(controlMessage{Type: "open", Conn: 3, SNI: "demo.test", Peer: "other"})
	if reset := s.nextControl(t, "reset"); reset.Conn != 3 || reset.Code != "too_many_connections" {
		t.Fatal(reset)
	}
	conn := acceptTest(t, l)
	_ = conn.Close()
	waitStatus(t, l.connection, func(s Status) bool { return s.Connections == 0 })
	_ = s.public(t, 4, "api.demo.test")
	_ = acceptTest(t, l)
}

func TestListenerRenewalPendingResumeAndIdle(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{IdleTimeout: 60 * time.Millisecond, CertificateRefreshInterval: 5 * time.Millisecond})
	canceled, cancel := context.WithCancel(t.Context())
	_, err := c.Create(canceled, "", ProvisionOptions{OnProgress: func(stage ProvisionStage) {
		if stage == StageRequestingCertificate {
			cancel()
		}
	}})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if pending, err := c.Pending(t.Context(), ""); err != nil || pending == nil {
		t.Fatal("missing pending", err)
	}
	l := listenTest(t, c, ListenOptions{Routes: []string{"@"}})
	s := f.next(t)
	old := l.Identity()
	f.api.mu.Lock()
	replacement, err := f.api.authority.issue(f.api.csr, 8)
	if err != nil {
		f.api.mu.Unlock()
		t.Fatal(err)
	}
	f.api.cert = replacement
	f.api.mu.Unlock()
	deadline := time.Now().Add(3 * time.Second)
	for l.Identity().Certificate == old.Certificate {
		if time.Now().After(deadline) {
			t.Fatal("renewal missing")
		}
		time.Sleep(time.Millisecond)
	}
	public := s.public(t, 1, "demo.test")
	if public.ConnectionState().PeerCertificates[0].SerialNumber.Int64() != 8 {
		t.Fatal("listener used stale cert")
	}
	conn := acceptTest(t, l)
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle channel survived")
	}
	waitStatus(t, l.connection, func(s Status) bool { return s.Connections == 0 })
	if l.Status().State != "connected" {
		t.Fatal(l.Status())
	}
}

func TestListenerStalledHandshakeAndBufferOverflow(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{MaxInboundBytes: 32768, HandshakeTimeout: 80 * time.Millisecond})
	l := listenTest(t, c, ListenOptions{Routes: []string{"@"}})
	s := f.next(t)
	_ = s.control(controlMessage{Type: "open", Conn: 1, SNI: "demo.test", Peer: "slow"})
	public := s.public(t, 2, "demo.test")
	conn := acceptTest(t, l)
	if _, err := public.Write([]byte("healthy")); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 7)
	if _, err := io.ReadFull(conn, body); err != nil || string(body) != "healthy" {
		t.Fatal(err, string(body))
	}
	if reset := s.nextControl(t, "reset"); reset.Conn != 1 {
		t.Fatal(reset)
	}
	// Overflow may reset the socket before the sender finishes its write.
	_, _ = public.Write([]byte(strings.Repeat("x", 100000)))
	if reset := s.nextControl(t, "reset"); reset.Conn != 2 {
		t.Fatal(reset)
	}
	waitStatus(t, l.connection, func(s Status) bool { return s.Connections == 0 })
	if l.Status().State != "connected" {
		t.Fatal(l.Status())
	}
}

func TestListenerDiscardsQueuedConnectionsAcrossReconnect(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{MaxConnections: 1})
	l := listenTest(t, c, ListenOptions{Routes: []string{"@"}})
	s := f.next(t)
	_ = s.public(t, 1, "demo.test")
	waitStatus(t, l.connection, func(s Status) bool { return s.Connections == 1 })
	// Repeated reconnects without Accept must not fill the next session's queue.
	for i := uint32(2); i < 5; i++ {
		s.close()
		s = f.next(t)
		_ = s.public(t, i, "demo.test")
	}
	conn := acceptTest(t, l)
	raw, ok := conn.NetConn().(*bridgeConn)
	if !ok || raw.id != 4 {
		t.Fatal("stale accepted connection")
	}
}

func TestListenerHTTPStreamingAndWebSocketUpgrade(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" {
			ws, e := websocket.Accept(w, r, nil)
			if e != nil {
				return
			}
			defer func() { _ = ws.CloseNow() }()
			for {
				kind, b, e := ws.Read(r.Context())
				if e != nil {
					return
				}
				if ws.Write(r.Context(), kind, b) != nil {
					return
				}
			}
		}
		if e := http.NewResponseController(w).EnableFullDuplex(); e != nil {
			t.Errorf("full duplex: %v", e)
			return
		}
		if _, e := io.Copy(w, r.Body); e != nil {
			t.Errorf("streaming backend: %v", e)
		}
	})
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	l := listenTest(t, c, ListenOptions{Routes: []string{"api"}})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(l) }()
	t.Cleanup(func() { _ = l.Close(); _ = server.Close(); <-done })
	s := f.next(t)
	var count uint32
	var mu sync.Mutex
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.api.authority.roots, MinVersion: tls.VersionTLS12}, DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		count++
		id := count
		mu.Unlock()
		return s.public(t, id, "api.demo.test"), nil
	}}}
	defer httpClient.CloseIdleConnections()
	body := strings.Repeat("streamed-content-", 20000)
	request, e := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://api.demo.test/echo", strings.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	resp, e := httpClient.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	reply, e := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if e != nil || string(reply) != body {
		t.Fatalf("streaming: %v, size %d", e, len(reply))
	}
	ws, upgradeResponse, e := websocket.Dial(t.Context(), "wss://api.demo.test/ws", &websocket.DialOptions{HTTPClient: httpClient})
	if upgradeResponse != nil && upgradeResponse.Body != nil {
		defer func() { _ = upgradeResponse.Body.Close() }()
	}
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = ws.CloseNow() }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e := ws.Write(ctx, websocket.MessageText, []byte("application websocket")); e != nil {
		t.Fatal(e)
	}
	_, b, e := ws.Read(ctx)
	if e != nil || string(b) != "application websocket" {
		t.Fatalf("upgrade: %s %v", b, e)
	}
	if err := ws.Close(websocket.StatusNormalClosure, "done"); err != nil {
		t.Fatalf("normal WebSocket close: %v", err)
	}
}

func TestListenerClientShutdownAndRemoveJoinAccepts(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(fmt.Sprint(remove), func(t *testing.T) {
			f := newRelay(t)
			c := tunnelClient(t, f, TransportOptions{})
			l := listenTest(t, c, ListenOptions{Routes: []string{"@"}})
			s := f.next(t)
			_ = s.public(t, 1, "demo.test")
			active := acceptTest(t, l)
			results := make(chan error, 8)
			for range 8 {
				go func() { _, err := l.Accept(); results <- err }()
			}
			var err error
			if remove {
				err = c.Remove(t.Context(), "")
			} else {
				err = c.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			for range 8 {
				select {
				case err := <-results:
					if !errors.Is(err, net.ErrClosed) {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("Accept not joined")
				}
			}
			if _, err := active.Read(make([]byte, 1)); err == nil {
				t.Fatal("accepted socket survived shutdown")
			}
			if err := l.SetRoutes([]string{"web"}); !errors.Is(err, ErrClosed) {
				t.Fatal(err)
			}
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestListenerCloseJoinsWriteDeadlineWatchers(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	l := listenTest(t, c, ListenOptions{Routes: []string{"@"}})
	s := f.next(t)
	_ = s.public(t, 1, "demo.test")
	conn := acceptTest(t, l)
	raw, ok := conn.NetConn().(*bridgeConn)
	if !ok {
		t.Fatal("missing bridge transport")
	}
	for range 32 {
		_, stop := raw.writeContext()
		defer stop()
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	joined := make(chan struct{})
	go func() { raw.writeWorkers.Wait(); close(joined) }()
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("deadline watchers not joined")
	}
}

func TestListenerApplicationClosePreservesBufferedResponse(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	l := listenTest(t, c, ListenOptions{Routes: []string{"@"}})
	s := f.next(t)
	public := s.public(t, 1, "demo.test")
	// Small TCP buffers can drain slowly on CI; assert byte preservation, not speed.
	if err := public.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	conn := acceptTest(t, l)
	tcp, ok := public.NetConn().(*net.TCPConn)
	if !ok {
		t.Fatal("missing visitor TCP socket")
	}
	if err := tcp.SetReadBuffer(1024); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	relay := s.channels[1]
	s.mu.Unlock()
	if err := relay.socket.SetWriteBuffer(1024); err != nil {
		t.Fatal(err)
	}
	payload := strings.Repeat("complete-response-", 32768)
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(public)
	if err != nil || string(reply) != payload {
		t.Fatalf("Close truncated response: got %d/%d, %v", len(reply), len(payload), err)
	}
}
