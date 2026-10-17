package opentunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type relayFixture struct {
	api        *testAPI
	sessions   chan *relaySession
	mu         sync.Mutex
	closed     bool
	all        []*relaySession
	attachCode string
	sessionID  string
	peer       string
	routes     []string
	heartbeat  int
	idle       int
	noPong     bool
}
type relayChunk struct {
	data []byte
	end  bool
}
type relayChannel struct {
	mu         sync.Mutex
	outputGate <-chan struct{}
	socket     *net.TCPConn
	input      chan relayChunk
}
type relaySession struct {
	fixture    *relayFixture
	ws         *websocket.Conn
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	closed     bool
	channels   map[uint32]*relayChannel
	controls   chan controlMessage
	routes     []string
	bytesMu    sync.Mutex
	ciphertext []byte
	wg         sync.WaitGroup
}

func newRelay(t *testing.T) *relayFixture {
	f := &relayFixture{api: newTestAPI(t), sessions: make(chan *relaySession, 32), sessionID: "test-session", peer: "127.0.0.1", heartbeat: 15000, idle: 45000}
	f.api.mu.Lock()
	f.api.bridge = f.accept
	f.api.mu.Unlock()
	t.Cleanup(func() {
		f.mu.Lock()
		f.closed = true
		all := append([]*relaySession(nil), f.all...)
		f.mu.Unlock()
		for _, s := range all {
			s.close()
		}
	})
	return f
}
func (f *relayFixture) accept(w http.ResponseWriter, r *http.Request) {
	ws, e := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"opentunnel"}})
	if e != nil {
		return
	}
	ws.SetReadLimit(1024 * 1024)
	ctx, cancel := context.WithCancel(context.Background())
	s := &relaySession{fixture: f, ws: ws, ctx: ctx, cancel: cancel, channels: make(map[uint32]*relayChannel), controls: make(chan controlMessage, 8192)}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		s.close()
		return
	}
	f.all = append(f.all, s)
	code, sessionID, hb, idle := f.attachCode, f.sessionID, f.heartbeat, f.idle
	routes := append([]string(nil), f.routes...)
	f.mu.Unlock()
	_, b, e := ws.Read(ctx)
	if e != nil {
		s.close()
		return
	}
	m, ok := decodeControl(b)
	if !ok || m.Type != "attach" || m.Token != f.api.token {
		s.close()
		return
	}
	s.routes = m.Routes
	if code != "" {
		_ = s.control(controlMessage{Type: "attach_error", Code: code})
		s.close()
		return
	}
	if routes == nil {
		routes = m.Routes
	}
	_ = s.control(controlMessage{Type: "attached", Session: sessionID, Routes: routes, HeartbeatMS: hb, IdleTimeoutMS: idle})
	// Serialize every worker registration with close, including the first Add.
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.wg.Add(1)
	s.mu.Unlock()
	go func() { defer s.wg.Done(); s.read() }()
	select {
	case f.sessions <- s:
	case <-s.ctx.Done():
	}
}
func (s *relaySession) read() {
	for {
		kind, b, e := s.ws.Read(s.ctx)
		if e != nil {
			return
		}
		if kind == websocket.MessageBinary {
			id, payload, ok := decodeFrame(b)
			if !ok {
				continue
			}
			s.bytesMu.Lock()
			s.ciphertext = append(s.ciphertext, payload...)
			s.bytesMu.Unlock()
			s.mu.Lock()
			ch := s.channels[id]
			s.mu.Unlock()
			if ch != nil {
				select {
				case ch.input <- relayChunk{data: append([]byte(nil), payload...)}:
				case <-s.ctx.Done():
					return
				}
			}
			continue
		}
		m, ok := decodeControl(b)
		if !ok {
			continue
		}
		if m.Type == "ping" && !s.fixture.noPong {
			_ = s.control(controlMessage{Type: "pong", TimeSent: m.TimeSent})
			continue
		}
		if m.Type == "end" || m.Type == "reset" {
			s.mu.Lock()
			ch := s.channels[m.Conn]
			s.mu.Unlock()
			if ch != nil {
				if m.Type == "reset" {
					_ = ch.socket.Close()
				} else {
					select {
					case ch.input <- relayChunk{end: true}:
					case <-s.ctx.Done():
						return
					}
				}
			}
		}
		select {
		case s.controls <- m:
		case <-s.ctx.Done():
			return
		}
	}
}
func (s *relaySession) control(m controlMessage) error {
	b, e := json.Marshal(m)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(s.ctx, 3*time.Second)
	defer cancel()
	return s.ws.Write(ctx, websocket.MessageText, b)
}
func (s *relaySession) close() {
	s.mu.Lock()
	s.closed = true
	for _, ch := range s.channels {
		_ = ch.socket.Close()
	}
	s.mu.Unlock()
	s.cancel()
	_ = s.ws.CloseNow()
	s.wg.Wait()
}
func (f *relayFixture) next(t *testing.T) *relaySession {
	t.Helper()
	select {
	case s := <-f.sessions:
		return s
	case <-time.After(8 * time.Second):
		t.Fatal("no attached session")
		return nil
	}
}
func (s *relaySession) nextControl(t *testing.T, kind string) controlMessage {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case m := <-s.controls:
			if m.Type == kind {
				return m
			}
		case <-deadline.C:
			t.Fatalf("no %s control", kind)
			return controlMessage{}
		}
	}
}

func (s *relaySession) publicRaw(t *testing.T, id uint32, sni string) net.Conn {
	t.Helper()
	listener, e := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	public, e := (&net.Dialer{}).DialContext(t.Context(), "tcp", listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	raw, e := listener.Accept()
	_ = listener.Close()
	if e != nil {
		t.Fatal(e)
	}
	tcp, ok := raw.(*net.TCPConn)
	if !ok {
		_ = raw.Close()
		t.Fatal("relay listener did not return TCP connection")
	}
	ch := &relayChannel{socket: tcp, input: make(chan relayChunk, 128)}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = tcp.Close()
		_ = public.Close()
		t.Fatal("relay session is closed")
	}
	s.channels[id] = ch
	s.wg.Add(2)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		for {
			select {
			case p := <-ch.input:
				ch.mu.Lock()
				gate := ch.outputGate
				ch.mu.Unlock()
				if gate != nil {
					select {
					case <-gate:
					case <-s.ctx.Done():
						return
					}
				}
				if p.end {
					_ = ch.socket.CloseWrite()
				} else {
					if _, e := ch.socket.Write(p.data); e != nil {
						return
					}
				}
			case <-s.ctx.Done():
				return
			}
		}
	}()
	s.fixture.mu.Lock()
	peer := s.fixture.peer
	s.fixture.mu.Unlock()
	if e := s.control(controlMessage{Type: "open", Conn: id, Peer: peer, SNI: sni, ALPN: "h2,http/1.1"}); e != nil {
		// The second worker has not started; balance its reservation on failure.
		s.wg.Done()
		_ = tcp.Close()
		_ = public.Close()
		t.Fatal(e)
	}
	go func() {
		defer s.wg.Done()
		buf := make([]byte, 32768)
		for {
			n, e := ch.socket.Read(buf)
			if n > 0 {
				if e := s.ws.Write(s.ctx, websocket.MessageBinary, encodeFrame(id, buf[:n])); e != nil {
					return
				}
			}
			if e != nil {
				_ = s.control(controlMessage{Type: "end", Conn: id})
				return
			}
		}
	}()
	t.Cleanup(func() { _ = public.Close() })
	return public
}

func (s *relaySession) public(t *testing.T, id uint32, sni string) *tls.Conn {
	t.Helper()
	secure := tls.Client(s.publicRaw(t, id, sni), &tls.Config{RootCAs: s.fixture.api.authority.roots, ServerName: sni, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}})
	_ = secure.SetDeadline(time.Now().Add(5 * time.Second))
	if e := secure.HandshakeContext(t.Context()); e != nil {
		_ = secure.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = secure.Close() })
	return secure
}
func tunnelClient(t *testing.T, f *relayFixture, o TransportOptions) *Client {
	t.Helper()
	o.CertificatePollInterval = 5 * time.Millisecond
	if o.BackoffMin == 0 {
		o.BackoffMin = 5 * time.Millisecond
		o.BackoffMax = 20 * time.Millisecond
	}
	c, e := NewClient(ClientOptions{API: f.api.server.URL, Storage: NewMemoryStorage(), Transport: o})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
func connectTest(t *testing.T, c *Client, r Routes) *Connection {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	x, e := c.Connect(ctx, ConnectOptions{Routes: r})
	if e != nil {
		t.Fatal(e)
	}
	return x
}
func echoTarget(t *testing.T) string {
	t.Helper()
	l, e := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	var sockets []net.Conn
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			sockets = append(sockets, c)
			wg.Add(1)
			mu.Unlock()
			go func() { defer wg.Done(); defer func() { _ = c.Close() }(); _, _ = io.Copy(c, c) }()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		for _, c := range sockets {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return l.Addr().String()
}
func waitStatus(t *testing.T, x *Connection, predicate func(Status) bool) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if predicate(x.Status()) {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline:
			t.Fatalf("status: %+v", x.Status())
		}
	}
}

func TestTunnelTLSForwardingLargeConcurrentAndCiphertext(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	target := echoTarget(t)
	x := connectTest(t, c, Routes{"@": target, "api": target})
	s := f.next(t)
	for i, host := range []string{"demo.test", "api.demo.test"} {
		socket := s.public(t, uint32(i+1), host)
		if socket.ConnectionState().NegotiatedProtocol != "http/1.1" {
			t.Fatal("HTTP/2 advertised to HTTP/1.1 target")
		}
		payload := bytes.Repeat([]byte("private-application-secret-"), 10000)
		write := make(chan error, 1)
		go func() { _, e := socket.Write(payload); write <- e }()
		reply := make([]byte, len(payload))
		if _, e := io.ReadFull(socket, reply); e != nil {
			t.Fatal(e)
		}
		if e := <-write; e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(payload, reply) {
			t.Fatal("corrupt forwarding")
		}
	}
	s.bytesMu.Lock()
	hasPlaintext := bytes.Contains(s.ciphertext, []byte("private-application-secret-"))
	s.bytesMu.Unlock()
	if hasPlaintext {
		t.Fatal("plaintext in relay")
	}
	waitStatus(t, x, func(s Status) bool { return s.Connections == 2 })
	if e := x.Close(); e != nil {
		t.Fatal(e)
	}
	select {
	case <-x.Done():
	default:
		t.Fatal("close returned before completion")
	}
}
func TestTunnelRoutesReconnectAndSnapshots(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	target := echoTarget(t)
	x := connectTest(t, c, Routes{"api": target})
	_ = f.next(t)
	routes := Routes{"api": "127.0.0.1:9"}
	if e := x.SetRoutes(routes); e != nil {
		t.Fatal(e)
	}
	routes["api"] = "invalid"
	if x.Status().Routes["api"] != "127.0.0.1:9" {
		t.Fatal("caller map aliases routes")
	}
	if e := x.SetRoutes(Routes{"api": target, "@": target}); e != nil {
		t.Fatal(e)
	}
	next := f.next(t)
	if len(next.routes) != 2 {
		t.Fatal("names did not reattach")
	}
	if e := x.SetRoutes(Routes{}); e != nil {
		t.Fatal(e)
	}
	waitStatus(t, x, func(s Status) bool { return s.State == "waiting-routes" })
	if e := x.SetRoutes(Routes{"api": target}); e != nil {
		t.Fatal(e)
	}
	s := f.next(t)
	s.close()
	f.next(t)
	copy := x.Status()
	copy.Routes["api"] = "bad"
	if x.Status().Routes["api"] != target {
		t.Fatal("snapshot aliases routes")
	}
}
func TestTunnelFatalAttachAndCancellation(t *testing.T) {
	for _, code := range []string{"bad_token", "cert_not_ready"} {
		t.Run(code, func(t *testing.T) {
			f := newRelay(t)
			f.attachCode = code
			c := tunnelClient(t, f, TransportOptions{})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, e := c.Connect(ctx, ConnectOptions{Routes: Routes{"api": echoTarget(t)}})
			var attach *AttachError
			if !errors.As(e, &attach) || attach.Code != code {
				t.Fatalf("fatal: %v", e)
			}
		})
	}
	t.Run("retry cancellation", func(t *testing.T) {
		f := newRelay(t)
		f.attachCode = "route_conflict"
		c := tunnelClient(t, f, TransportOptions{})
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, e := c.Connect(ctx, ConnectOptions{Routes: Routes{"api": echoTarget(t)}})
		if !errors.Is(e, context.DeadlineExceeded) {
			t.Fatalf("retry: %v", e)
		}
	})
}
func TestTunnelResetLimitsAndUnknownControls(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{MaxConnections: 1, HandshakeTimeout: 300 * time.Millisecond})
	x := connectTest(t, c, Routes{"api": echoTarget(t)})
	s := f.next(t)
	if e := s.control(controlMessage{Type: "open", Conn: 9, SNI: "other.demo.test", Peer: "local", ALPN: ""}); e != nil {
		t.Fatal(e)
	}
	if m := s.nextControl(t, "reset"); m.Code != "unknown_route" {
		t.Fatal(m)
	}
	_ = s.control(controlMessage{Type: "open", Conn: 1, SNI: "api.demo.test", Peer: "local", ALPN: ""})
	waitStatus(t, x, func(s Status) bool { return s.Connections == 1 })
	_ = s.control(controlMessage{Type: "open", Conn: 2, SNI: "api.demo.test", Peer: "local", ALPN: ""})
	if m := s.nextControl(t, "reset"); m.Code != "too_many_connections" {
		t.Fatal(m)
	}
	_ = s.ws.Write(s.ctx, websocket.MessageText, []byte(`{"type":"future","value":true}`))
	_ = s.ws.Write(s.ctx, websocket.MessageText, []byte(`{"type":"open","conn":-1}`))
	_ = s.control(controlMessage{Type: "reset", Conn: 1, Code: "client_io_error"})
	waitStatus(t, x, func(s Status) bool { return s.Connections == 0 })
	if x.Status().State != "connected" {
		t.Fatal("bad control stopped session")
	}
}
func TestTunnelHeartbeatAndDrain(t *testing.T) {
	f := newRelay(t)
	f.heartbeat = 100
	f.idle = 500
	f.noPong = true
	c := tunnelClient(t, f, TransportOptions{})
	x := connectTest(t, c, Routes{"api": echoTarget(t)})
	_ = f.next(t)
	current := f.next(t)
	_ = current.control(controlMessage{Type: "drain", Reason: "deploy"})
	f.next(t)
	if x.Status().State == "stopped" {
		t.Fatal("heartbeat or drain became fatal")
	}
}
func TestTunnelRenewalAndDeletion(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{CertificateRefreshInterval: 20 * time.Millisecond})
	x := connectTest(t, c, Routes{"api": echoTarget(t)})
	s := f.next(t)
	old := x.Identity()
	f.api.mu.Lock()
	cert, e := f.api.authority.issue(f.api.csr, 3)
	if e != nil {
		t.Fatal(e)
	}
	f.api.cert = cert
	f.api.mu.Unlock()
	deadline := time.After(3 * time.Second)
	for x.Identity().Certificate == old.Certificate {
		select {
		case <-deadline:
			t.Fatal("renewal missing")
		case <-time.After(time.Millisecond):
		}
	}
	pub := s.public(t, 1, "api.demo.test")
	if pub.ConnectionState().PeerCertificates[0].SerialNumber.Int64() != 3 {
		t.Fatal("new TLS channel used old certificate")
	}
	if e := c.Remove(context.Background(), ""); e != nil {
		t.Fatal(e)
	}
	select {
	case <-x.Done():
	case <-time.After(time.Second):
		t.Fatal("remove did not stop session")
	}
	if id, e := c.Get(context.Background(), ""); e != nil || id != nil {
		t.Fatal("renewal resurrected removed identity")
	}
}
func TestTunnelHTTPStreamingAndWebSocketUpgrade(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
	defer backend.Close()
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	_ = connectTest(t, c, Routes{"api": strings.TrimPrefix(backend.URL, "http://")})
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
}

func TestBridgeConnBoundsDeadlinesAndHalfClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &session{ctx: ctx}
	b := newBridgeConn(s, 1, "peer", 4)
	if !b.push([]byte("1234")) || b.push([]byte("5")) {
		t.Fatal("buffer cap")
	}
	b.endInbound()
	p := make([]byte, 4)
	if n, e := b.Read(p); n != 4 || e != nil {
		t.Fatal(n, e)
	}
	if _, e := b.Read(p); !errors.Is(e, io.EOF) {
		t.Fatal(e)
	}
	other := newBridgeConn(s, 2, "peer", 4)
	_ = other.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, e := other.Read(p); !errors.Is(e, errors.ErrUnsupported) && !errors.Is(e, context.DeadlineExceeded) {
		var n net.Error
		if !errors.As(e, &n) || !n.Timeout() {
			t.Fatalf("deadline: %v", e)
		}
	}
}

func TestTunnelHalfClosePreservesResponse(t *testing.T) {
	listener, e := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = listener.Close() }()
	backendDone := make(chan error, 1)
	go func() {
		socket, e := listener.Accept()
		if e != nil {
			backendDone <- e
			return
		}
		defer func() { _ = socket.Close() }()
		_ = socket.SetDeadline(time.Now().Add(5 * time.Second))
		body, e := io.ReadAll(socket)
		if e == nil {
			_, e = socket.Write(append([]byte("response-after-eof:"), body...))
		}
		backendDone <- e
	}()
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	x := connectTest(t, c, Routes{"api": listener.Addr().String()})
	s := f.next(t)
	public := s.public(t, 1, "api.demo.test")
	if _, e := public.Write([]byte("request")); e != nil {
		t.Fatal(e)
	}
	if e := public.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	response, e := io.ReadAll(public)
	if e != nil || string(response) != "response-after-eof:request" {
		t.Fatalf("half-close lost response: %q %v", response, e)
	}
	if e := <-backendDone; e != nil {
		t.Fatal(e)
	}
	waitStatus(t, x, func(s Status) bool { return s.Connections == 0 })
}

func TestTunnelStalledChannelDoesNotBlockHealthyChannel(t *testing.T) {
	listener, e := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		socket, e := listener.Accept()
		if e == nil {
			tcp, ok := socket.(*net.TCPConn)
			if !ok {
				return
			}
			_ = tcp.SetReadBuffer(1024)
			accepted <- tcp
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case socket := <-accepted:
			_ = socket.Close()
		default:
		}
	})
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{MaxInboundBytes: 65536})
	x := connectTest(t, c, Routes{"slow": listener.Addr().String(), "api": echoTarget(t)})
	s := f.next(t)
	slow := s.public(t, 1, "slow.demo.test")
	writeDone := make(chan error, 1)
	go func() { _, e := slow.Write(bytes.Repeat([]byte("stalled"), 1024*1024)); writeDone <- e }()
	reset := s.nextControl(t, "reset")
	if reset.Conn != 1 {
		t.Fatal(reset)
	}
	healthy := s.public(t, 2, "api.demo.test")
	if _, e := healthy.Write([]byte("healthy")); e != nil {
		t.Fatal(e)
	}
	reply := make([]byte, 7)
	if _, e := io.ReadFull(healthy, reply); e != nil || string(reply) != "healthy" {
		t.Fatalf("other channel stalled: %v", e)
	}
	_ = slow.Close()
	select {
	case <-writeDone: //nolint:errcheck // Closing the stalled connection must join the writer.
	case <-time.After(time.Second):
		t.Fatal("stalled write leaked")
	}
	if x.Status().State != "connected" {
		t.Fatal("overflow killed bridge")
	}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		select {
		case event := <-x.Events():
			if event.Type == "connection-closed" && event.Conn == 1 {
				if event.Error != ErrInboundLimit.Error() {
					t.Fatalf("overflow diagnostic: %+v", event)
				}
				return
			}
		case <-timer.C:
			t.Fatal("overflow closure event missing")
		}
	}
}

func TestTunnelCancellationBeforeAttachJoinsWorkers(t *testing.T) {
	f := newRelay(t)
	accepted := make(chan struct{})
	f.api.bridge = func(w http.ResponseWriter, r *http.Request) {
		ws, e := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"opentunnel"}})
		if e != nil {
			return
		}
		defer func() { _ = ws.CloseNow() }()
		close(accepted)
		for {
			if _, _, e := ws.Read(r.Context()); e != nil {
				return
			}
		}
	}
	c := tunnelClient(t, f, TransportOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, e := c.Connect(ctx, ConnectOptions{Routes: Routes{"api": echoTarget(t)}}); result <- e }()
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("handshake not started")
	}
	cancel()
	select {
	case e := <-result:
		if !errors.Is(e, context.Canceled) {
			t.Fatalf("cancel: %v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("startup workers leaked")
	}
	if e := c.Close(); e != nil {
		t.Fatal(e)
	}
}

func TestTunnelConcurrentSnapshotsUpdatesAndClose(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{EventBuffer: 1})
	target := echoTarget(t)
	x := connectTest(t, c, Routes{"api": target})
	s := f.next(t)
	for i := uint32(10); i < 30; i++ {
		_ = s.control(controlMessage{Type: "open", Conn: i, SNI: "other.demo.test", Peer: "local", ALPN: ""})
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			for range 50 {
				_ = x.Status()
				_ = x.Identity()
				routes := Routes{"api": target}
				if index%2 == 0 {
					routes["@"] = target
				}
				_ = x.SetRoutes(routes)
			}
		}(i)
	}
	wg.Add(1)
	go func() { defer wg.Done(); _ = x.Close() }()
	wg.Wait()
	if x.Status().DroppedEvents == 0 {
		t.Fatal("bounded event queue did not account for drops")
	}
	if e := x.SetRoutes(Routes{"api": target}); !errors.Is(e, ErrClosed) {
		t.Fatalf("closed mutation: %v", e)
	}
}

func TestTunnelDuplicateAndBadTLSResetWithoutBridgeFailure(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	x := connectTest(t, c, Routes{"api": echoTarget(t)})
	s := f.next(t)
	open := controlMessage{Type: "open", Conn: 1, SNI: "api.demo.test", Peer: "local", ALPN: ""}
	_ = s.control(open)
	waitStatus(t, x, func(s Status) bool { return s.Connections == 1 })
	_ = s.control(open)
	if reset := s.nextControl(t, "reset"); reset.Conn != 1 {
		t.Fatal(reset)
	}
	waitStatus(t, x, func(s Status) bool { return s.Connections == 0 })
	_ = s.control(controlMessage{Type: "open", Conn: 2, SNI: "api.demo.test", Peer: "local", ALPN: ""})
	_ = s.ws.Write(s.ctx, websocket.MessageBinary, encodeFrame(2, []byte("this is not a TLS record")))
	if reset := s.nextControl(t, "reset"); reset.Conn != 2 {
		t.Fatal(reset)
	}
	if x.Status().State != "connected" {
		t.Fatal("bad TLS killed bridge")
	}
}
