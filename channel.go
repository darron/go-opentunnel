package opentunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

type channel struct {
	ctx           context.Context
	cancel        context.CancelFunc
	id            uint32
	route         string
	target        string
	proxyProtocol ProxyProtocol
	sni           string
	session       *session
	cert          *tls.Certificate
	raw           *bridgeConn
	remoteReset   atomic.Bool
}

func (ch *channel) forward() {
	s := ch.session
	var final error
	defer func() {
		ch.raw.mu.Lock()
		cause := ch.raw.err
		ch.raw.mu.Unlock()
		if errors.Is(cause, ErrIdleTimeout) || errors.Is(cause, ErrInboundLimit) {
			final = cause
		}
		ch.cancel()
		ch.raw.abort(net.ErrClosed)
		ch.raw.writeWorkers.Wait()
		s.finished(ch, final)
	}()
	config := channelTLS(ch.cert)
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		route, ok := RouteForSNI(hello.ServerName, s.owner.Identity().Hostname)
		if !ok || route != ch.route {
			return nil, ErrRouteMismatch
		}
		if !time.Now().Before(ch.cert.Leaf.NotAfter) {
			return nil, ErrCertificateExpired
		}
		if time.Now().Before(ch.cert.Leaf.NotBefore) {
			return nil, ErrInvalid
		}
		return config, nil
	}
	secure := tls.Server(ch.raw, config)
	ctx, cancel := context.WithTimeout(ch.ctx, s.owner.client.options.HandshakeTimeout)
	err := secure.HandshakeContext(ctx)
	cancel()
	if err != nil {
		final = tlsHandshakeFailure(err)
		ch.reset("client_io_error")
		return
	}
	if s.owner.listener != nil {
		final = ch.serveListener(secure)
		return
	}
	ctx, cancel = context.WithTimeout(ch.ctx, s.owner.client.options.DialTimeout)
	upstream, err := (&net.Dialer{}).DialContext(ctx, "tcp", ch.target)
	cancel()
	if err != nil {
		final = errors.New("upstream connection failed")
		ch.reset("upstream_connect_failed")
		return
	}
	defer func() { _ = upstream.Close() }()
	stop := context.AfterFunc(ch.ctx, func() { _ = upstream.Close(); ch.raw.abort(net.ErrClosed) })
	defer stop()
	if header := proxyHeader(ch.proxyProtocol, ch.raw.RemoteAddr().String(), ch.sni); len(header) > 0 {
		if err := writeProxyHeader(upstream, header, s.owner.client.options.WriteTimeout); err != nil {
			final = errors.New("PROXY protocol header write failed")
			ch.reset("upstream_io_error")
			return
		}
	}
	var stream net.Conn = secure
	if idle := s.owner.client.options.IdleTimeout; idle > 0 {
		active := &activityConn{Conn: secure}
		active.last.Store(time.Now().UnixNano())
		stream = active
		done := make(chan struct{})
		go func() { defer close(done); ch.watchIdle(&active.last, idle) }()
		defer func() { ch.cancel(); <-done }()
	}
	results := make(chan error, 2)
	go func() {
		_, e := io.Copy(upstream, stream)
		if e == nil {
			if tcp, ok := upstream.(*net.TCPConn); ok {
				e = tcp.CloseWrite()
			}
		}
		if e != nil {
			ch.raw.abort(e)
			_ = upstream.Close()
		}
		results <- e
	}()
	go func() {
		_, e := io.Copy(stream, upstream)
		if e == nil {
			e = secure.CloseWrite()
			if e == nil {
				e = ch.raw.CloseWrite()
			}
		}
		if e != nil {
			ch.raw.abort(e)
			_ = upstream.Close()
		}
		results <- e
	}()
	for range 2 {
		if e := <-results; e != nil {
			final = errors.New("connection IO failed")
		}
	}
	if final != nil {
		ch.reset("upstream_io_error")
	}
}

// tlsHandshakeFailure retains package-defined causes while discarding raw TLS
// errors, which can contain attacker-controlled SNI or ALPN text.
func tlsHandshakeFailure(err error) error {
	switch {
	case errors.Is(err, ErrRouteMismatch):
		return fmt.Errorf("TLS handshake failed: %w", ErrRouteMismatch)
	case errors.Is(err, ErrCertificateExpired):
		return fmt.Errorf("TLS handshake failed: %w", ErrCertificateExpired)
	case errors.Is(err, ErrInvalid):
		return fmt.Errorf("TLS handshake failed: %w", ErrInvalid)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("TLS handshake timed out: %w", context.DeadlineExceeded)
	default:
		return errors.New("TLS handshake failed")
	}
}

func (ch *channel) abort(e error) { ch.raw.abort(e); ch.cancel() }
func (ch *channel) reset(code string) {
	if !ch.remoteReset.Load() && ch.session.ctx.Err() == nil {
		ch.session.enqueueControl(controlMessage{Type: "reset", Conn: ch.id, Code: code})
	}
}

// activityConn tracks successfully forwarded application bytes in both directions.
type activityConn struct {
	net.Conn
	last atomic.Int64
}

func (c *activityConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.last.Store(time.Now().UnixNano())
	}
	return n, err
}
func (c *activityConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.last.Store(time.Now().UnixNano())
	}
	return n, err
}
func (ch *channel) watchIdle(last *atomic.Int64, idle time.Duration) {
	timer := time.NewTimer(idle)
	defer timer.Stop()
	for {
		select {
		case <-ch.ctx.Done():
			return
		case <-timer.C:
			remaining := idle - time.Since(time.Unix(0, last.Load()))
			if remaining <= 0 {
				ch.abort(ErrIdleTimeout)
				return
			}
			timer.Reset(remaining)
		}
	}
}

// bridgeConn provides bounded buffering and TCP half-close semantics. push does
// not block the bridge reader when a TLS channel is slow.
type bridgeConn struct {
	ctx           context.Context
	cancel        context.CancelFunc
	session       *session
	id            uint32
	peer          string
	limit         int
	mu            sync.Mutex
	chunks        [][]byte
	offset        int
	bytes         int
	notify        chan struct{}
	writeNotify   chan struct{}
	readEnd       bool
	writeEnd      bool
	closed        bool
	err           error
	readDeadline  time.Time
	writeDeadline time.Time
	lastActivity  atomic.Int64
	writeWorkers  sync.WaitGroup
	callerClosed  atomic.Bool
}

func newBridgeConn(s *session, id uint32, peer string, limit int) *bridgeConn {
	ctx := context.Background()
	if s != nil {
		ctx = s.ctx
	}
	ctx, cancel := context.WithCancel(ctx)
	return &bridgeConn{ctx: ctx, cancel: cancel, session: s, id: id, peer: peer, limit: limit, notify: make(chan struct{}), writeNotify: make(chan struct{})}
}
func (b *bridgeConn) signal()      { close(b.notify); b.notify = make(chan struct{}) }
func (b *bridgeConn) signalWrite() { close(b.writeNotify); b.writeNotify = make(chan struct{}) }
func (b *bridgeConn) push(data []byte) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.readEnd {
		return true
	}
	if len(data) > b.limit-b.bytes {
		return false
	}
	if len(data) > 0 {
		if !b.session.reserveInbound(len(data)) {
			return false
		}
		b.bytes += len(data)
		// Coalescing bounds allocation and slice metadata even for one-byte frames.
		for len(data) > 0 {
			if len(b.chunks) == 0 || len(b.chunks[len(b.chunks)-1]) == cap(b.chunks[len(b.chunks)-1]) {
				b.chunks = append(b.chunks, make([]byte, 0, min(b.limit, 32768)))
			}
			last := len(b.chunks) - 1
			n := min(len(data), cap(b.chunks[last])-len(b.chunks[last]))
			b.chunks[last] = append(b.chunks[last], data[:n]...)
			data = data[n:]
		}
		b.signal()
	}
	return true
}
func (b *bridgeConn) endInbound() { b.mu.Lock(); defer b.mu.Unlock(); b.readEnd = true; b.signal() }
func (b *bridgeConn) abort(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	b.cancel()
	b.err = err
	b.chunks = nil
	b.session.releaseInbound(b.bytes)
	b.bytes = 0
	b.signal()
	b.signalWrite()
}
func (b *bridgeConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		b.mu.Lock()
		if b.closed {
			e := b.err
			if e == nil {
				e = net.ErrClosed
			}
			b.mu.Unlock()
			return 0, e
		}
		if !b.readDeadline.IsZero() && !time.Now().Before(b.readDeadline) {
			b.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		if len(b.chunks) > 0 {
			n := copy(p, b.chunks[0][b.offset:])
			b.lastActivity.Store(time.Now().UnixNano())
			b.offset += n
			b.bytes -= n
			b.session.releaseInbound(n)
			if b.offset == len(b.chunks[0]) {
				b.chunks[0] = nil
				b.chunks = b.chunks[1:]
				if len(b.chunks) == 0 {
					b.chunks = nil
				}
				b.offset = 0
			}
			b.mu.Unlock()
			return n, nil
		}
		if b.readEnd {
			b.mu.Unlock()
			return 0, io.EOF
		}
		notify, deadline := b.notify, b.readDeadline
		b.mu.Unlock()
		var timer *time.Timer
		var timerC <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timerC = timer.C
		}
		select {
		case <-notify:
		case <-b.session.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return 0, b.session.ctx.Err()
		case <-timerC:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}
func (b *bridgeConn) Write(p []byte) (int, error) {
	b.mu.Lock()
	if b.closed || b.writeEnd {
		b.mu.Unlock()
		return 0, net.ErrClosed
	}
	if !b.writeDeadline.IsZero() && !time.Now().Before(b.writeDeadline) {
		b.mu.Unlock()
		return 0, os.ErrDeadlineExceeded
	}
	b.mu.Unlock()
	ctx, stop := b.writeContext()
	defer stop()
	n := 0
	for len(p) > 0 {
		size := len(p)
		if size > 32768 {
			size = 32768
		}
		if e := b.session.sendContext(ctx, websocket.MessageBinary, encodeFrame(b.id, p[:size])); e != nil {
			if ctx.Err() != nil {
				e = context.Cause(ctx)
			}
			return n, e
		}
		n += size
		b.lastActivity.Store(time.Now().UnixNano())
		p = p[size:]
	}
	return n, nil
}

// Watch deadline changes during this write, as required by net.Conn. The watcher
// belongs to this call and is joined before return; it never cancels the socket.
func (b *bridgeConn) writeContext() (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(b.ctx)
	b.mu.Lock()
	if b.closed || b.writeEnd {
		b.mu.Unlock()
		cancel(net.ErrClosed)
		return ctx, func() {}
	}
	// Admission under mu prevents additions after abort, before channel teardown
	// waits for these package-owned deadline watchers.
	b.writeWorkers.Add(1)
	b.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer b.writeWorkers.Done()
		defer close(done)
		for {
			b.mu.Lock()
			deadline, notify := b.writeDeadline, b.writeNotify
			closed := b.closed || b.writeEnd
			b.mu.Unlock()
			if closed {
				cancel(net.ErrClosed)
				return
			}
			if !deadline.IsZero() && !time.Now().Before(deadline) {
				cancel(os.ErrDeadlineExceeded)
				return
			}
			var timer *time.Timer
			var timerC <-chan time.Time
			if !deadline.IsZero() {
				timer = time.NewTimer(time.Until(deadline))
				timerC = timer.C
			}
			select {
			case <-ctx.Done():
				if timer != nil {
					timer.Stop()
				}
				return
			case <-notify:
			case <-timerC:
			}
			if timer != nil {
				timer.Stop()
			}
		}
	}()
	return ctx, func() { cancel(context.Canceled); <-done }
}
func (b *bridgeConn) Close() error { b.callerClosed.Store(true); b.abort(net.ErrClosed); return nil }
func (b *bridgeConn) CloseWrite() error {
	b.mu.Lock()
	if b.writeEnd || b.closed {
		b.mu.Unlock()
		return nil
	}
	b.writeEnd = true
	b.signalWrite()
	b.mu.Unlock()
	return b.session.controlContext(b.ctx, controlMessage{Type: "end", Conn: b.id})
}

type bridgeAddr string

func (a bridgeAddr) Network() string       { return "opentunnel" }
func (a bridgeAddr) String() string        { return string(a) }
func (b *bridgeConn) LocalAddr() net.Addr  { return bridgeAddr("local") }
func (b *bridgeConn) RemoteAddr() net.Addr { return bridgeAddr(b.peer) }
func (b *bridgeConn) SetDeadline(t time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.readDeadline = t
	b.writeDeadline = t
	b.signal()
	b.signalWrite()
	return nil
}
func (b *bridgeConn) SetReadDeadline(t time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.readDeadline = t
	b.signal()
	return nil
}
func (b *bridgeConn) SetWriteDeadline(t time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.writeDeadline = t
	b.signal()
	b.signalWrite()
	return nil
}

var _ net.Conn = (*bridgeConn)(nil)

// Write the entire preamble before either payload copy starts. Cancellation closes
// upstream in forward; the deadline also bounds a backend that does not read.
func writeProxyHeader(upstream net.Conn, header []byte, timeout time.Duration) error {
	if err := upstream.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	for len(header) > 0 {
		n, err := upstream.Write(header)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		header = header[n:]
	}
	return upstream.SetWriteDeadline(time.Time{})
}
