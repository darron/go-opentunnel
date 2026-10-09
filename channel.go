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
	ctx         context.Context
	cancel      context.CancelFunc
	id          uint32
	route       string
	target      string
	session     *session
	cert        *tls.Certificate
	raw         *bridgeConn
	remoteReset atomic.Bool
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
		final = fmt.Errorf("TLS handshake failed: %w", err)
		ch.reset("client_io_error")
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
	var stream net.Conn = secure
	if idle := s.owner.client.options.IdleTimeout; idle > 0 {
		active := &activityConn{Conn: secure}
		active.last.Store(time.Now().UnixNano())
		stream = active
		done := make(chan struct{})
		go func() { defer close(done); ch.watchIdle(active, idle) }()
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
func (ch *channel) abort(e error) { ch.raw.abort(e); ch.cancel() }
func (ch *channel) reset(code string) {
	if !ch.remoteReset.Load() && ch.session.ctx.Err() == nil {
		_ = ch.session.control(controlMessage{Type: "reset", Conn: ch.id, Code: code})
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
func (ch *channel) watchIdle(c *activityConn, idle time.Duration) {
	timer := time.NewTimer(idle)
	defer timer.Stop()
	for {
		select {
		case <-ch.ctx.Done():
			return
		case <-timer.C:
			remaining := idle - time.Since(time.Unix(0, c.last.Load()))
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
	session       *session
	id            uint32
	peer          string
	limit         int
	mu            sync.Mutex
	chunks        [][]byte
	offset        int
	bytes         int
	notify        chan struct{}
	readEnd       bool
	writeEnd      bool
	closed        bool
	err           error
	readDeadline  time.Time
	writeDeadline time.Time
}

func newBridgeConn(s *session, id uint32, peer string, limit int) *bridgeConn {
	return &bridgeConn{session: s, id: id, peer: peer, limit: limit, notify: make(chan struct{})}
}
func (b *bridgeConn) signal() { close(b.notify); b.notify = make(chan struct{}) }
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
		b.chunks = append(b.chunks, append([]byte(nil), data...))
		b.bytes += len(data)
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
	b.err = err
	b.chunks = nil
	b.bytes = 0
	b.signal()
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
			b.offset += n
			b.bytes -= n
			if b.offset == len(b.chunks[0]) {
				b.chunks[0] = nil
				b.chunks = b.chunks[1:]
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
	deadline := b.writeDeadline
	b.mu.Unlock()
	ctx := b.session.ctx
	var cancel context.CancelFunc
	if !deadline.IsZero() {
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	n := 0
	for len(p) > 0 {
		size := len(p)
		if size > 32768 {
			size = 32768
		}
		if e := b.session.sendContext(ctx, websocket.MessageBinary, encodeFrame(b.id, p[:size])); e != nil {
			return n, e
		}
		n += size
		p = p[size:]
	}
	return n, nil
}
func (b *bridgeConn) Close() error { b.abort(net.ErrClosed); return nil }
func (b *bridgeConn) CloseWrite() error {
	b.mu.Lock()
	if b.writeEnd || b.closed {
		b.mu.Unlock()
		return nil
	}
	b.writeEnd = true
	b.mu.Unlock()
	return b.session.control(controlMessage{Type: "end", Conn: b.id})
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
	return nil
}

var _ net.Conn = (*bridgeConn)(nil)
