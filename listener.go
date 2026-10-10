package opentunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"
)

// ListenOptions selects a profile, SNI route names, and listener lifetime.
type ListenOptions struct {
	// Profile selects stored credentials; empty selects "default".
	Profile string
	// Routes contains "@" for the root hostname or lowercase DNS labels.
	// At least one initial route is required; duplicate names are invalid.
	Routes []string
	// Lifetime controls the running listener. Nil uses the client's lifetime.
	Lifetime context.Context
}

// Listener accepts locally terminated visitor TLS without a loopback backend.
// Accept returns a handshaken *tls.Conn, so http.Server.Serve preserves Request.TLS.
// RemoteAddr is relay-provided metadata, not an independently verified visitor IP.
// Closing the listener also aborts accepted connections and joins package workers.
// It does not join application handlers or remove stored credentials.
type Listener struct {
	connection *Connection
	pending    chan *tls.Conn
}

// Listen provisions or resumes an identity and attaches its routes. ctx bounds
// startup only; Lifetime or Close controls the running listener. It shares route
// ownership with Connect: overlapping names on one client/profile are rejected.
func (c *Client) Listen(ctx context.Context, o ListenOptions) (*Listener, error) {
	routes, err := listenerRoutes(o.Routes)
	if err != nil {
		return nil, err
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("%w: at least one initial route is required", ErrInvalid)
	}
	l := &Listener{pending: make(chan *tls.Conn, c.options.MaxConnections)}
	x, err := c.connect(ctx, ConnectOptions{Profile: o.Profile, Routes: routes, Lifetime: o.Lifetime}, l)
	if err != nil {
		return nil, err
	}
	l.connection = x
	return l, nil
}

// Accept waits through transient reconnects. Invalid visitor handshakes are
// rejected internally. After shutdown it waits for owned workers and returns
// net.ErrClosed for requested Close/client shutdown, the Lifetime context error,
// or the fatal *AttachError. Queued connections from dead sessions are discarded.
func (l *Listener) Accept() (net.Conn, error) {
	x := l.connection
	for {
		if x.ctx.Err() != nil {
			return nil, l.acceptError()
		}
		select {
		case <-x.ctx.Done():
			return nil, l.acceptError()
		case secure := <-l.pending:
			raw, ok := secure.NetConn().(*bridgeConn)
			if !ok || raw.ctx.Err() != nil {
				continue
			}
			if x.ctx.Err() != nil {
				return nil, l.acceptError()
			}
			return secure, nil
		}
	}
}
func (l *Listener) acceptError() error {
	<-l.connection.Done()
	if err := l.connection.Err(); err != nil {
		return err
	}
	return net.ErrClosed
}

// Close aborts Accept and active I/O, joins package workers, and retains identity.
func (l *Listener) Close() error { return l.connection.Close() }

// Addr identifies the tunnel root hostname; it is not a local TCP socket address.
func (l *Listener) Addr() net.Addr { return bridgeAddr(l.Identity().Hostname) }

// Identity returns current credentials. Its exported fields contain secrets.
func (l *Listener) Identity() Identity { return l.connection.Identity() }

// Status returns a snapshot. Routes maps claimed names to empty strings because
// listener routes have no backend targets.
func (l *Listener) Status() Status { return l.connection.Status() }

// Events returns bounded, lossy lifecycle events. It closes with Done.
func (l *Listener) Events() <-chan Event { return l.connection.Events() }

// Done closes after all package-owned workers exit.
func (l *Listener) Done() <-chan struct{} { return l.connection.Done() }

// Err returns the terminal error after Done. Requested Close returns nil.
func (l *Listener) Err() error { return l.connection.Err() }

// SetRoutes changes accepted SNI names. Name changes reattach asynchronously and
// abort existing channels. An empty list pauses attachment until routes are added.
func (l *Listener) SetRoutes(names []string) error {
	routes, err := listenerRoutes(names)
	if err != nil {
		return err
	}
	return l.connection.setRoutes(routes)
}
func listenerRoutes(names []string) (Routes, error) {
	routes := make(Routes, len(names))
	for _, name := range names {
		if _, ok := routes[name]; ok {
			return nil, fmt.Errorf("%w: duplicate route %q", ErrInvalid, name)
		}
		if !validRoute(name) {
			return nil, ErrInvalid
		}
		routes[name] = ""
	}
	return routes, nil
}
func (l *Listener) discardPending() {
	for {
		select {
		case <-l.pending:
		default:
			return
		}
	}
}

func (ch *channel) serveListener(secure *tls.Conn) error {
	// Keep the exact *tls.Conn visible to net/http. Track record activity on the
	// underlying transport so an optional idle watchdog needs no TLS wrapper.
	ch.raw.lastActivity.Store(time.Now().UnixNano())
	if idle := ch.session.owner.client.options.IdleTimeout; idle > 0 {
		done := make(chan struct{})
		go func() { defer close(done); ch.watchIdle(&ch.raw.lastActivity, idle) }()
		defer func() { ch.cancel(); <-done }()
	}
	select {
	case <-ch.ctx.Done():
		return ch.ctx.Err()
	case ch.session.owner.listener.pending <- secure:
	default:
		ch.reset("too_many_connections")
		return fmt.Errorf("%w: listener accept queue full", ErrInboundLimit)
	}
	select {
	case <-ch.ctx.Done():
	case <-ch.raw.ctx.Done():
	}
	ch.raw.mu.Lock()
	cause := ch.raw.err
	ch.raw.mu.Unlock()
	if ch.raw.callerClosed.Load() && errors.Is(cause, net.ErrClosed) && !ch.remoteReset.Load() && ch.ctx.Err() == nil {
		// An immediate reset can discard TLS/HTTP/WebSocket bytes already queued
		// at the relay. End drains preceding writes before the relay half-closes.
		ch.session.enqueueControl(controlMessage{Type: "end", Conn: ch.id})
	} else {
		ch.reset("client_io_error")
	}
	return nil
}

var _ net.Listener = (*Listener)(nil)
