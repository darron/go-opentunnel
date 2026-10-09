package opentunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"
)

// Connection reconnects until its lifetime context is cancelled, Close is
// called, or a fatal attach error occurs. Events are bounded and may be dropped;
// Status is an authoritative snapshot. Done closes after every worker exits.
type Connection struct {
	client     *Client
	profile    string
	ctx        context.Context
	cancel     context.CancelFunc
	stopParent func() bool
	mu         sync.Mutex
	identity   Identity
	cert       *tls.Certificate
	routes     Routes
	status     Status
	session    *session
	events     chan Event
	ready      chan struct{}
	readyOnce  sync.Once
	done       chan struct{}
	wake       chan struct{}
	err        error
}

func (c *Client) Connect(ctx context.Context, o ConnectOptions) (*Connection, error) {
	if len(o.Routes) == 0 {
		return nil, fmt.Errorf("%w: at least one initial route is required", ErrInvalid)
	}
	if e := ValidateRoutes(o.Routes); e != nil {
		return nil, e
	}
	p, e := profileName(o.Profile)
	if e != nil {
		return nil, e
	}
	opctx, end, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer end()
	unlock, e := c.lockProfile(opctx, p)
	if e != nil {
		return nil, e
	}
	id, e := c.ensure(opctx, p)
	if e != nil {
		unlock()
		return nil, e
	}
	cert, e := parseCertificate(*id)
	if e != nil {
		unlock()
		return nil, e
	}
	// The lifetime is the caller's context, not the temporary provisioning context.
	life, cancel := context.WithCancel(ctx)
	x := &Connection{client: c, profile: p, ctx: life, cancel: cancel, identity: *id, cert: cert, routes: copyRoutes(o.Routes), events: make(chan Event, c.options.EventBuffer), ready: make(chan struct{}), done: make(chan struct{}), wake: make(chan struct{}, 1)}
	x.status = Status{State: "connecting", Hostname: id.Hostname, Routes: copyRoutes(o.Routes)}
	x.stopParent = context.AfterFunc(c.ctx, cancel)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		unlock()
		cancel()
		x.stopParent()
		return nil, ErrClosed
	}
	c.connections[x] = p
	c.wg.Add(1)
	c.mu.Unlock()
	unlock()
	go x.run()
	select {
	case <-x.ready:
		if e := x.Err(); e != nil {
			_ = x.Close()
			return nil, e
		}
		return x, nil
	case <-x.done:
		if e := x.Err(); e != nil {
			return nil, e
		}
		return nil, context.Canceled
	case <-opctx.Done():
		_ = x.Close()
		return nil, opctx.Err()
	}
}

func copyRoutes(r Routes) Routes {
	out := make(Routes, len(r))
	for k, v := range r {
		out[k] = v
	}
	return out
}
func (x *Connection) Identity() Identity    { x.mu.Lock(); defer x.mu.Unlock(); return x.identity }
func (x *Connection) Events() <-chan Event  { return x.events }
func (x *Connection) Done() <-chan struct{} { return x.done }
func (x *Connection) Err() error            { x.mu.Lock(); defer x.mu.Unlock(); return x.err }
func (x *Connection) Status() Status {
	x.mu.Lock()
	defer x.mu.Unlock()
	s := x.status
	s.Routes = copyRoutes(x.routes)
	return s
}
func (x *Connection) Close() error { x.cancel(); <-x.done; return nil }

// SetRoutes applies targets immediately to new channels. Changing names causes
// asynchronous reattachment; existing channels close when the session changes.
func (x *Connection) SetRoutes(routes Routes) error {
	if e := ValidateRoutes(routes); e != nil {
		return e
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.ctx.Err() != nil || x.status.State == "stopped" {
		return ErrClosed
	}
	oldNames := routeNames(x.routes)
	newNames := routeNames(routes)
	changed := len(oldNames) != len(newNames)
	if !changed {
		for i := range oldNames {
			if oldNames[i] != newNames[i] {
				changed = true
				break
			}
		}
	}
	x.routes = copyRoutes(routes)
	if changed && x.session != nil {
		x.session.routesChanged.Store(true)
		x.session.cancel()
	}
	select {
	case x.wake <- struct{}{}:
	default:
	}
	return nil
}

func (x *Connection) emit(e Event) {
	x.mu.Lock()
	defer x.mu.Unlock()
	select {
	case x.events <- e:
	default:
		x.status.DroppedEvents++
	}
}
func (x *Connection) setState(state string, err error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.status.State = state
	if err != nil {
		x.status.LastError = err.Error()
	}
}
func (x *Connection) run() {
	defer x.client.wg.Done()
	refreshDone := make(chan struct{})
	go func() { defer close(refreshDone); x.refresh() }()
	var terminal error
	attempt := 0
	for x.ctx.Err() == nil {
		x.mu.Lock()
		routes := copyRoutes(x.routes)
		x.mu.Unlock()
		if len(routes) == 0 {
			x.setState("waiting-routes", nil)
			select {
			case <-x.wake:
			case <-x.ctx.Done():
			}
			continue
		}
		x.setState("connecting", nil)
		x.emit(Event{Type: "connecting", Attempt: attempt})
		s := newSession(x, routes)
		x.mu.Lock()
		x.session = s
		// A name change between the snapshot and publication must not be lost.
		if !sameRouteNames(routes, x.routes) {
			s.routesChanged.Store(true)
			s.cancel()
		}
		x.mu.Unlock()
		err := s.run()
		x.mu.Lock()
		x.session = nil
		x.status.Session = ""
		x.status.Connections = 0
		x.mu.Unlock()
		if x.ctx.Err() != nil {
			break
		}
		if s.routesChanged.Load() {
			x.emit(Event{Type: "disconnected", Reason: "routes changed"})
			attempt = 0
			continue
		}
		var attach *AttachError
		if errors.As(err, &attach) && (attach.Code == "bad_token" || attach.Code == "cert_not_ready") {
			terminal = err
			break
		}
		if s.attached.Load() {
			attempt = 0
		}
		if err == nil {
			err = errors.New("opentunnel: bridge disconnected")
		}
		x.emit(Event{Type: "disconnected", Reason: err.Error()})
		delay := x.backoff(attempt)
		attempt++
		x.setState("reconnecting", err)
		x.emit(Event{Type: "reconnecting", Attempt: attempt, Delay: delay})
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-x.wake:
		case <-x.ctx.Done():
		}
		timer.Stop()
	}
	if terminal == nil && x.ctx.Err() != nil {
		terminal = x.ctx.Err()
	}
	x.cancel()
	<-refreshDone
	x.stopParent()
	x.mu.Lock()
	x.err = terminal
	x.status.State = "stopped"
	if terminal != nil && !errors.Is(terminal, context.Canceled) {
		x.status.LastError = terminal.Error()
	}
	x.mu.Unlock()
	event := Event{Type: "stopped"}
	if terminal != nil && !errors.Is(terminal, context.Canceled) {
		event.Error = terminal.Error()
	}
	x.emit(event)
	x.client.mu.Lock()
	delete(x.client.connections, x)
	x.client.mu.Unlock()
	close(x.events)
	close(x.done)
}
func sameRouteNames(a, b Routes) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}
func (x *Connection) backoff(attempt int) time.Duration {
	d := x.client.options.BackoffMin
	maximum := x.client.options.BackoffMax
	for i := 0; i < attempt && d < maximum; i++ {
		if d > maximum/2 {
			d = maximum
			break
		}
		d *= 2
	}
	if d > maximum {
		d = maximum
	}
	// #nosec G404 -- Reconnection jitter is not a cryptographic secret.
	return d/2 + time.Duration(rand.Float64()*float64(d-d/2))
}

func (x *Connection) refresh() {
	for x.ctx.Err() == nil {
		if err := x.refreshOnce(); err != nil && x.ctx.Err() == nil {
			x.emit(Event{Type: "certificate-refresh-failed", Error: err.Error()})
		}
		id := x.Identity()
		interval := x.client.options.CertificateRefreshInterval
		if time.Until(id.CertificateExpiry) <= 30*24*time.Hour {
			interval = x.client.options.CertificateDueInterval
		}
		if sleepContext(x.ctx, interval) != nil {
			return
		}
	}
}
func (x *Connection) refreshOnce() error {
	un, t := x.client.lockProfile(x.ctx, x.profile)
	if t != nil {
		return t
	}
	defer un()
	if e := x.ctx.Err(); e != nil {
		return e
	}
	id := x.Identity()
	remote, e := x.client.api.Certificate(x.ctx, id.ID, id.Token)
	if e != nil {
		return e
	}
	if remote.State.Type != "ready" {
		return nil
	}
	if remote.State.Certificate == id.Certificate {
		return nil
	}
	id.Certificate = remote.State.Certificate
	id.Chain = remote.State.Chain
	id.CertificateExpiry = remote.State.Expiry
	cert, e := parseCertificate(id)
	if e != nil {
		return e
	}
	if e := x.client.store.Save(x.ctx, x.profile, id); e != nil {
		return e
	}
	x.mu.Lock()
	x.identity = id
	x.cert = cert
	x.mu.Unlock()
	x.emit(Event{Type: "certificate-renewed", Expiry: id.CertificateExpiry})
	return nil
}
