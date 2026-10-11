package opentunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

// Connection reconnects until context cancellation, Close, or a fatal attach error.
// Events are bounded and lossy; Status gives the current state. Done closes after
// all workers exit.
// Methods support concurrent calls. Obtain a Connection through Client.Connect;
// its zero value is not usable. Close does not delete the remote tunnel.
type Connection struct {
	listener        *Listener
	client          *Client
	profile         string
	ctx             context.Context
	cancel          context.CancelFunc
	stopParent      func() bool
	mu              sync.Mutex
	identity        Identity
	cert            *tls.Certificate
	routes          Routes
	routeOptions    map[string]RouteOptions
	status          Status
	session         *session
	events          chan Event
	ready           chan struct{}
	readyOnce       sync.Once
	done            chan struct{}
	wake            chan struct{}
	err             error
	closeRequested  atomic.Bool
	recoveryPending atomic.Bool
}

// Connect provisions and attaches a tunnel. ctx bounds startup only; cancel it
// after return without stopping the tunnel. Set Lifetime for context-owned shutdown.
// Expired identities attach to trigger server renewal, but readiness waits for a
// valid certificate. Overlapping routes within one client return ErrRouteInUse.
// Routes are copied on entry; callers must not mutate the input map while this
// call is running. At least one valid initial route is required. Cancellation
// during startup may preserve a pending identity for Client.Resume or Client.Remove.
func (c *Client) Connect(ctx context.Context, o ConnectOptions) (*Connection, error) {
	if len(o.Routes) == 0 {
		return nil, fmt.Errorf("%w: at least one initial route is required", ErrInvalid)
	}
	if e := ValidateRoutes(o.Routes); e != nil {
		return nil, e
	}
	if e := validateRouteOptions(o.Routes, o.RouteOptions); e != nil {
		return nil, e
	}
	return c.connect(ctx, o, nil)
}

func (c *Client) connect(ctx context.Context, o ConnectOptions, listener *Listener) (*Connection, error) {
	p, e := profileName(o.Profile)
	if e != nil {
		return nil, e
	}
	opctx, end, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer end()
	if o.Lifetime != nil {
		if err := o.Lifetime.Err(); err != nil {
			return nil, err
		}
		startup, cancelStartup := context.WithCancel(opctx)
		stopLifetime := context.AfterFunc(o.Lifetime, cancelStartup)
		defer func() { stopLifetime(); cancelStartup() }()
		opctx = startup
	}
	guard, e := c.guardProfile(opctx, p)
	if e != nil {
		return nil, e
	}
	defer guard.release()
	c.mu.Lock()
	e = c.checkRouteClaims(p, o.Routes, nil)
	c.mu.Unlock()
	if e != nil {
		guard.release()
		return nil, e
	}
	id, e := c.ensure(opctx, p, true, guard)
	if e != nil {
		guard.release()
		return nil, e
	}
	cert, e := parseCertificateMaterial(*id)
	if e != nil {
		guard.release()
		return nil, e
	}
	parent := o.Lifetime
	if parent == nil {
		parent = c.ctx
	}
	life, cancel := context.WithCancel(parent)
	x := &Connection{listener: listener, client: c, profile: p, ctx: life, cancel: cancel, identity: *id, cert: cert, routes: copyRoutes(o.Routes), routeOptions: copyRouteOptions(o.RouteOptions), events: make(chan Event, c.options.EventBuffer), ready: make(chan struct{}), done: make(chan struct{}), wake: make(chan struct{}, 1)}
	x.status = Status{State: "connecting", Hostname: id.Hostname, Routes: copyRoutes(o.Routes)}
	x.stopParent = context.AfterFunc(c.ctx, cancel)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		guard.release()
		cancel()
		x.stopParent()
		return nil, ErrClosed
	}
	if e := c.checkRouteClaims(p, o.Routes, nil); e != nil {
		c.mu.Unlock()
		guard.release()
		cancel()
		x.stopParent()
		return nil, e
	}
	c.connections[x] = p
	c.wg.Add(1)
	c.mu.Unlock()
	guard.release()
	go x.run()
	select {
	case <-x.ready:
		if e := opctx.Err(); e != nil {
			_ = x.Close()
			return nil, e
		}
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

// Identity returns a copy of the current identity, including credentials.
func (x *Connection) Identity() Identity { x.mu.Lock(); defer x.mu.Unlock(); return x.identity }

// Events returns the bounded, lossy event stream. Repeated calls return the same
// channel, so multiple readers divide events rather than each receiving a copy.
// It closes when Done closes. Status.DroppedEvents counts omitted events.
func (x *Connection) Events() <-chan Event { return x.events }

// Done closes after bridge, channel, and certificate-refresh workers exit.
func (x *Connection) Done() <-chan struct{} { return x.done }

// Err reports the terminal error after Done closes. Requested Close returns nil;
// explicit Lifetime cancellation returns its context error.
func (x *Connection) Err() error { x.mu.Lock(); defer x.mu.Unlock(); return x.err }

// Status returns a snapshot with copied route and option maps. LastError is diagnostic text.
func (x *Connection) Status() Status {
	x.mu.Lock()
	defer x.mu.Unlock()
	s := x.status
	s.Routes = copyRoutes(x.routes)
	s.RouteOptions = copyRouteOptions(x.routeOptions)
	return s
}

// Close stops the connection and joins its workers. It is safe to call repeatedly
// or concurrently. A normal requested close leaves Err nil; an already recorded
// terminal error remains available. Stored credentials and the remote tunnel remain.
func (x *Connection) Close() error { x.closeRequested.Store(true); x.cancel(); <-x.done; return nil }

// SetRoutes clears forwarding options and updates targets for new channels.
// Name changes reattach asynchronously and close existing channels when the
// session changes.
// An empty map pauses attachment. Invalid routes return ErrInvalid; overlapping
// names on this client's same-profile connections return ErrRouteInUse. The input
// map is copied; do not mutate it concurrently with this call.
func (x *Connection) SetRoutes(routes Routes) error {
	return x.SetRoutesWithOptions(routes, nil)
}

// SetRoutesWithOptions atomically replaces targets and forwarding options for new
// channels. Existing channels retain their options. Name changes reattach as in
// SetRoutes. Invalid options return ErrInvalid without changing configuration.
// Both maps are copied; do not mutate them concurrently with this call.
func (x *Connection) SetRoutesWithOptions(routes Routes, options map[string]RouteOptions) error {
	if e := ValidateRoutes(routes); e != nil {
		return e
	}
	if e := validateRouteOptions(routes, options); e != nil {
		return e
	}
	return x.setRoutesWithOptions(routes, options)
}

func (x *Connection) setRoutes(routes Routes) error {
	return x.setRoutesWithOptions(routes, nil)
}

func (x *Connection) setRoutesWithOptions(routes Routes, options map[string]RouteOptions) error {
	x.client.mu.Lock()
	defer x.client.mu.Unlock()
	if e := x.client.checkRouteClaims(x.profile, routes, x); e != nil {
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
	x.routeOptions = copyRouteOptions(options)
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
		// Recheck names to preserve updates that raced session publication.
		if !sameRouteNames(routes, x.routes) {
			s.routesChanged.Store(true)
			s.cancel()
		}
		x.mu.Unlock()
		err := s.run()
		if x.listener != nil {
			x.listener.discardPending()
		}
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
		if s.attached.Load() && time.Since(s.attachedAt) >= x.client.options.BackoffMax {
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
	if terminal == nil {
		terminal = x.ctx.Err()
		if errors.Is(terminal, context.Canceled) && (x.closeRequested.Load() || x.client.ctx.Err() != nil) {
			terminal = nil
		}
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
	if x.listener != nil {
		x.listener.discardPending()
	}
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

// checkRouteClaims requires c.mu. SetRoutes takes c.mu before any connection lock.
func (c *Client) checkRouteClaims(profile string, routes Routes, except *Connection) error {
	for other, p := range c.connections {
		if p != profile || other == except || other.ctx.Err() != nil {
			continue
		}
		other.mu.Lock()
		var conflict string
		for name := range routes {
			if _, ok := other.routes[name]; ok {
				conflict = name
				break
			}
		}
		other.mu.Unlock()
		if conflict != "" {
			return fmt.Errorf("%w: %q", ErrRouteInUse, conflict)
		}
	}
	return nil
}

func (x *Connection) markReady() {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.session == nil || !x.session.attached.Load() || x.session.ctx.Err() != nil {
		return
	}
	if !time.Now().Before(x.cert.Leaf.NotAfter) {
		x.status.State = "waiting-certificate"
		x.status.LastError = ErrCertificateExpired.Error()
		return
	}
	x.status.State = "connected"
	x.status.LastError = ""
	x.readyOnce.Do(func() { close(x.ready) })
}

func (x *Connection) refresh() {
	var warned, expired string
	for x.ctx.Err() == nil {
		id := x.Identity()
		untilExpiry := time.Until(id.CertificateExpiry)
		if untilExpiry <= 30*24*time.Hour && warned != id.Certificate {
			warned = id.Certificate
			x.emit(Event{Type: "certificate-expiring", Expiry: id.CertificateExpiry})
		}
		if untilExpiry <= 0 && expired != id.Certificate {
			expired = id.Certificate
			x.markReady()
			x.emit(Event{Type: "certificate-expired", Expiry: id.CertificateExpiry, Error: ErrCertificateExpired.Error()})
		}
		if err := x.refreshOnce(); err != nil && x.ctx.Err() == nil {
			x.emit(Event{Type: "certificate-refresh-failed", Error: err.Error()})
		}
		id = x.Identity()
		untilExpiry = time.Until(id.CertificateExpiry)
		interval := x.client.options.CertificateRefreshInterval
		if untilExpiry <= 0 {
			interval = x.client.options.CertificatePollInterval
		} else {
			if untilExpiry <= 30*24*time.Hour {
				interval = x.client.options.CertificateDueInterval
			}
			if interval > untilExpiry {
				interval = untilExpiry
			}
		}
		if x.recoveryPending.Load() && interval > x.client.options.CertificatePollInterval {
			interval = x.client.options.CertificatePollInterval
		}
		if retry := time.Until(x.client.recoveryDeadline(x.profile)); retry > 0 && interval > retry {
			interval = retry
		}
		if sleepContext(x.ctx, interval) != nil {
			return
		}
	}
}

func (x *Connection) refreshOnce() error {
	unlock, err := x.client.lockProfile(x.ctx, x.profile)
	if err != nil {
		return err
	}
	defer unlock()
	if err := x.ctx.Err(); err != nil {
		return err
	}
	id := x.Identity()
	remote, err := x.client.api.Certificate(x.ctx, id.ID, id.Token)
	if err != nil {
		return err
	}
	if remote.State.Type == "failed" {
		x.recoveryPending.Store(false)
		err := x.startCertificateRecovery(id)
		if errors.Is(err, ErrCertificateIssuance) {
			return certificateIssuanceError(remote.State.Reason)
		}
		return err
	}
	if remote.State.Type == "challenge" || remote.State.Type == "issuing" {
		x.recoveryPending.Store(true)
		return nil
	}
	x.recoveryPending.Store(false)
	if remote.State.Certificate == id.Certificate && remote.State.Chain == id.Chain {
		return nil
	}
	id.Certificate = remote.State.Certificate
	id.Chain = remote.State.Chain
	id.CertificateExpiry = remote.State.Expiry
	cert, err := parseCertificate(id)
	if err != nil {
		return err
	}
	id.CertificateExpiry = cert.Leaf.NotAfter
	if err := x.client.store.Save(x.ctx, x.profile, id); err != nil {
		return err
	}
	x.mu.Lock()
	x.identity = id
	x.cert = cert
	x.mu.Unlock()
	x.client.recoveryAfter.Delete(x.profile)
	x.markReady()
	x.emit(Event{Type: "certificate-renewed", Expiry: id.CertificateExpiry})
	return nil
}

// startCertificateRecovery requires the profile lock. Submit once, then release
// it; refresh polls on later iterations so stuck issuance cannot block Remove.
func (x *Connection) startCertificateRecovery(id Identity) error {
	_, err := x.client.startCertificateRecovery(x.ctx, x.profile, id)
	if err != nil {
		return err
	}
	x.recoveryPending.Store(true)
	x.emit(Event{Type: "certificate-recovery-started"})
	return nil
}
