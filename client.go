package opentunnel

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Client owns provisioning operations and connections; Close cancels and joins
// them. Applications must coordinate same-profile provisioning across clients
// or processes, even when sharing a store.
type Client struct {
	api           *API
	store         Storage
	options       TransportOptions
	ctx           context.Context
	cancel        context.CancelFunc
	mu            sync.Mutex
	closed        bool
	connections   map[*Connection]string
	profiles      sync.Map
	recoveryAfter sync.Map // profile -> time.Time; writes require the profile lock
	wg            sync.WaitGroup
}

// NewClient creates an owner for provisioning and running tunnels. Zero options
// select the hosted API, persistent XDG storage, and documented transport defaults.
// Call Close when the application no longer needs the client.
func NewClient(options ClientOptions) (*Client, error) {
	if options.API == "" {
		options.API = DefaultAPI
	}
	api, err := NewAPI(options.API, options.HTTPClient, options.RequestTimeout)
	if err != nil {
		return nil, err
	}
	if options.Storage == nil {
		options.Storage, err = NewXDGStorage()
		if err != nil {
			return nil, err
		}
	}
	opts, err := transportDefaults(options.Transport)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{api: api, store: options.Storage, options: opts, ctx: ctx, cancel: cancel, connections: make(map[*Connection]string)}, nil
}

// API returns the low-level HTTP client for remote inspection and custom workflows.
// Its calls use their own contexts; Client.Close does not cancel them.
func (c *Client) API() *API { return c.api }

func transportDefaults(o TransportOptions) (TransportOptions, error) {
	if o.IdleTimeout < 0 {
		return o, fmt.Errorf("%w: negative idle timeout", ErrInvalid)
	}
	ints := []*int{&o.MaxConnections, &o.EventBuffer, &o.MaxInboundBytes}
	defaults := []int{256, 256, 8 * 1024 * 1024}
	for i, p := range ints {
		if *p < 0 {
			return o, fmt.Errorf("%w: negative transport limit", ErrInvalid)
		}
		if *p == 0 {
			*p = defaults[i]
		}
	}
	ds := []*time.Duration{&o.AttachTimeout, &o.HandshakeTimeout, &o.DialTimeout, &o.WriteTimeout, &o.CertificatePollInterval, &o.CertificateRefreshInterval, &o.CertificateDueInterval, &o.CertificateRetryInterval, &o.BackoffMin, &o.BackoffMax}
	df := []time.Duration{10 * time.Second, 10 * time.Second, 10 * time.Second, 10 * time.Second, 2 * time.Second, 12 * time.Hour, time.Minute, time.Hour, 250 * time.Millisecond, 30 * time.Second}
	for i, p := range ds {
		if *p < 0 {
			return o, fmt.Errorf("%w: negative transport duration", ErrInvalid)
		}
		if *p == 0 {
			*p = df[i]
		}
	}
	if o.BackoffMax < o.BackoffMin {
		return o, fmt.Errorf("%w: backoff maximum below minimum", ErrInvalid)
	}
	return o, nil
}

func profileName(p string) (string, error) {
	if p == "" {
		p = "default"
	}
	if !validProfile(p) {
		return "", fmt.Errorf("%w: invalid profile", ErrInvalid)
	}
	return p, nil
}

func (c *Client) begin(ctx context.Context) (context.Context, func(), error) {
	if ctx == nil {
		return nil, nil, fmt.Errorf("%w: nil context", ErrInvalid)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, nil, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	c.wg.Add(1)
	merged, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctx, cancel)
	return merged, func() { stop(); cancel(); c.wg.Done() }, nil
}

func (c *Client) lockProfile(ctx context.Context, p string) (func(), error) {
	v, _ := c.profiles.LoadOrStore(p, make(chan struct{}, 1))
	sem, ok := v.(chan struct{})
	if !ok {
		return nil, fmt.Errorf("%w: invalid profile lock", ErrInvalid)
	}
	select {
	case sem <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-sem
			return nil, err
		}
		return func() { <-sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// profileGuard can release ownership while issuance sleeps. Each poll reacquires
// the lock and checks the persisted record before any write to storage.
type profileGuard struct{ unlock func() }

func (c *Client) guardProfile(ctx context.Context, p string) (*profileGuard, error) {
	unlock, err := c.lockProfile(ctx, p)
	if err != nil {
		return nil, err
	}
	return &profileGuard{unlock: unlock}, nil
}
func (g *profileGuard) release() {
	if g.unlock != nil {
		g.unlock()
		g.unlock = nil
	}
}
func (g *profileGuard) pause(ctx context.Context, c *Client, p string) error {
	g.release()
	if err := sleepContext(ctx, c.options.CertificatePollInterval); err != nil {
		return err
	}
	unlock, err := c.lockProfile(ctx, p)
	if err != nil {
		return err
	}
	g.unlock = unlock
	return nil
}

// Profiles lists local profile names using the configured store.
func (c *Client) Profiles(ctx context.Context) ([]string, error) {
	ctx, end, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer end()
	return c.store.Profiles(ctx)
}

// List lists local completed identities with their profile names. Returned
// identities contain credentials even though their JSON representation omits them.
func (c *Client) List(ctx context.Context) ([]StoredTunnel, error) {
	ctx, end, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer end()
	return c.store.List(ctx)
}

// Get loads a completed local identity. An absent profile returns (nil, nil).
// Empty profile selects "default"; the returned identity contains credentials.
func (c *Client) Get(ctx context.Context, profile string) (*Identity, error) {
	ctx, end, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer end()
	p, e := profileName(profile)
	if e != nil {
		return nil, e
	}
	return c.store.Load(ctx, p)
}

// Pending loads unfinished local provisioning. Absence returns (nil, nil).
// Empty profile selects "default"; the result contains credentials.
func (c *Client) Pending(ctx context.Context, profile string) (*PendingIdentity, error) {
	ctx, end, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer end()
	p, e := profileName(profile)
	if e != nil {
		return nil, e
	}
	return c.store.LoadPending(ctx, p)
}

// Create provisions a tunnel or resumes pending issuance. A completed local
// identity returns ErrExists. Empty profile selects "default". Cancellation
// leaves persisted pending credentials available to Resume or Remove. After a
// known remote creation, bounded persistence or cleanup completes even if ctx is
// canceled. If both fail, ProvisioningError exposes credentials for manual recovery.
func (c *Client) Create(ctx context.Context, profile string, options ProvisionOptions) (*Identity, error) {
	ctx, end, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer end()
	p, e := profileName(profile)
	if e != nil {
		return nil, e
	}
	guard, e := c.guardProfile(ctx, p)
	if e != nil {
		return nil, e
	}
	defer guard.release()
	return c.create(ctx, p, options, guard)
}
func progress(o ProvisionOptions, s ProvisionStage) {
	if o.OnProgress != nil {
		o.OnProgress(s)
	}
}
func (c *Client) create(ctx context.Context, p string, o ProvisionOptions, guard *profileGuard) (*Identity, error) {
	id, e := c.store.Load(ctx, p)
	if e != nil {
		return nil, e
	}
	if id != nil {
		return nil, ErrExists
	}
	pending, e := c.store.LoadPending(ctx, p)
	if e != nil {
		return nil, e
	}
	if pending != nil {
		progress(o, StageResumingCertificate)
		return c.complete(ctx, p, *pending, o, guard, false)
	}
	progress(o, StageCreatingTunnel)
	created, e := c.api.Create(ctx)
	if e != nil {
		if created.Tunnel.ID != "" && created.Token != "" {
			pending := PendingIdentity{ID: created.Tunnel.ID, Hostname: created.Tunnel.Hostname, Token: created.Token}
			return nil, c.compensateProvision(ctx, p, pending, e)
		}
		return nil, e
	}
	return c.provision(ctx, p, created.Tunnel.ID, created.Tunnel.Hostname, created.Token, o, guard)
}
func (c *Client) provision(ctx context.Context, p, id, host, token string, o ProvisionOptions, guard *profileGuard) (*Identity, error) {
	pending := PendingIdentity{ID: id, Hostname: host, Token: token}
	progress(o, StageGeneratingKey)
	progress(o, StageGeneratingCSR)
	key, csr, e := generateRequest(host)
	if e != nil {
		return nil, c.compensateProvision(ctx, p, pending, e)
	}
	pending.PrivateKey, pending.CSR = key, csr
	// The successful create response contains the only deletion credentials.
	// Preserve them even when the startup context was just canceled.
	persist, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.api.timeout)
	e = c.store.SavePending(persist, p, pending)
	cancel()
	if e != nil {
		return nil, c.compensateProvision(ctx, p, pending, fmt.Errorf("persist pending identity: %w", e))
	}
	return c.complete(ctx, p, pending, o, guard, false)
}

func (c *Client) compensateProvision(ctx context.Context, p string, pending PendingIdentity, cause error) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.api.timeout)
	defer cancel()
	if err := c.api.Remove(cleanup, pending.ID, pending.Token); err != nil {
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != 404 {
			return &ProvisioningError{Pending: pending, Err: errors.Join(cause, fmt.Errorf("remove unpersisted tunnel: %w", err))}
		}
	}
	if err := c.store.Remove(cleanup, p); err != nil {
		return errors.Join(cause, fmt.Errorf("clean up failed provisioning: %w", err))
	}
	return cause
}
func (c *Client) complete(ctx context.Context, p string, pending PendingIdentity, o ProvisionOptions, guard *profileGuard, submitted bool) (*Identity, error) {
	for {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		current, err := c.store.LoadPending(ctx, p)
		if err != nil {
			return nil, err
		}
		if current == nil {
			// Another same-client waiter or refresh worker may have completed it.
			id, err := c.store.Load(ctx, p)
			if err != nil {
				return nil, err
			}
			if id == nil || !matchesPending(*id, pending) {
				return nil, ErrProfileChanged
			}
			if _, err := parseCertificate(*id); err != nil {
				return nil, err
			}
			progress(o, StageReady)
			return id, nil
		}
		if *current != pending {
			return nil, ErrProfileChanged
		}
		progress(o, StageWaitingCertificate)
		cert, e := c.api.Certificate(ctx, pending.ID, pending.Token)
		if e != nil {
			var apiErr *APIError
			if submitted || !errors.As(e, &apiErr) || apiErr.Tag != "CertificateNotFoundError" {
				return nil, e
			}
			progress(o, StageRequestingCertificate)
			if err := c.submitCertificate(ctx, p, pending); err != nil {
				return nil, err
			}
			submitted = true
			continue
		}
		switch cert.State.Type {
		case "ready":
			id := Identity{ID: pending.ID, Hostname: pending.Hostname, Token: pending.Token, PrivateKey: pending.PrivateKey, Certificate: cert.State.Certificate, Chain: cert.State.Chain, CertificateExpiry: cert.State.Expiry}
			validated, e := parseCertificate(id)
			if e != nil {
				return nil, e
			}
			id.CertificateExpiry = validated.Leaf.NotAfter
			progress(o, StageSavingIdentity)
			if e := c.store.Save(ctx, p, id); e != nil {
				return nil, e
			}
			c.recoveryAfter.Delete(p)
			progress(o, StageReady)
			return &id, nil
		case "failed":
			if submitted {
				return nil, ErrCertificateIssuance
			}
			progress(o, StageRequestingCertificate)
			if err := c.submitCertificate(ctx, p, pending); err != nil {
				return nil, err
			}
			submitted = true
			continue
		case "challenge", "issuing":
		default:
			return nil, errors.New("opentunnel: unknown certificate state")
		}
		if e := guard.pause(ctx, c, p); e != nil {
			return nil, e
		}
	}
}

// Resume finishes pending issuance; no pending identity returns (nil, nil).
// Empty profile selects "default". ctx bounds the entire issuance wait.
func (c *Client) Resume(ctx context.Context, profile string, o ProvisionOptions) (*Identity, error) {
	ctx, end, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer end()
	p, e := profileName(profile)
	if e != nil {
		return nil, e
	}
	guard, e := c.guardProfile(ctx, p)
	if e != nil {
		return nil, e
	}
	defer guard.release()
	pending, e := c.store.LoadPending(ctx, p)
	if e != nil || pending == nil {
		return nil, e
	}
	progress(o, StageResumingCertificate)
	return c.complete(ctx, p, *pending, o, guard, false)
}

// Ensure loads, resumes, or provisions a currently valid identity. Empty profile
// selects "default". Use Connect to attach an expired identity and trigger the
// hosted service's ordinary renewal; Ensure does not attach a bridge.
func (c *Client) Ensure(ctx context.Context, profile string) (*Identity, error) {
	ctx, end, e := c.begin(ctx)
	if e != nil {
		return nil, e
	}
	defer end()
	p, e := profileName(profile)
	if e != nil {
		return nil, e
	}
	guard, e := c.guardProfile(ctx, p)
	if e != nil {
		return nil, e
	}
	defer guard.release()
	return c.ensure(ctx, p, false, guard)
}
func (c *Client) ensure(ctx context.Context, p string, allowExpired bool, guard *profileGuard) (*Identity, error) {
	id, e := c.store.Load(ctx, p)
	if e != nil {
		return nil, e
	}
	if id == nil {
		return c.create(ctx, p, ProvisionOptions{}, guard)
	}
	cert, e := c.api.Certificate(ctx, id.ID, id.Token)
	if e != nil {
		// A valid local identity can attach during a temporary API outage. Do not
		// bypass authentication/not-found failures or local certificate validation.
		var rejected *APIError
		if allowExpired && (!errors.As(e, &rejected) || rejected.StatusCode >= 500) && ctx.Err() == nil {
			if local, valid := parseCertificate(*id); valid == nil {
				id.CertificateExpiry = local.Leaf.NotAfter
				return id, nil
			}
		}
		return nil, e
	}
	if cert.State.Type == "failed" {
		pending, err := c.startCertificateRecovery(ctx, p, *id)
		if err != nil {
			return nil, err
		}
		return c.complete(ctx, p, *pending, ProvisionOptions{}, guard, true)
	}
	replacement := cert.State.Type == "ready" && (cert.State.Certificate != id.Certificate || cert.State.Chain != id.Chain)
	if replacement {
		id.Certificate = cert.State.Certificate
		id.Chain = cert.State.Chain
		id.CertificateExpiry = cert.State.Expiry
	}
	validated, e := parseCertificate(*id)
	if e != nil {
		if !allowExpired || !errors.Is(e, ErrCertificateExpired) {
			return nil, e
		}
		validated, e = parseCertificateMaterial(*id)
		if e != nil {
			return nil, e
		}
	}
	id.CertificateExpiry = validated.Leaf.NotAfter
	if replacement {
		if e := c.store.Save(ctx, p, *id); e != nil {
			return nil, e
		}
		if time.Now().Before(validated.Leaf.NotAfter) {
			c.recoveryAfter.Delete(p)
		}
	}
	return id, nil
}

// All replacement submissions require the profile lock and share one cooldown.
func (c *Client) startCertificateRecovery(ctx context.Context, p string, id Identity) (*PendingIdentity, error) {
	if time.Now().Before(c.recoveryDeadline(p)) {
		return nil, ErrCertificateIssuance
	}
	csr, err := requestForExistingKey(id.Hostname, id.PrivateKey)
	if err != nil {
		return nil, err
	}
	pending := PendingIdentity{ID: id.ID, Hostname: id.Hostname, Token: id.Token, PrivateKey: id.PrivateKey, CSR: csr}
	if err := c.store.SavePending(ctx, p, pending); err != nil {
		return nil, err
	}
	if err := c.submitCertificate(ctx, p, pending); err != nil {
		return nil, err
	}
	return &pending, nil
}

func (c *Client) submitCertificate(ctx context.Context, p string, pending PendingIdentity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if time.Now().Before(c.recoveryDeadline(p)) {
		return ErrCertificateIssuance
	}
	// A failed request can conceal an accepted CSR. Record before sending it.
	c.recoveryAfter.Store(p, time.Now().Add(c.options.CertificateRetryInterval))
	_, err := c.api.BindCertificate(ctx, pending.ID, pending.Token, pending.CSR)
	if err != nil {
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Tag != "CertificateInProgressError" {
			return err
		}
	}
	return nil
}

// Remove releases the remote tunnel, stops this client's same-profile bridges,
// and removes local credentials. Remote failures retain credentials for retry.
// Empty profile selects "default"; an absent local identity succeeds.
func (c *Client) Remove(ctx context.Context, profile string) error {
	ctx, end, e := c.begin(ctx)
	if e != nil {
		return e
	}
	defer end()
	p, e := profileName(profile)
	if e != nil {
		return e
	}
	unlock, e := c.lockProfile(ctx, p)
	if e != nil {
		return e
	}
	defer unlock()
	id, e := c.store.Load(ctx, p)
	if e != nil {
		return e
	}
	var tunnelID, token string
	if id != nil {
		tunnelID, token = id.ID, id.Token
	} else {
		pending, e := c.store.LoadPending(ctx, p)
		if e != nil {
			return e
		}
		if pending == nil {
			return nil
		}
		tunnelID, token = pending.ID, pending.Token
	}
	if e := c.api.Remove(ctx, tunnelID, token); e != nil {
		var a *APIError
		if !errors.As(e, &a) || a.StatusCode != 404 {
			return e
		}
	}
	// Stop renewal before deleting credentials. Refresh shares this profile lock,
	// so it cannot recreate the identity after deletion.
	c.mu.Lock()
	conns := make([]*Connection, 0, len(c.connections))
	for conn, profile := range c.connections {
		if profile == p {
			conns = append(conns, conn)
			// Publish requested closure before cancellation can classify shutdown.
			conn.closeRequested.Store(true)
			conn.cancel()
		}
	}
	c.mu.Unlock()
	// Cancellation releases renewal workers waiting for this lock. Joining them
	// while holding it cannot deadlock.
	for _, conn := range conns {
		_ = conn.Close()
	}
	// Remote deletion succeeded. Finish local cleanup with a finite deadline,
	// even if the caller has cancelled.
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.api.timeout)
	defer cancel()
	if err := c.store.Remove(cleanup, p); err != nil {
		return err
	}
	c.recoveryAfter.Delete(p)
	return nil
}

func (c *Client) recoveryDeadline(profile string) time.Time {
	value, _ := c.recoveryAfter.Load(profile)
	deadline, _ := value.(time.Time)
	return deadline
}

// Close cancels and joins client-owned operations and connections. It is safe
// to call repeatedly and does not remove stored identities or remote tunnels.
func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	c.cancel()
	conns := make([]*Connection, 0, len(c.connections))
	for conn := range c.connections {
		conns = append(conns, conn)
	}
	c.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	c.wg.Wait()
	return nil
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
