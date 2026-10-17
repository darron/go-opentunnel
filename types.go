package opentunnel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// DefaultAPI is the hosted OpenTunnel control API endpoint.
const DefaultAPI = "https://opentunnel.xyz"

// Version is this module's protocol client version.
const Version = "0.14.1"

var (
	// ErrClosed reports an operation attempted after its Client, Connection, or Listener was closed.
	ErrClosed = errors.New("opentunnel: closed")
	// ErrExists reports an attempt to create a completed tunnel over an existing profile.
	ErrExists = errors.New("opentunnel: profile already has a tunnel")
	// ErrProfileChanged reports removal or replacement during provisioning.
	ErrProfileChanged = errors.New("opentunnel: profile removed or replaced during provisioning")
	// ErrInvalid reports invalid input or protocol/certificate data.
	ErrInvalid = errors.New("opentunnel: invalid input")
	// ErrRouteInUse reports overlapping routes on tunnels owned by one Client.
	ErrRouteInUse = errors.New("opentunnel: route already connected by this client")
	// ErrRouteMismatch reports a TLS hostname that differs from the relay route.
	ErrRouteMismatch = errors.New("opentunnel: TLS hostname does not match relay route")
	// ErrCertificateExpired reports a certificate at or past its NotAfter time.
	ErrCertificateExpired = fmt.Errorf("%w: certificate expired", ErrInvalid)
	// ErrCertificateIssuance reports terminal certificate issuance failure.
	ErrCertificateIssuance = errors.New("opentunnel: certificate issuance failed")
	// ErrInboundLimit reports a channel whose inbound buffer reached its limit.
	ErrInboundLimit = errors.New("opentunnel: inbound channel buffer limit exceeded")
	// ErrHalfCloseTimeout reports an observed half-close closed for subsequent inactivity.
	ErrHalfCloseTimeout = errors.New("opentunnel: half-closed channel inactivity timeout")
	// ErrIdleTimeout reports an established channel closed for inactivity.
	ErrIdleTimeout = errors.New("opentunnel: channel idle timeout")
)

// Routes maps route names to backend host:port targets. "@" is the root
// hostname; other names are lowercase DNS labels for subdomains.
type Routes map[string]string

// Identity holds a completed tunnel's credentials. JSON omits Token and
// PrivateKey; custom Storage implementations must persist those secrets
// separately if they need to restore an identity.
type Identity struct {
	// ID identifies the remote tunnel.
	ID string `json:"id"`
	// Hostname is the tunnel's public root DNS name, without a scheme or port.
	Hostname string `json:"hostname"`
	// Token authenticates control API and relay requests. Keep it secret.
	Token string `json:"-"`
	// PrivateKey is the locally generated PKCS#8 PEM key. Keep it secret.
	PrivateKey string `json:"-"`
	// Certificate is the PEM-encoded visitor TLS leaf certificate.
	Certificate string `json:"certificate"`
	// Chain is the PEM-encoded certificate chain returned by the service.
	Chain string `json:"chain"`
	// CertificateExpiry is the stored certificate's expiration time.
	CertificateExpiry time.Time `json:"certificateExpiry"`
}

// PendingIdentity holds credentials and a CSR while certificate issuance is pending.
// JSON omits Token and PrivateKey; custom Storage implementations must persist
// those secrets separately if they need to resume issuance.
type PendingIdentity struct {
	// ID identifies the remote tunnel awaiting issuance.
	ID string `json:"id"`
	// Hostname is the tunnel's public root DNS name.
	Hostname string `json:"hostname"`
	// Token authenticates recovery or remote deletion. Keep it secret.
	Token string `json:"-"`
	// PrivateKey is the PKCS#8 PEM key used for CSR. Keep it secret.
	PrivateKey string `json:"-"`
	// CSR is the PEM-encoded certificate signing request for this key and hostname.
	CSR string `json:"csr"`
}

// ProvisioningError means a known remote creation could neither be persisted nor
// deleted. Pending contains secret credentials: persist them securely or pass
// Pending.ID and Pending.Token to API.Remove. Key/CSR may be absent if generation
// failed; such a record supports deletion, not Resume.
type ProvisioningError struct {
	// Pending contains the remote identity's recovery credentials.
	Pending PendingIdentity
	// Err is the underlying persistence or cleanup failure.
	Err error
}

// Error returns a recovery-required message with the underlying failure.
func (e *ProvisioningError) Error() string {
	return "opentunnel: provisioning recovery required: " + e.Err.Error()
}

// Unwrap returns the underlying failure for errors.Is and errors.As.
func (e *ProvisioningError) Unwrap() error { return e.Err }

// RecoveryIdentity returns the known credentials for secure recovery or deletion.
func (e *ProvisioningError) RecoveryIdentity() PendingIdentity { return e.Pending }

// StoredTunnel associates a stored completed identity with its profile name.
type StoredTunnel struct {
	// Profile is the local storage name associated with Tunnel.
	Profile string `json:"profile"`
	// Tunnel is the completed identity, including live credential fields.
	Tunnel Identity `json:"tunnel"`
}

// Storage persists profiles. Implementations must support concurrent calls and
// cancellation. Missing identities return (nil, nil). Save must clear any
// pending identity only after successfully storing the completed identity.
type Storage interface {
	// Profiles returns sorted profile names.
	Profiles(context.Context) ([]string, error)
	// Load returns a completed identity, or (nil, nil) when absent.
	Load(context.Context, string) (*Identity, error)
	// Save persists a completed identity and clears any pending identity.
	Save(context.Context, string, Identity) error
	// LoadPending returns a pending identity, or (nil, nil) when absent.
	LoadPending(context.Context, string) (*PendingIdentity, error)
	// SavePending persists an issuance recovery record.
	SavePending(context.Context, string, PendingIdentity) error
	// Remove removes the profile's credentials.
	Remove(context.Context, string) error
	// List returns all completed identities with their profile names.
	List(context.Context) ([]StoredTunnel, error)
}

// ClientOptions configures a Client.
type ClientOptions struct {
	// API is the control API base URL. Empty selects DefaultAPI.
	API string
	// Storage persists identities. Nil selects XDG-backed storage.
	Storage Storage
	// HTTPClient performs API and bridge handshakes. Nil uses the default HTTP
	// transport. Custom transport, cookie jar and hooks are trusted with secrets.
	HTTPClient *http.Client
	// CACertFile adds PEM certificates to the API and relay trust roots. Empty
	// uses HTTPClient's existing trust. With a custom HTTPClient, its transport
	// must be an *http.Transport with TLS verification enabled and no custom
	// TLS dialer; it is cloned.
	// This does not change visitor TLS, backend trust, or process-wide defaults.
	CACertFile string
	// RequestTimeout limits each control API operation, including retries and
	// body reads. Zero selects 15 seconds.
	RequestTimeout time.Duration
	// Transport configures connection limits and timing.
	Transport TransportOptions
}

// TransportOptions sets resource limits and timeouts. Zero values select defaults,
// except IdleTimeout, which stays disabled. Negative values are invalid, and
// BackoffMax must be at least BackoffMin after defaults are applied.
// The relay has no per-channel flow control; sustained outbound backpressure
// can delay other channels. Inbound overflow resets the affected channel.
type TransportOptions struct {
	// MaxConnections defaults to 256 concurrent visitor channels.
	MaxConnections int
	// EventBuffer defaults to 256 queued lossy lifecycle events.
	EventBuffer int
	// MaxInboundBytes defaults to 8 MiB buffered per visitor channel.
	MaxInboundBytes int
	// MaxInboundTotalBytes defaults to 64 MiB buffered across all visitor
	// channels in one relay session.
	MaxInboundTotalBytes int
	// AttachTimeout defaults to 10 seconds for one bridge attachment.
	AttachTimeout time.Duration
	// HandshakeTimeout defaults to 10 seconds for each visitor TLS handshake.
	HandshakeTimeout time.Duration
	// DialTimeout defaults to 10 seconds for each backend dial.
	DialTimeout time.Duration
	// WriteTimeout defaults to 10 seconds for each bridge write and PROXY header write.
	WriteTimeout time.Duration
	// CertificatePollInterval defaults to 2 seconds while issuance is pending.
	CertificatePollInterval time.Duration
	// CertificateRefreshInterval defaults to 12 hours between renewal checks.
	CertificateRefreshInterval time.Duration
	// CertificateDueInterval defaults to 1 minute between checks in the renewal window.
	CertificateDueInterval time.Duration
	// CertificateRetryInterval defaults to 1 hour between failed-issuance CSR
	// submissions. The cooldown is shared by this client's same-profile bridges.
	CertificateRetryInterval time.Duration
	// BackoffMin defaults to 250 milliseconds for bridge reconnection.
	BackoffMin time.Duration
	// BackoffMax defaults to 30 seconds for bridge reconnection.
	BackoffMax time.Duration
	// IdleTimeout closes inactive established channels. Connect counts application
	// bytes; Listen counts TLS records read/written by the application. Zero disables it.
	IdleTimeout time.Duration
	// HalfCloseTimeout defaults to 60 seconds of inactivity after an observed
	// half-close. Negative values are invalid. Application bytes and successful
	// transport chunks extend it, including progress within a pending TLS Write.
	// Fully open idle streams are unaffected. Connect observes either copy reaching
	// EOF. Listen observes explicit relay end or raw CloseWrite; it cannot observe
	// encrypted TLS close_notify itself. Applications must close accepted
	// connections. Listen counts transport record activity.
	HalfCloseTimeout time.Duration
}

// ProvisionStage identifies synchronous provisioning progress callbacks.
type ProvisionStage string

const (
	// StageCreatingTunnel reports remote tunnel creation.
	StageCreatingTunnel ProvisionStage = "creating-tunnel"
	// StageGeneratingKey reports local private-key generation.
	StageGeneratingKey ProvisionStage = "generating-key"
	// StageGeneratingCSR reports local certificate-request generation.
	StageGeneratingCSR ProvisionStage = "generating-csr"
	// StageResumingCertificate reports a persisted issuance recovery attempt.
	StageResumingCertificate ProvisionStage = "resuming-certificate"
	// StageRequestingCertificate reports CSR submission.
	StageRequestingCertificate ProvisionStage = "requesting-certificate"
	// StageWaitingCertificate reports certificate status polling.
	StageWaitingCertificate ProvisionStage = "waiting-certificate"
	// StageSavingIdentity reports completed-identity storage.
	StageSavingIdentity ProvisionStage = "saving-identity"
	// StageReady reports a completed identity ready for use.
	StageReady ProvisionStage = "ready"
)

// ProvisionOptions configures progress reporting. Its zero value disables callbacks.
type ProvisionOptions struct {
	// OnProgress runs synchronously during Create or Resume. It must return
	// promptly and must not reenter operations on the same profile or call
	// Client.Close, which waits for the operation invoking the callback.
	OnProgress func(ProvisionStage)
}

// ConnectOptions selects the profile, routes, and lifetime of a connection.
type ConnectOptions struct {
	// Profile is a lowercase DNS-label storage name; empty selects "default".
	Profile string
	// Routes must include at least one valid route-to-backend mapping.
	Routes Routes
	// RouteOptions enables local forwarding options for configured route names.
	// Missing entries forward bytes unchanged. Both maps are copied on entry.
	RouteOptions map[string]RouteOptions
	// Lifetime controls the running connection after startup. Nil leaves lifetime
	// ownership to Connection.Close and Client.Close. Connect's context bounds startup.
	Lifetime context.Context
}

// Event reports a lifecycle transition. Type determines which fields apply;
// unused fields have their zero values. Delivery is bounded and lossy; use
// Status.DroppedEvents to detect omissions and Status for current state.
type Event struct {
	// Type is connecting, connected, disconnected, reconnecting, stopped,
	// connection-opened, connection-closed, certificate-expiring,
	// certificate-expired, certificate-renewed, certificate-refresh-failed,
	// or certificate-recovery-started.
	Type string `json:"type"`
	// Attempt is the retry count for connecting or reconnecting events.
	Attempt int `json:"attempt,omitempty"`
	// Session is the relay session identifier for a connected event.
	Session string `json:"session,omitempty"`
	// Routes contains the relay-accepted route names for a connected event.
	Routes []string `json:"routes,omitempty"`
	// Reason explains a disconnected event.
	Reason string `json:"reason,omitempty"`
	// Delay is the planned reconnect wait, encoded as integer nanoseconds in JSON.
	Delay time.Duration `json:"delay,omitempty"`
	// Conn identifies a visitor channel within its relay session. Zero is valid.
	Conn uint32 `json:"conn,omitempty"`
	// Route is the route name for a connection-opened or connection-closed event.
	Route string `json:"route,omitempty"`
	// Peer is the relay-provided address for a connection-opened event.
	// It is not an independently verified visitor identity.
	Peer string `json:"peer,omitempty"`
	// Error contains diagnostic text for a failed channel, certificate or tunnel.
	Error string `json:"error,omitempty"`
	// Expiry is the certificate expiration for expiring, expired or renewed events.
	Expiry time.Time `json:"expiry,omitzero"`
}

// Status is a snapshot of one connection. DroppedEvents counts events omitted
// because its bounded event channel was full.
type Status struct {
	// State is connecting, connected, reconnecting, waiting-routes or stopped.
	State string `json:"state"`
	// Hostname is the tunnel's public root DNS name.
	Hostname string `json:"hostname"`
	// Routes is a copy of the locally configured routes. Listener targets are empty.
	Routes Routes `json:"routes"`
	// RouteOptions is a copy of the local forwarding options. Listeners have none.
	RouteOptions map[string]RouteOptions `json:"routeOptions,omitempty"`
	// Session is the current relay session identifier, empty when unattached.
	Session string `json:"session,omitempty"`
	// Connections counts visitor channels, including handshaking and queued sockets.
	Connections int `json:"connections"`
	// LastError is diagnostic text, cleared after a successful bridge attachment.
	// It is not a typed error; use Connection.Err or Listener.Err for terminal errors.
	LastError string `json:"lastError,omitempty"`
	// ConnectedAt is the most recent successful attachment time, zero before the first.
	ConnectedAt time.Time `json:"connectedAt,omitzero"`
	// DroppedEvents counts lifecycle events omitted because the event buffer was full.
	DroppedEvents uint64 `json:"droppedEvents"`
}

// TunnelInfo is the public remote state of a tunnel.
type TunnelInfo struct {
	// ID identifies the remote tunnel.
	ID string `json:"id"`
	// Hostname is its public root DNS name.
	Hostname string `json:"hostname"`
	// State is online or offline as reported by the service.
	State string `json:"state"`
	// CertificateID identifies its certificate, if assigned.
	CertificateID string `json:"certificateID,omitempty"`
}

// CreateTunnelResponse is the control API response for tunnel creation.
// Unlike Identity, this response includes Token in JSON and ordinary formatting.
type CreateTunnelResponse struct {
	// Tunnel contains the new remote tunnel's public metadata.
	Tunnel TunnelInfo `json:"tunnel"`
	// Token authenticates the new tunnel. Keep it secret and persist it securely.
	Token string `json:"token"`
}

// CertificateInfo is the control API response for certificate status.
type CertificateInfo struct {
	// ID identifies the service's certificate record.
	ID string `json:"id"`
	// State contains its current issuance result or challenge.
	State CertificateState `json:"state"`
}

// CertificateState describes the current certificate issuance state.
// Type determines which other fields apply. Treat challenge material as sensitive;
// this API response does not redact it in JSON or ordinary formatting.
type CertificateState struct {
	// Type is challenge, issuing, ready or failed.
	Type string `json:"type"`
	// Token is the service's ACME challenge token when Type is challenge.
	Token string `json:"token,omitempty"`
	// Key is the ACME DNS-01 TXT value, not the local TLS private key.
	Key string `json:"key,omitempty"`
	// Certificate is the PEM leaf certificate when Type is ready.
	Certificate string `json:"certificate,omitempty"`
	// Chain is the PEM certificate chain when Type is ready.
	Chain string `json:"chain,omitempty"`
	// Expiry is the certificate expiration when Type is ready.
	Expiry time.Time `json:"expiry,omitzero"`
	// Reason explains terminal issuance failure when Type is failed.
	Reason string `json:"reason,omitempty"`
}

// APIError reports the remote HTTP status and a recognized protocol error tag.
// Unknown tags become HttpError so reflected credentials cannot reach logs.
type APIError struct {
	// StatusCode is the rejected request's HTTP response status.
	StatusCode int
	// Tag is a recognized service error tag, or HttpError for an unknown tag.
	Tag string
	// Message is diagnostic text. API-generated errors do not copy response bodies.
	Message string
}

// Error returns HTTP status, a normalized tag and Message.
func (e *APIError) Error() string {
	return fmt.Sprintf("opentunnel API: HTTP %d (%q): %s", e.StatusCode, diagnosticAPITag(e.Tag), e.Message)
}

func diagnosticAPITag(tag string) string {
	switch tag {
	case "InvalidRequestError", "UnauthorizedError", "TunnelNotFoundError", "CertificateNotFoundError", "InvalidHostnameError", "HostnameUnavailableError", "CertificateInProgressError", "ServiceUnavailableError":
		return tag
	default:
		return "HttpError"
	}
}

// AttachError reports a relay bridge attachment failure code.
// bad_token and cert_not_ready stop a connection; other failures are retried.
type AttachError struct {
	// Code is a recognized relay error code, or unknown for an unrecognized code.
	Code string
}

// Error returns the normalized attachment failure code.
func (e *AttachError) Error() string {
	return fmt.Sprintf("opentunnel: attach failed: %q", diagnosticAttachCode(e.Code))
}

func diagnosticAttachCode(code string) string {
	switch code {
	case "bad_attach", "bad_token", "tunnel_not_bound", "cert_not_ready", "replaced", "upstream_connect_failed", "upstream_io_error", "client_io_error", "idle_timeout", "route_conflict", "invalid_route", "unknown_route", "too_many_connections":
		return code
	default:
		return "unknown"
	}
}
