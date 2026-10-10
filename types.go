// Package opentunnel terminates visitor TLS carried through OpenTunnel and
// exposes it through a net.Listener or forwards decrypted bytes to TCP targets.
// See docs/SECURITY.md for the operator trust boundary.
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
const Version = "0.3.0"

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
	ID                string    `json:"id"`
	Hostname          string    `json:"hostname"`
	Token             string    `json:"-"`
	PrivateKey        string    `json:"-"`
	Certificate       string    `json:"certificate"`
	Chain             string    `json:"chain"`
	CertificateExpiry time.Time `json:"certificateExpiry"`
}

// PendingIdentity holds credentials and a CSR while certificate issuance is pending.
// JSON omits Token and PrivateKey; custom Storage implementations must persist
// those secrets separately if they need to resume issuance.
type PendingIdentity struct {
	ID         string `json:"id"`
	Hostname   string `json:"hostname"`
	Token      string `json:"-"`
	PrivateKey string `json:"-"`
	CSR        string `json:"csr"`
}

// ProvisioningError means a known remote creation could neither be persisted nor
// deleted. Pending contains secret credentials: persist them securely or pass
// Pending.ID and Pending.Token to API.Remove. Key/CSR may be absent if generation
// failed; such a record supports deletion, not Resume.
type ProvisioningError struct {
	Pending PendingIdentity
	Err     error
}

func (e *ProvisioningError) Error() string {
	return "opentunnel: provisioning recovery required: " + e.Err.Error()
}
func (e *ProvisioningError) Unwrap() error { return e.Err }

// RecoveryIdentity returns the known credentials for secure recovery or deletion.
func (e *ProvisioningError) RecoveryIdentity() PendingIdentity { return e.Pending }

// StoredTunnel associates a stored completed identity with its profile name.
type StoredTunnel struct {
	Profile string   `json:"profile"`
	Tunnel  Identity `json:"tunnel"`
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
	// HTTPClient performs API and bridge handshakes. Nil uses the default client.
	HTTPClient *http.Client
	// RequestTimeout limits each control API request. Zero selects 15 seconds.
	RequestTimeout time.Duration
	// Transport configures connection limits and timing.
	Transport TransportOptions
}

// TransportOptions sets resource limits and timeouts. Zero values select defaults, except IdleTimeout;
// positive values override them.
type TransportOptions struct {
	// MaxConnections defaults to 256 concurrent visitor channels.
	MaxConnections int
	// EventBuffer defaults to 256 queued lossy lifecycle events.
	EventBuffer int
	// MaxInboundBytes defaults to 8 MiB buffered per visitor channel.
	MaxInboundBytes int
	// AttachTimeout defaults to 10 seconds for one bridge attachment.
	AttachTimeout time.Duration
	// HandshakeTimeout defaults to 10 seconds for each visitor TLS handshake.
	HandshakeTimeout time.Duration
	// DialTimeout defaults to 10 seconds for each backend dial.
	DialTimeout time.Duration
	// WriteTimeout defaults to 10 seconds for each bridge write.
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

// ProvisionOptions configures progress reporting. OnProgress runs synchronously;
// callbacks must not reenter operations on the same profile.
type ProvisionOptions struct{ OnProgress func(ProvisionStage) }

// ConnectOptions selects the profile, routes, and lifetime of a connection.
type ConnectOptions struct {
	// Profile is a lowercase DNS-label storage name; empty selects "default".
	Profile string
	// Routes must include at least one valid route-to-backend mapping.
	Routes Routes
	// Lifetime controls the running connection after startup. Nil leaves lifetime
	// ownership to Connection.Close and Client.Close. Connect's context bounds startup.
	Lifetime context.Context
}

// Event reports a lifecycle transition. Type determines which optional fields
// apply: connected uses Session and Routes; connection-opened/closed use Conn
// and Route (opened also uses Peer); reconnecting uses Attempt and Delay;
// certificate-expiring/expired/renewed use Expiry (expired also uses Error);
// certificate-refresh-failed uses Error; certificate-recovery-started has no
// extra fields. Disconnected and stopped use Reason or Error. Delay marshals
// as integer nanoseconds.
type Event struct {
	Type    string        `json:"type"`
	Attempt int           `json:"attempt,omitempty"`
	Session string        `json:"session,omitempty"`
	Routes  []string      `json:"routes,omitempty"`
	Reason  string        `json:"reason,omitempty"`
	Delay   time.Duration `json:"delay,omitempty"`
	Conn    uint32        `json:"conn,omitempty"`
	Route   string        `json:"route,omitempty"`
	Peer    string        `json:"peer,omitempty"`
	Error   string        `json:"error,omitempty"`
	Expiry  time.Time     `json:"expiry,omitzero"`
}

// Status is a snapshot of one connection. DroppedEvents counts events omitted
// because its bounded event channel was full.
type Status struct {
	State         string    `json:"state"`
	Hostname      string    `json:"hostname"`
	Routes        Routes    `json:"routes"`
	Session       string    `json:"session,omitempty"`
	Connections   int       `json:"connections"`
	LastError     string    `json:"lastError,omitempty"`
	ConnectedAt   time.Time `json:"connectedAt,omitzero"`
	DroppedEvents uint64    `json:"droppedEvents"`
}

// TunnelInfo is the public remote state of a tunnel.
type TunnelInfo struct {
	ID            string `json:"id"`
	Hostname      string `json:"hostname"`
	State         string `json:"state"`
	CertificateID string `json:"certificateID,omitempty"`
}

// CreateTunnelResponse is the control API response for tunnel creation.
type CreateTunnelResponse struct {
	Tunnel TunnelInfo `json:"tunnel"`
	Token  string     `json:"token"`
}

// CertificateInfo is the control API response for certificate status.
type CertificateInfo struct {
	ID    string           `json:"id"`
	State CertificateState `json:"state"`
}

// CertificateState describes the current certificate issuance state.
type CertificateState struct {
	Type        string    `json:"type"`
	Token       string    `json:"token,omitempty"`
	Key         string    `json:"key,omitempty"`
	Certificate string    `json:"certificate,omitempty"`
	Chain       string    `json:"chain,omitempty"`
	Expiry      time.Time `json:"expiry,omitzero"`
	Reason      string    `json:"reason,omitempty"`
}

// APIError reports the remote HTTP status and a recognized protocol error tag.
// Unknown tags become HttpError so reflected credentials cannot reach logs.
type APIError struct {
	StatusCode int
	Tag        string
	Message    string
}

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
type AttachError struct{ Code string }

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
