// Package opentunnel creates blind TLS tunnels compatible with OpenTunnel.
// TLS terminates in the embedding process; see docs/SECURITY.md for trust boundaries.
package opentunnel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const DefaultAPI = "https://opentunnel.xyz"
const Version = "0.1.0"

var (
	ErrClosed  = errors.New("opentunnel: closed")
	ErrExists  = errors.New("opentunnel: profile already has a tunnel")
	ErrInvalid = errors.New("opentunnel: invalid input")
)

type Routes map[string]string

// Identity contains credentials. Token and PrivateKey are excluded from JSON.
type Identity struct {
	ID                string    `json:"id"`
	Hostname          string    `json:"hostname"`
	Token             string    `json:"-"`
	PrivateKey        string    `json:"-"`
	Certificate       string    `json:"certificate"`
	Chain             string    `json:"chain"`
	CertificateExpiry time.Time `json:"certificateExpiry"`
}

type PendingIdentity struct {
	ID         string `json:"id"`
	Hostname   string `json:"hostname"`
	Token      string `json:"-"`
	PrivateKey string `json:"-"`
	CSR        string `json:"csr"`
}

type StoredTunnel struct {
	Profile string   `json:"profile"`
	Tunnel  Identity `json:"tunnel"`
}

// Storage implementations must be safe for concurrent use and honor cancellation.
// Missing data is represented by a nil pointer and nil error.
type Storage interface {
	Profiles(context.Context) ([]string, error)
	Load(context.Context, string) (*Identity, error)
	Save(context.Context, string, Identity) error
	LoadPending(context.Context, string) (*PendingIdentity, error)
	SavePending(context.Context, string, PendingIdentity) error
	Remove(context.Context, string) error
	List(context.Context) ([]StoredTunnel, error)
}

type ClientOptions struct {
	API            string
	Storage        Storage
	HTTPClient     *http.Client
	RequestTimeout time.Duration
	Transport      TransportOptions
}

// TransportOptions zero values select defaults. Positive overrides enable bounded
// resource use and deterministic integration tests without global settings.
type TransportOptions struct {
	MaxConnections             int
	EventBuffer                int
	MaxInboundBytes            int
	AttachTimeout              time.Duration
	HandshakeTimeout           time.Duration
	DialTimeout                time.Duration
	WriteTimeout               time.Duration
	CertificatePollInterval    time.Duration
	CertificateRefreshInterval time.Duration
	CertificateDueInterval     time.Duration
	BackoffMin                 time.Duration
	BackoffMax                 time.Duration
}

type ProvisionStage string

const (
	StageCreatingTunnel        ProvisionStage = "creating-tunnel"
	StageGeneratingKey         ProvisionStage = "generating-key"
	StageGeneratingCSR         ProvisionStage = "generating-csr"
	StageResumingCertificate   ProvisionStage = "resuming-certificate"
	StageRequestingCertificate ProvisionStage = "requesting-certificate"
	StageWaitingCertificate    ProvisionStage = "waiting-certificate"
	StageSavingIdentity        ProvisionStage = "saving-identity"
	StageReady                 ProvisionStage = "ready"
)

// OnProgress runs synchronously; callbacks must not reenter the same profile.
type ProvisionOptions struct{ OnProgress func(ProvisionStage) }
type ConnectOptions struct {
	Profile string
	Routes  Routes
}

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
	Expiry  time.Time     `json:"expiry,omitempty"`
}

type Status struct {
	State         string    `json:"state"`
	Hostname      string    `json:"hostname"`
	Routes        Routes    `json:"routes"`
	Session       string    `json:"session,omitempty"`
	Connections   int       `json:"connections"`
	LastError     string    `json:"lastError,omitempty"`
	ConnectedAt   time.Time `json:"connectedAt,omitempty"`
	DroppedEvents uint64    `json:"droppedEvents"`
}

type TunnelInfo struct {
	ID            string `json:"id"`
	Hostname      string `json:"hostname"`
	State         string `json:"state"`
	CertificateID string `json:"certificateID,omitempty"`
}
type CreateTunnelResponse struct {
	Tunnel TunnelInfo `json:"tunnel"`
	Token  string     `json:"token"`
}
type CertificateInfo struct {
	ID    string           `json:"id"`
	State CertificateState `json:"state"`
}
type CertificateState struct {
	Type        string    `json:"type"`
	Token       string    `json:"token,omitempty"`
	Key         string    `json:"key,omitempty"`
	Certificate string    `json:"certificate,omitempty"`
	Chain       string    `json:"chain,omitempty"`
	Expiry      time.Time `json:"expiry,omitempty"`
	Reason      string    `json:"reason,omitempty"`
}

// APIError preserves the remote HTTP status and error tag without exposing bodies.
type APIError struct {
	StatusCode int
	Tag        string
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("opentunnel API: HTTP %d (%q): %s", e.StatusCode, e.Tag, e.Message)
}

type AttachError struct{ Code string }

func (e *AttachError) Error() string { return fmt.Sprintf("opentunnel: attach failed: %q", e.Code) }
