package opentunnel

import (
	"fmt"
	"io"
	"log/slog"
	"strconv"
)

// String returns an identifier-only representation of an Identity.
func (i Identity) String() string { return identityText("Identity", i.ID, i.Hostname) }

// GoString returns an identifier-only Go-syntax representation of an Identity.
func (i Identity) GoString() string { return i.String() }

// Format writes an identifier-only representation regardless of the requested
// verb, preventing formatted values from exposing credentials.
func (i Identity) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, i.String()) }

// LogValue returns only non-secret identity attributes for structured logging.
func (i Identity) LogValue() slog.Value {
	return slog.GroupValue(slog.String("id", i.ID), slog.String("hostname", i.Hostname))
}

// String returns an identifier-only representation of a PendingIdentity.
func (i PendingIdentity) String() string { return identityText("PendingIdentity", i.ID, i.Hostname) }

// GoString returns an identifier-only Go-syntax representation of a PendingIdentity.
func (i PendingIdentity) GoString() string { return i.String() }

// Format writes an identifier-only representation regardless of the requested
// verb, preventing formatted values from exposing credentials.
func (i PendingIdentity) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, i.String()) }

// LogValue returns only non-secret pending identity attributes for structured logging.
func (i PendingIdentity) LogValue() slog.Value {
	return slog.GroupValue(slog.String("id", i.ID), slog.String("hostname", i.Hostname))
}

func identityText(kind, id, hostname string) string {
	return "opentunnel." + kind + "{ID:" + strconv.Quote(id) + ", Hostname:" + strconv.Quote(hostname) + "}"
}
