package opentunnel

import (
	"sync"
	"time"
)

// Stats is a copied snapshot of cumulative counters and current gauges. Counters
// survive connection shutdown. Concurrent operations may progress between snapshots.
// It contains no tunnel, route, visitor, session or credential metadata.
type Stats struct {
	// APIRequests counts completed HTTP API requests, including failed attempts.
	// APIErrors counts transport, body, decoding, validation and HTTP status errors.
	// APIDuration is total completed request time, including body read/validation.
	// Inputs rejected before an HTTP request is attempted do not count.
	APIRequests, APIErrors uint64
	APIDuration            time.Duration
	// BridgeAttempts counts attach attempts; Reconnects counts attempts after the
	// first on each Connection. BridgeFailures counts unsuccessful attachment,
	// including cancellation, rather than teardown of an established bridge.
	BridgeAttempts, BridgeAttachments, BridgeFailures, Reconnects uint64
	// ConnectionsOpened/Closed count each admitted relay visitor once. Rejected
	// admissions count separately. ActiveConnections includes TLS handshakes and
	// handshaken listener visitors waiting for Accept.
	ConnectionsOpened, ConnectionsClosed, ConnectionsRejected uint64
	// BytesReceived/Sent count TLS record payload bytes read from/successfully
	// written to the relay transport, including handshakes, excluding relay frame
	// headers and WebSocket framing/control traffic. Successfully sent chunks
	// count even when a later chunk of the same write fails.
	BytesReceived, BytesSent uint64
	// DroppedEvents counts omissions from bounded Events channels.
	DroppedEvents uint64
	// Current gauges converge to zero after their owner closes.
	ActiveBridges, ActiveConnections, InboundBufferedBytes int64
}

type statistics struct {
	mu    sync.Mutex
	value Stats
}

func (s *statistics) snapshot() Stats { s.mu.Lock(); defer s.mu.Unlock(); return s.value }
func (s *statistics) add(d Stats) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.value.APIRequests += d.APIRequests
	s.value.APIErrors += d.APIErrors
	s.value.APIDuration += d.APIDuration
	s.value.BridgeAttempts += d.BridgeAttempts
	s.value.BridgeAttachments += d.BridgeAttachments
	s.value.BridgeFailures += d.BridgeFailures
	s.value.Reconnects += d.Reconnects
	s.value.ConnectionsOpened += d.ConnectionsOpened
	s.value.ConnectionsClosed += d.ConnectionsClosed
	s.value.ConnectionsRejected += d.ConnectionsRejected
	s.value.BytesReceived += d.BytesReceived
	s.value.BytesSent += d.BytesSent
	s.value.DroppedEvents += d.DroppedEvents
	s.value.ActiveBridges += d.ActiveBridges
	s.value.ActiveConnections += d.ActiveConnections
	s.value.InboundBufferedBytes += d.InboundBufferedBytes
}

// Stats returns API-only completed-request counters. Transport fields are zero.
// It includes direct low-level calls when the API belongs to a Client.
func (a *API) Stats() Stats { return a.stats.snapshot() }

// Stats returns all this client's API calls and transport operations, including
// direct API() calls and totals from connections that have already been removed.
// The API and transport snapshots are taken separately; no workers are blocked
// for the duration of a scrape. Client.Close does not cancel direct API() calls.
func (c *Client) Stats() Stats {
	s := c.stats.snapshot()
	if c.api != nil {
		a := c.api.Stats()
		s.APIRequests = a.APIRequests
		s.APIErrors = a.APIErrors
		s.APIDuration = a.APIDuration
	}
	return s
}

// Stats returns transport counters for this connection across all reattachments.
// API fields are zero: provisioning and refresh calls belong to Client/API scope.
// Snapshot reads are safe during forwarding, teardown and after Close.
func (x *Connection) Stats() Stats { return x.stats.snapshot() }

func (x *Connection) record(d Stats) {
	x.stats.add(d)
	if x.client != nil {
		x.client.stats.add(d)
	}
}
