# Implementation

Start with `client.go` for lifecycle operations and `connection.go` for a running
tunnel. `cmd/otgo` and `examples/webapp` both consume the public package.

The module is `github.com/darron/go-opentunnel`, requires Go 1.25 or newer, and
is MIT licensed. Its sole external module is `github.com/coder/websocket v1.8.15`.

## Lifecycle and persistence

| File | Responsibility |
| --- | --- |
| `api.go` | HTTP endpoints, finite deadlines, 1 MiB response limit, escaped IDs, typed errors, redirect hardening, and response-body ownership |
| `certificate.go` | Local P-256 keys/CSRs; certificate checks for key, validity, exact hostname, and wildcard SAN; material-only parsing for expired renewal attachment |
| `storage.go` | Concurrent memory storage and compatible file layout; private temporary files, marker-scoped removal, metadata last, permissions, and symlink rejection |
| `client.go` | Per-profile lifecycle lock, pending state before issuance, same-key recovery, owned cancellation, and bounded local cleanup after confirmed remote deletion |

File replacement is atomic per file. A crash can leave a mixed generation across
credential files. The store does not provide a cross-process transaction or
lock, and its path checks retain a same-user check-then-use race.

## Transport

| File | Responsibility |
| --- | --- |
| `protocol.go` | Route/control validation and four-byte big-endian connection IDs; upstream fixtures are in `testdata/vectors/` |
| `connection.go` | Startup/lifetime ownership, same-profile route claims, reconnects, copied routes/status, bounded events, certificate refresh, and route-change attachment |
| `session.go` | Attachment, framing, heartbeat, channel dispatch, and bounded write queue |
| `channel.go` | SNI-to-route authorization, certificate-time checks, optional channel idle timeout, bidirectional TCP forwarding, half-close, and blocked-socket cancellation |

Target changes apply to new channels. Name changes reattach. Empty replacement
routes suspend attachment.

## Ownership

- The `Client.Connect` context bounds provisioning and the first valid
  attachment. It no longer owns the connection after return.
- `ConnectOptions.Lifetime` optionally owns the running connection. With no
  lifetime, call `Connection.Close` or `Client.Close`.
- `Connection.Close` cancels and joins its workers.
- `Client.Close` cancels and joins its owned operations and connections.
- `Client.API()` calls use their own contexts.
- Custom storage must honor cancellation; coordinate shared-profile provisioning
  across separate clients or processes.
- Custom `Storage.Save` must successfully store the completed identity before it
  clears pending state. Persist token and private-key fields explicitly;
  `json.Marshal` on an `Identity` intentionally omits them.

## Default resource limits

| Resource | Limit |
| --- | ---: |
| Active channels | 256 |
| Pending inbound bytes per channel | 8 MiB |
| Queued events | 256 |
| Outbound queue | 32 messages |
| Outbound payload per message | 32 KiB |
| Per-channel idle timeout | Disabled unless `TransportOptions.IdleTimeout` is positive |

The maximum aggregate inbound budget is **2 GiB**, before TLS, socket, and other
memory overhead. Lower `TransportOptions.MaxConnections` and `MaxInboundBytes`
for smaller applications.

An inbound overflow resets that channel. A large upload to a slow target can
reach this limit even when the session is healthy. A configured idle timeout
closes a channel only after no application bytes move in either direction. Slow
event consumers lose events;
`Status().DroppedEvents` counts them. Sustained outbound pressure can delay other
channels because the wire protocol has no per-channel flow control.

## Serialization

- `Identity` and `PendingIdentity` JSON, `fmt`, and `slog` representations omit
  credentials. Direct access to exported `Token` and `PrivateKey` fields still
  exposes secrets; other API response types can also contain credentials.
- `Event.Expiry`, `Status.ConnectedAt`, and `CertificateState.Expiry` use
  `omitzero`.
- `Event.Delay` is a Go `time.Duration`; JSON represents it as integer
  nanoseconds.
- Protocol controls use custom JSON marshaling where required zero values must
  remain on the wire.

## Review fixes covered by regressions

Lifecycle and credentials:

- Finish local cleanup after confirmed remote deletion, even if the caller cancels.
- Share a profile lock between renewal and deletion to prevent credential recreation.
- Reuse the stored key when retrying failed issuance, with a shared per-profile
  cooldown and no profile lock held across issuance polling.
- Attach an expired stored identity to trigger server renewal, but wait for a
  valid certificate before `Connect` returns.
- Require the wildcard SAN itself, rather than accepting a sample subdomain.
- Permit disjoint same-profile connections and reject overlapping route names
  with `ErrRouteInUse`.

I/O and shutdown:

- Cancel blocked upstream sockets on channel reset or overflow.
- Require ClientHello SNI to select the same route as the relay; reject missing
  SNI and expired certificates before dialing the target.
- Allow an optional application-byte idle timeout; keep zero disabled.
- Keep API deadlines active through response-body consumption.
- Restrict plain HTTP APIs to literal loopback/`localhost` and reject HTTPS
  downgrade and cross-origin redirects before another request is made.
- Preserve route-name changes that race session publication.
- Stop interactive CLI shutdown from waiting for EOF on inherited stdin. `quit`
  stops scanning; cancellation leaves native stdin to process exit after SDK cleanup.

Use [TESTING.md](TESTING.md) to rerun checks. Read
[VERIFICATION.md](VERIFICATION.md) for local evidence,
[LIVE_TESTING.md](LIVE_TESTING.md) for hosted-service evidence, and
[SECURITY.md](SECURITY.md) for trust boundaries. Use
[HARDENING.md](HARDENING.md) for the current hardening changes and unresolved
limits.
