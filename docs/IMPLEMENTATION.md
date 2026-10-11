# Implementation

Start with `client.go` for lifecycle operations and `connection.go` for a running
tunnel, or `listener.go` for direct HTTP embedding. `cmd/otgo` and `examples/webapp` both consume the public package.

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
| `listener.go` | TLS net.Listener, bounded accept queue, exact TLS connections, relay peer metadata, and socket ownership |
| `channel.go` | SNI-to-route authorization, certificate-time checks, optional channel idle timeout, bidirectional TCP forwarding, half-close, and blocked-socket cancellation |

Target changes apply to new channels. Name changes reattach. Empty replacement
routes suspend attachment.

## Ownership

- The `Client.Connect` or `Client.Listen` context bounds provisioning and the first valid
  attachment. It no longer owns the connection after return.
- `ConnectOptions.Lifetime` or `ListenOptions.Lifetime` optionally owns the running
  tunnel. With no lifetime, call its `Close` or `Client.Close`.
- `Connection.Close` and `Listener.Close` cancel and join their package workers.
  Listener close also aborts accepted sockets; application handlers are not joined.
- `Client.Close` cancels and joins its owned operations and connections.
- `Client.API()` calls use their own contexts.

Custom storage must honor cancellation and coordinate shared-profile provisioning
across separate clients or processes. `Storage.Save` must store the completed
identity before clearing pending state. Persist token and private-key fields
explicitly: `json.Marshal` on an `Identity` intentionally omits them.

## Default resource limits

| Resource | Limit |
| --- | ---: |
| Active channels | 256 |
| Pending inbound bytes per channel | 8 MiB |
| Pending inbound bytes per relay session | 64 MiB |
| Queued events | 256 |
| Outbound data queue | 32 messages |
| Reader-reply queue | 32 messages; reader replies wait for capacity; heartbeat pings coalesce/skip when busy |
| Teardown-control queue | 32 messages reserved; saturation closes the session |
| Outbound payload per message | 32 KiB |
| Per-channel idle timeout | Disabled unless `TransportOptions.IdleTimeout` is positive |

The aggregate inbound payload budget is **64 MiB per relay session**. Coalesced 32 KiB
blocks add at most 64 KiB capacity per channel plus bounded slice metadata; TLS,
sockets, and other memory remain additional overhead. Lower
`TransportOptions.MaxConnections`, `MaxInboundBytes` and `MaxInboundTotalBytes`
for smaller applications. Separate relay sessions have separate budgets.

Exceeding either inbound budget resets only the channel receiving that frame.
Reads and aborts release its aggregate reservation. A large upload to a slow target can
reach this limit even when the session is healthy. A configured idle timeout
closes inactive channels: Connect counts application bytes, while Listen counts
TLS records consumed or written by the application. Slow event consumers lose events;
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
- Visitor open/close events retain `conn=0`; unrelated events omit unused IDs.
- Protocol controls use custom JSON marshaling where required zero values must
  remain on the wire.

## CLI authentication

| Location | Responsibility |
| --- | --- |
| `cmd/otgo/auth.go` | Password/GitHub setup, profile locks and machine-token commands |
| `cmd/otgo/proxy.go` | Saved identity validation, listener startup and proxy lifetime |
| `internal/authproxy/` | Login gate, sessions, OAuth wizard, bound token registries, private storage and backend forwarding |

The gate is internal to the CLI. The public SDK exposes transport APIs without
adding application authentication. See [AUTH_PROXY.md](AUTH_PROXY.md) for setup,
migration and compatibility limits.

## Verification

Use [TESTING.md](TESTING.md) for commands. The [current audit](SECURITY_AUDIT.md)
records reproduced defects and test-quality checks; [local results](VERIFICATION.md)
and [hosted results](LIVE_TESTING.md) identify the revisions tested.
[SECURITY.md](SECURITY.md) describes trust boundaries. Earlier review decisions
remain in the [archive](archive/README.md).
