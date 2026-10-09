# Implementation

Start with `client.go` for lifecycle operations and `connection.go` for a running
tunnel. `cmd/otgo` and `examples/webapp` both consume the public package.

The module is `github.com/darron/go-opentunnel`, requires Go 1.25 or newer, and
is MIT licensed. Its sole external module is `github.com/coder/websocket v1.8.15`.

## Lifecycle and persistence

| File | Responsibility |
| --- | --- |
| `api.go` | HTTP endpoints, finite deadlines, 1 MiB response limit, escaped IDs, typed errors, and response-body ownership |
| `certificate.go` | Local P-256 keys/CSRs; certificate checks for key, validity, exact hostname, and wildcard SAN |
| `storage.go` | Concurrent memory storage and compatible file layout; private temporary files, atomic replacement, metadata last, and symlink rejection |
| `client.go` | Per-profile lifecycle lock, pending state before issuance, recovery, owned cancellation, and bounded local cleanup after confirmed remote deletion |

File replacement is atomic per file. The store does not provide a cross-process
transaction or lock.

## Transport

| File | Responsibility |
| --- | --- |
| `protocol.go` | Route/control validation and four-byte big-endian connection IDs; upstream fixtures are in `testdata/vectors/` |
| `connection.go` | Reconnects, copied routes/status, bounded events, certificate refresh, and route-change attachment |
| `session.go` | Attachment, framing, heartbeat, channel dispatch, and bounded write queue |
| `channel.go` | Local visitor TLS, bidirectional TCP forwarding, half-close, and cancellation of blocked upstream sockets |

Target changes apply to new channels. Name changes reattach. Empty replacement
routes suspend attachment.

## Ownership

- The connection context lasts for the entire bridge lifetime.
- `Connection.Close` cancels and joins its workers.
- `Client.Close` cancels and joins its owned operations and connections.
- `Client.API()` calls use their own contexts.
- Custom storage must honor cancellation; coordinate shared-profile provisioning
  across separate clients or processes.

## Default resource limits

| Resource | Limit |
| --- | ---: |
| Active channels | 256 |
| Pending inbound bytes per channel | 8 MiB |
| Queued events | 256 |
| Outbound queue | 32 messages |
| Outbound payload per message | 32 KiB |

The maximum aggregate inbound budget is **2 GiB**, before TLS, socket, and other
memory overhead. Lower `TransportOptions.MaxConnections` and `MaxInboundBytes`
for smaller applications.

An inbound overflow resets that channel. Slow event consumers lose events;
`Status().DroppedEvents` counts them. Sustained outbound pressure can delay other
channels because the wire protocol has no per-channel flow control.

## Review fixes covered by regressions

Lifecycle and credentials:

- Finish local cleanup after confirmed remote deletion, even if the caller cancels.
- Share a profile lock between renewal and deletion to prevent credential recreation.
- Reuse the stored key when retrying failed issuance.
- Require the wildcard SAN itself, rather than accepting a sample subdomain.

I/O and shutdown:

- Cancel blocked upstream sockets on channel reset or overflow.
- Keep API deadlines active through response-body consumption.
- Preserve route-name changes that race session publication.
- Stop interactive CLI shutdown from waiting for EOF on inherited stdin. `quit`
  stops scanning; cancellation leaves native stdin to process exit after SDK cleanup.

Use [TESTING.md](TESTING.md) to rerun checks. Read
[VERIFICATION.md](VERIFICATION.md) for local evidence,
[LIVE_TESTING.md](LIVE_TESTING.md) for hosted-service evidence, and
[SECURITY.md](SECURITY.md) for trust boundaries.
