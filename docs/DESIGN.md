# Native Go OpenTunnel client and otgo verification CLI

## Intended outcome

Build a Go package that applications can embed to create and manage OpenTunnel
tunnels and forward public TLS connections to local services. Match the
capabilities of the upstream TypeScript SDK and the HTTP, WebSocket, certificate,
and storage protocols shared with the Rust client. Build a small `otgo` CLI to
exercise the exported package; the CLI is a testing and diagnostic consumer,
not the architecture the library depends on.

Success requires a usable public API, deterministic local integration tests,
race-detector checks, an embedding example, and a CLI ready for a subsequent
live test with the user. Local test success does not establish interoperability
with the deployed public service; report that separately.

## Compatibility baseline

Inspected upstream commit: `22156aa6ab209515186c3ca4f111901b7cedc284`.

Source references:

- [Protocol specification](https://github.com/anomalyco/opentunnel/blob/22156aa6ab209515186c3ca4f111901b7cedc284/docs/protocol.md)
- [SDK API](https://github.com/anomalyco/opentunnel/blob/22156aa6ab209515186c3ca4f111901b7cedc284/packages/client/src/promise/client.ts)
- [SDK types](https://github.com/anomalyco/opentunnel/blob/22156aa6ab209515186c3ca4f111901b7cedc284/packages/client/src/effect/types.ts)
- [Shared vectors](https://github.com/anomalyco/opentunnel/tree/22156aa6ab209515186c3ca4f111901b7cedc284/spec/vectors)

The upstream JavaScript distribution is compiled from the TypeScript SDK; the
other native implementation is Rust. This project implements the client, not
the hosted relay or certificate authority.

## Approach and tradeoffs

Recommended: native Go with standard-library HTTP, P-256 key generation, X.509
CSR creation, TLS termination, and TCP forwarding, plus one maintained WebSocket
dependency. This supports embedding, cancellation, and Go deployment without
requiring Bun, Node, Rust, or a background process.

A wrapper around the upstream CLI would reduce initial protocol work, but would
add executable deployment and process supervision to every embedding app.
Implementing a new relay would expand the task and would not demonstrate client
compatibility with OpenTunnel. Neither alternative is selected.

## Public package and API

Use package `opentunnel` at the module root. The provisional module path is
`github.com/darron/go-opentunnel`, consistent with the checkout name; publishing
and creating a remote repository are outside this task.

Expose a flat, idiomatic Go API with a documented mapping from the TypeScript
SDK rather than reproducing JavaScript namespaces or promises:

| TypeScript operation | Go operation |
| --- | --- |
| `create(options)` | `NewClient(options) (*Client, error)` |
| `profile.list()` | `Client.Profiles(ctx)` |
| `tunnel.list()` | `Client.List(ctx)` |
| `tunnel.get(options)` | `Client.Get(ctx, profile)` |
| `tunnel.pending(options)` | `Client.Pending(ctx, profile)` |
| `tunnel.create(options)` | `Client.Create(ctx, profile, provisionOptions)` |
| `tunnel.resume(options)` | `Client.Resume(ctx, profile, provisionOptions)` |
| `tunnel.ensure(options)` | `Client.Ensure(ctx, profile)` |
| `tunnel.remove(options)` | `Client.Remove(ctx, profile)` |
| `tunnel.connect(options)` | `Client.Connect(ctx, connectOptions)` |
| `dispose()` | `Client.Close()` |
| `connection.tunnel` | `Connection.Identity()` |
| `connection.events` | `Connection.Events()` |
| `connection.status()` | `Connection.Status()` |
| `connection.setRoutes(routes)` | `Connection.SetRoutes(routes)` |
| `connection.closed` | `Connection.Done()` and `Connection.Err()` |
| `connection.close()` | `Connection.Close()` |

All fallible client operations return errors. `Get`, `Pending`, and `Resume`
return a nil identity with a nil error for absent data. An empty profile option
selects `default`; storage operations themselves validate explicit profile names.

`ClientOptions` accepts an API base URL, a `Storage` implementation, an HTTP
client, and bounded transport settings. Defaults target `https://opentunnel.xyz`
and XDG storage. Request, handshake, and local dial timeouts are finite and
overridable. No logger, CLI output, signal handling, or process exit is required
by the package. HTTP customization also applies to WebSocket dialing where
supported by the chosen dependency.

Export `Routes` as a map from route name to `host:port`. Copy caller maps on entry
and return copies in snapshots. Return identity snapshots rather than exposing
mutable session state. Export structured events and typed errors usable with
`errors.Is`/`errors.As`, including API status/tag and bridge attach code.

`Connect` validates inputs before any provisioning side effect, ensures the
identity, and returns after the first successful attach. Its context governs
the connection lifetime, including provisioning and reconnection. An empty
initial route set is rejected to avoid a call that waits forever before the
caller has a connection on which to set routes. After startup, `SetRoutes` may
set an empty map, entering `waiting-routes` until routes are added again.

The library supports multiple profiles and sessions in one process. Same-profile
provisioning and deletion are serialized within a client. Closing a client
cancels its owned work and waits for connections to stop. Closing a connection
is idempotent, closes event delivery, and waits for its transport, certificate
refresh, and forwarding goroutines. Calls after close return an explicit error.

## Provisioning and HTTP API

Implement all HTTP endpoints, including remote tunnel inspection for diagnostics:

- `POST /api/tunnel` with `{}`; expect 201 and a tunnel/token.
- `GET /api/tunnel/:id` with bearer authentication; expect 200.
- `POST /api/tunnel/:id/certificate` with bearer authentication and a CSR;
  expect 202.
- `GET /api/tunnel/:id/certificate` with bearer authentication; expect 200.
- `DELETE /api/tunnel/:id` with bearer authentication; expect 204.

Limit HTTP response sizes, close response bodies, preserve upstream error tags,
and reject malformed success responses. Escape identifiers in paths. Do not
include bearer tokens or private keys in errors, logs, CLI output, or events.

Generate a P-256 private key and an ECDSA-SHA256 PKCS#10 CSR locally with
`CN=<hostname>` and SANs `<hostname>` and `*.<hostname>`. Persist the PKCS#8
private key, token, and pending CSR before requesting issuance. Poll every two
seconds, interruptibly, until ready or failed. A certificate-in-progress conflict
on resumed issuance is accepted. Other failures preserve pending state for retry.

Expose the upstream progress stages through an optional callback. Verify an
issued certificate matches the local key and both expected hostname forms before
saving or installing it. Never send the private key to the API.

`Create` refuses to overwrite a completed identity and resumes an existing pending
identity. `Ensure` reuses an existing identity, picks up an offline renewal, or
provisions as required. Recovering a failed issuance uses the same tunnel ID.
`Remove` can delete either a complete or pending remote tunnel; only remove local
credentials after confirmed deletion or remote not-found. Retain credentials
when deletion fails. Deletion stops this client's sessions for that profile.

## Storage and interoperability

Export a context-aware `Storage` interface providing `Profiles`, `Load`, `Save`,
`LoadPending`, `SavePending`, `Remove`, and `List`. Provide concurrency-safe
memory storage, a filesystem store rooted at an explicit directory, and XDG
defaults. This lets an embedding app own persistence without importing the CLI.

Use the upstream layout:

```text
$XDG_DATA_HOME/opentunnel/<profile>/
  tunnel.json        {id, hostname, certificateExpiry}
  pending.json       {id, hostname, csr}, while provisioning
  token
  private-key.pem    PKCS#8
  certificate.pem
  chain.pem
```

On systems without `XDG_DATA_HOME`, use `~/.local/share/opentunnel`, including
macOS, to interoperate with upstream. Directory permissions are 0700 and secret
files 0600 on Unix. Use temporary files and rename, writing metadata last so it
acts as the completion marker. Remove pending metadata after a successful save.
Distinguish missing identities from corrupt or incomplete ones. Reject profile
traversal and symlinked profile directories. Do not silently overwrite malformed
identities or create a replacement remote tunnel when storage cannot be read.

Memory storage returns independent copies. Profiles and list results are sorted.
Document that a memory-only identity cannot be recovered after process exit and
must be deleted explicitly when intended to be temporary. File compatibility is
required; simultaneous provisioning through different language clients is not
a supported cross-process transaction and must be documented.

## Security model and confidentiality limits

The intended TLS endpoints are the public visitor and the embedding Go process.
The relay and Worker carry encrypted TLS records; terminating the bridge's outer
WebSocket TLS does not decrypt the visitor's inner application TLS. The Go
process owns the certificate private key. Ordinary passive observation at the
relay does not disclose HTTP paths, queries, headers, cookies, bodies, or
application WebSocket contents.

This is not a protocol-level guarantee against an actively malicious operator
of the hosted service. The upstream service controls DNS and performs ACME
DNS-01 authorization for `*.opentunnel.xyz`. An operator with that authority
could issue another browser-trusted certificate for a tunnel hostname using its
own key and terminate future visitor connections, then proxy to the legitimate
client. This is a threat-model inference from certificate/DNS authority, not a
claim that the deployed service performs interception. Checking the certificate
returned to the Go client against its private key does not prevent a different
certificate being presented to visitors. Client-controlled, independently
verified key pinning or a separately authenticated application encryption layer
would be required to exclude this authority from the trust boundary; neither is
provided by ordinary browser HTTPS to a provider-owned hostname.

The service can observe source addresses, tunnel and route identities, SNI,
ClientHello metadata, timing, connection counts, and encrypted byte volumes.
The inspected upstream source logs routing metadata and emits byte/duration
analytics. This system does not hide traffic metadata or provide anonymity.

After TLS termination, forwarding to a plaintext `host:port` exposes application
bytes on that local network segment. Examples bind loopback; forwarding to a
different host extends the plaintext trust boundary. Endpoint processes, their
logs, and a compromised endpoint can also expose plaintext.

Documentation must distinguish normal relay blindness, metadata visibility,
endpoint trust, and active certificate-authority/domain-operator interception.
Require TLS 1.2 or later, prefer TLS 1.3, and use forward-secret authenticated
encryption suites. Do not disable upstream HTTPS certificate verification.
Tests must check that forwarded relay payloads are TLS ciphertext, that invalid
or mismatched certificates are rejected, and that credentials are absent from
diagnostic output. These tests establish the implemented boundaries, not an
independent security audit or verification of the production deployment.

## Bridge, TLS, and forwarding

Use `ws`/`wss` at `/api/tunnel/:id/connect`, negotiate subprotocol `opentunnel`,
and authenticate in the first JSON `attach` message. Advertise sorted route names,
a Go client version, and a default `max_conns` of 256. Require successful attach
within ten seconds.

Binary frames contain a big-endian uint32 connection ID followed by bytes.
Outbound payloads are at most 32 KiB. Implement attached, attach_error, open,
ping, pong, drain, end, and reset. Ignore unknown message types and fields;
ignore malformed controls without allocating channels. Bound incoming frame
sizes. Honor negotiated heartbeat/idle timing with sensible positive minima.

Route names are `@` or a lowercase DNS label up to 63 characters. Profile names
use the same label rule without `@`. Resolve SNI case-insensitively: the base
hostname selects `@`, a single label selects that route, and deeper/unrelated
names do not match. Targets are host/port values; include IPv4, DNS, and bracketed
IPv6 coverage, and reject schemes, paths, missing hosts, and invalid ports.

Represent each multiplexed connection as an internal `net.Conn` suitable for
`tls.Server`. Terminate TLS locally using the current certificate, then forward
decrypted bytes to the selected local TCP target. Do not advertise HTTP/2 when
forwarding to an ordinary HTTP/1.1 target. Preserve streaming bodies, application
WebSocket upgrades, and arbitrary application bytes after TLS termination.
Handshake and upstream dial failures produce a channel reset and leave the
bridge running. Enforce connection limits before allocating channel TLS state.
Handle duplicate IDs without leaking or replacing live channels silently.

Use one ordered bridge writer, bounded outbound buffering of approximately
1 MiB, and an 8 MiB per-channel inbound cap. Stop local reads when writes block;
reset a stalled inbound channel rather than blocking the bridge reader behind
it. Explicitly document the upstream limitation: there is no per-channel flow
control on the wire, so a slow shared bridge can delay other channels. Event
consumption must not block traffic or allow unbounded memory growth; expose a
bounded event channel and a dropped-event counter in status.

Preserve half-close semantics: inbound `end` yields EOF while leaving the other
direction usable; completion in one forwarding direction closes that direction
without prematurely aborting the response. Reset aborts both directions. Session
shutdown cancels all channels and joins their goroutines.

## Reconnection, route changes, and renewal

Fatal attach codes `bad_token` and `cert_not_ready` stop the connection and return
a typed error. Retry other attach errors, socket loss, heartbeat timeout, and
server drain with jittered exponential backoff from 250 ms to 30 seconds. Reset
backoff after successful attach; cancellation interrupts retries immediately.

Changing only route targets affects newly opened channels without reattaching or
retargeting existing ones. Adding/removing route names reattaches. Applying a
route update is synchronous; it does not promise the replacement session has
already attached. Status/events expose that transition.

Refresh certificates on connect and every 12 hours, or every minute within the
30-day renewal window. Install a validated renewed certificate for new TLS
connections without disrupting established ones; save it and emit a renewal
event. Transient polling failures keep the last valid certificate and are
observable. Stop refresh work on shutdown. Renewal reuses the existing key.

## otgo and embedding example

Create `cmd/otgo` as a thin consumer of public APIs. Provide `profiles`, `list`,
`get`, `pending`, `create`, `resume`, `ensure`, `remove`, and `connect` commands.
Provide `--api`, `--data-dir`, `--profile`, request/provision timeout controls,
and `--json` where useful. Display public metadata only.

`connect` accepts repeated `--route name=host:port`, prints public URLs, and emits
connection events. With an explicit `--interactive` option, accept stdin commands
for `status`, `routes name=host:port ...`, and `quit`, so route changes can be
tested on a running session. Ctrl-C shuts down cleanly. Default CLI persistence
is compatible filesystem storage. The CLI does not daemonize, install services,
or become a runtime dependency of the package.

Include an example Go web app that starts a loopback HTTP server, embeds the
package, connects a route, consumes events, and shuts down through context
cancellation. It must compile as a normal Go consumer. Document a live CLI
sequence using a dedicated profile, HTTP requests, a streaming request,
application WebSocket traffic, route changes, restart/reconnect, and cleanup.

## Verification and acceptance

1. Vendor the four shared upstream JSON vector files with provenance and the
   upstream MIT notice. Tests must validate framing, controls, names, and SNI.
2. Unit tests validate CSR signature/SAN/key properties, storage layout and
   permissions, corruption and traversal errors, HTTP auth/status/error handling,
   cancellation, and interrupted provisioning/resumption.
3. A local fake API/relay uses real WebSocket framing and real TLS handshakes,
   with a locally trusted test CA. Exercise root/named routes, concurrent clients
   and channels, large transfers, HTTP streaming, application WebSocket upgrades,
   upstream refusal, reset and half-close, bad TLS, unknown routes, channel limits,
   attach rejection, reconnect, heartbeat timeout, drain, route changes,
   certificate renewal, blocked readers, and cleanup.
4. Race-detector tests cover concurrent status, route updates, event consumption,
   identity refresh, and close. Time-sensitive tests use bounded deadlines and
   explicit synchronization instead of relying on arbitrary sleeps.
5. Fuzz frame/control/name parsers; verify inputs cannot panic or allocate without
   bounds. CLI tests exercise dispatch, flags, exit status, public JSON output,
   and interactive route updates against the local fixture.
6. Run `go test ./...`, `go test -race ./...`, `go vet ./...`, build `otgo` and the
   embedding example, and report actual evidence and remaining gaps.
7. Live testing with the public service follows once the CLI is ready. Record
   which public-service paths were actually checked; do not substitute local
   fixture results for live certificate/relay interoperability.

## Scope limits

No server implementation, daemon, system service installer, authentication layer
for tunneled apps, direct HTTP-handler integration, or tunnel-backed public
`net.Listener` is required for SDK parity. Applications can embed the client and
forward to their own loopback server. No production deployment, publishing,
GitHub push, or background live tunnel is part of this task.
