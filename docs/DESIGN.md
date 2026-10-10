# Package and protocol reference

Use package `opentunnel` from `github.com/darron/go-opentunnel` to manage tunnel
identities and forward visitor TLS to local services. Start with the
[embedding example](../README.md#embed-the-client); use this document for API,
wire, and persistence contracts.

The client uses Go's HTTP, P-256, X.509, TLS, and TCP implementations plus one
WebSocket dependency. Applications need no Node, Bun, Rust, or background process.
`otgo` is a consumer of the package.

## Compatibility baseline

Inspected upstream commit: `22156aa6ab209515186c3ca4f111901b7cedc284`.

- [Protocol specification](https://github.com/anomalyco/opentunnel/blob/22156aa6ab209515186c3ca4f111901b7cedc284/docs/protocol.md)
- [TypeScript SDK API](https://github.com/anomalyco/opentunnel/blob/22156aa6ab209515186c3ca4f111901b7cedc284/packages/client/src/promise/client.ts)
- [SDK types](https://github.com/anomalyco/opentunnel/blob/22156aa6ab209515186c3ca4f111901b7cedc284/packages/client/src/effect/types.ts)
- [Shared vectors](https://github.com/anomalyco/opentunnel/tree/22156aa6ab209515186c3ca4f111901b7cedc284/spec/vectors)

The JavaScript distribution is compiled from the TypeScript SDK. Rust is the
other native implementation. This package implements the client; it does not
implement the hosted relay or certificate authority.

## Public package and API

Go methods map directly to the upstream SDK operations.

### Construction and local inspection

| TypeScript operation | Go operation |
| --- | --- |
| `create(options)` | `NewClient(options) (*Client, error)` |
| `profile.list()` | `Client.Profiles(ctx)` |
| `tunnel.list()` | `Client.List(ctx)` |
| `tunnel.get(options)` | `Client.Get(ctx, profile)` |
| `tunnel.pending(options)` | `Client.Pending(ctx, profile)` |

### Lifecycle

| TypeScript operation | Go operation |
| --- | --- |
| `tunnel.create(options)` | `Client.Create(ctx, profile, provisionOptions)` |
| `tunnel.resume(options)` | `Client.Resume(ctx, profile, provisionOptions)` |
| `tunnel.ensure(options)` | `Client.Ensure(ctx, profile)` |
| `tunnel.remove(options)` | `Client.Remove(ctx, profile)` |
| `dispose()` | `Client.Close()` |

### Connections

| TypeScript operation | Go operation |
| --- | --- |
| `tunnel.connect(options)` | `Client.Connect(ctx, connectOptions)` |
| `connection.setRoutes(routes)` | `Connection.SetRoutes(routes)` |
| `connection.close()` | `Connection.Close()` |

### Connection state

| TypeScript operation | Go operation |
| --- | --- |
| `connection.tunnel` | `Connection.Identity()` |
| `connection.events` | `Connection.Events()` |
| `connection.status()` | `Connection.Status()` |
| `connection.closed` | `Connection.Done()` and `Connection.Err()` |

### Inputs and results

- Fallible operations return errors. Absent `Get`, `Pending`, and `Resume`
  results return `(nil, nil)`.
- An empty client profile option selects `default`. Storage validates explicit
  profile names.
- `ClientOptions` accepts an API base URL, storage, HTTP client, request timeout,
  and bounded transport settings. Defaults use `https://opentunnel.xyz` and XDG
  storage. Request, handshake, local dial, and write timeouts are finite.
  `TransportOptions.IdleTimeout` is optional and defaults to disabled.
- `Routes` maps names to `host:port`. Caller maps are copied; identities, routes,
  and status return snapshots. Events and typed errors support structured handling,
  including `errors.Is`/`errors.As`, API status/tag, and attach code.
- The package needs no logger, CLI output, signals, or process exit. HTTP-client
  customization also applies to WebSocket dialing where supported by the dependency.
- JSON omits zero `Event.Expiry`, `Status.ConnectedAt`, and
  `CertificateState.Expiry`. `Event.Delay` is a `time.Duration`; JSON encodes it
  as integer nanoseconds.

### Connection lifetime

`Connect` validates inputs, ensures an identity, and returns after the first
successful attachment with a valid certificate. The `ctx` argument bounds this
startup sequence only. Cancelling it after `Connect` returns does not stop the
connection.

Set `ConnectOptions.Lifetime` to make another context own the running tunnel.
When it is nil, stop the tunnel with `Connection.Close` or `Client.Close`.
Cancelling an explicit lifetime closes `Done` and records the cancellation in
`Err`.

Initial routes must be nonempty. Once connected, `SetRoutes` can clear them;
state becomes `waiting-routes` until routes are added.

A client supports multiple profiles and sessions. It may run multiple
connections for one profile when their route-name sets are disjoint. An overlap
at `Connect` or `SetRoutes` returns `ErrRouteInUse`; a rejected update leaves the
old route snapshot active. Same-profile provisioning and deletion are serialized
within that client. `Client.Close` cancels and joins its owned operations and
connections. `Connection.Close` is idempotent, returns with `Err() == nil` for a
normal requested close, and joins transport, refresh, and forwarding workers.
Events close on shutdown; `Done` closes after workers exit.

Lifecycle calls after client close return an error. Connection snapshots remain
readable. Low-level `Client.API()` calls retain their own context ownership.

## HTTP API

| Endpoint | Authentication | Success |
| --- | --- | --- |
| `POST /api/tunnel` with `{}` | None | 201, tunnel/token |
| `GET /api/tunnel/:id` | Bearer token | 200, tunnel state |
| `POST /api/tunnel/:id/certificate` with CSR | Bearer token | 202, issuance state |
| `GET /api/tunnel/:id/certificate` | Bearer token | 200, issuance state |
| `DELETE /api/tunnel/:id` | Bearer token | 204 |

The API escapes IDs, caps response bodies at 1 MiB, rejects malformed success
responses, and preserves recognized upstream error tags. Unknown tags become
`HttpError`; unknown attach-error codes render as `unknown`. This prevents a
hostile error field from reflecting credentials into logs. It closes response
bodies and keeps request deadlines active through consumption. Package-generated
API errors discard raw error response bodies; CLI identity output omits tokens
and private keys. `Client.API().Get` enables remote
inspection using a stored identity's ID and token.

Use HTTPS for remote API bases. Plain HTTP is accepted only for exact
`localhost` or a literal loopback IP such as `127.0.0.1` or `::1`; loopback-like
DNS names are rejected without resolution. The package clones a supplied
`http.Client`, requires every redirect to stay at the initial origin (scheme, hostname, effective
port), both before and after invoking the caller's redirect hook. A supplied
transport, cookie jar, or hook is trusted with credentials.

## Certificate provisioning

1. Create a tunnel, then generate a local P-256 key and ECDSA-SHA256 PKCS#10 CSR.
   Set `CN=<hostname>` and SANs `<hostname>` and `*.<hostname>`.
2. Persist the PKCS#8 key, token, and pending CSR **before** requesting issuance.
   The private key never goes to the API.
3. Inspect certificate state before submitting. Resume polls an already active
   issuance without rebinding. New or failed issuance submits at most once per
   retry interval, including ambiguous request failures. Poll every two seconds
   until ready, failed, or cancelled; release the profile lock between polls.
4. Validate the issued certificate's key, validity, exact hostname, and wildcard
   SAN before saving or installing it.

After a known create response, pending persistence has its own finite deadline,
even if startup was cancelled. Failed persistence or key generation triggers a
bounded remote deletion attempt. If persistence and deletion both fail,
`ProvisioningError.Pending` retains the known secret credentials for explicit
recovery. A lost create response can still leave an unknown remote allocation.

`ProvisionOptions.OnProgress` receives the upstream stages synchronously.
Callbacks must not reenter operations on the same profile.

| Operation | Recovery behavior |
| --- | --- |
| `Create` | Rejects an existing completed identity with `ErrExists`; resumes pending state |
| `Resume` | Continues pending issuance; absent pending state returns `(nil, nil)` |
| `Ensure` | Reuses an identity, resumes offline renewal, or provisions as needed; failed issuance retains the same tunnel ID and key |
| `Remove` | Deletes complete or pending remote identity; removes local credentials only after confirmed deletion or remote 404 |

Failed deletion retains credentials. Successful deletion stops and joins this
client's sessions for that profile. Renewal and deletion share the profile lock
so renewal cannot recreate a removed identity. Confirmed remote deletion uses a
bounded cleanup context even if the caller cancels.

`Connect` can attach an expired stored identity because the hosted protocol uses
attachment to trigger server-side renewal. It does not report startup success
until refresh installs a valid certificate. Visitor handshakes reject expired or
not-yet-valid certificates. A `failed` issuance state resubmits a CSR
with the existing tunnel ID and private key, at most once per hour per profile
within this client by default (`CertificateRetryInterval`). Foreground and
background paths share that cooldown. Each issuance poll releases the profile lock; stuck issuance cannot hold it
indefinitely and prevent removal. Foreground waiters recheck pending identity
ownership after reacquiring the lock and return `ErrProfileChanged` if the
profile was removed or replaced. A merely near-expiry certificate
does not cause a CSR submission: the inspected upstream protocol expects the
server to renew it.

## Storage

The context-aware `Storage` interface provides `Profiles`, `Load`, `Save`,
`LoadPending`, `SavePending`, `Remove`, and `List`. Implementations must support
concurrent calls and cancellation.

| Constructor | Persistence |
| --- | --- |
| `NewMemoryStorage()` | Process-local, independent copies |
| `NewFileStorage(root)` | Profiles immediately below the supplied root |
| `NewXDGStorage()` | `$XDG_DATA_HOME/opentunnel`, or `~/.local/share/opentunnel` when unset, including on macOS |

The upstream-compatible layout is:

```text
$XDG_DATA_HOME/opentunnel/<profile>/
  tunnel.json        {id, hostname, certificateExpiry}
  pending.json       {id, hostname, csr}, while provisioning
  token
  private-key.pem    PKCS#8
  certificate.pem
  chain.pem
```

Use the fallback root above when `XDG_DATA_HOME` is unset.

- Profile directories secured by a write use `0700`; credential files written
  by the file store use `0600`. Loading imported files does not validate or
  repair their modes, so audit existing storage before use.
- A newly created storage root is `0700`. A pre-existing Unix root is never
  chmod'd: read/traverse-only group or other access is allowed because profiles
  created or secured by a write are `0700`, while group/other write access is
  rejected. Windows does not enforce these Unix mode bits; the caller must apply
  suitable ACLs.
- Writes use private temporary files and atomic per-file replacement. Metadata
  is written last as the completion marker; a completed save removes pending metadata.
- Missing identities differ from corrupt or incomplete ones. Read failures do
  not silently overwrite credentials or create replacement remote tunnels.
- Profile traversal, symlinked profile directories, and symlinked credential
  files are rejected. Writes also reject a symlinked storage root. Profile and
  tunnel listings are sorted.
- `Remove` requires a regular `tunnel.json` or `pending.json` marker. It removes
  only the six known credential files and removes the profile directory only
  when empty. Unmarked label-shaped directories and unrelated contents inside a
  marked profile are preserved; unsafe markers fail before deletion.
- Provisioning across clients/processes requires caller coordination; the file
  format has no cross-process transaction. Memory identities cannot be recovered
  after exit: explicitly remove temporary remote tunnels before losing credentials.

Custom `Storage` implementations must preserve the same state transition:
`Save` successfully stores the completed identity, then clears pending state
for that profile. Do not use `json.Marshal` on an `Identity` as a persistence
format: JSON intentionally omits `Token` and `PrivateKey`. Persist every required
field explicitly, honor cancellation and concurrent calls, and return `(nil,
nil)` for missing loads.

File access remains path-based. The symlink checks reduce accidental traversal
but retain a same-user check-then-use race. Saves replace files individually, so
a process or machine crash can leave a mixed credential generation. These limits
require an `os.OpenRoot`-style conversion and a transactional format to remove.

## Bridge framing and controls

The bridge connects with `ws`/`wss` at `/api/tunnel/:id/connect` using subprotocol
`opentunnel`. Its first JSON `attach` message carries the token, sorted route
names, Go client version, and default `max_conns` of 256. Attachment must succeed
within ten seconds by default.

Binary frames contain a four-byte big-endian uint32 connection ID followed by
payload bytes. Incoming frames are capped at 1 MiB; outbound payloads at 32 KiB.
Control serialization retains required zero values such as `conn=0`, empty
`open.alpn`, and empty route arrays.

| Controls | Purpose |
| --- | --- |
| `attach`, `attached`, `attach_error` | Authenticate and establish or reject the session |
| `open` | Open a multiplexed visitor connection |
| `ping`, `pong` | Heartbeat |
| `drain` | End the session and reconnect |
| `end`, `reset` | Half-close or abort a channel |

Unknown message types/fields are ignored. Malformed controls do not allocate
channels. Future attach-error codes are accepted when at most 256 bytes and free
of ASCII control characters; unfamiliar codes become `unknown` in public
attachment errors. Negotiated durations must be positive and at most
24 hours. Heartbeat execution uses minima of one second for interval and five
seconds for idle timeout.

## Routes and TLS forwarding

| Input | Rule |
| --- | --- |
| Route name | `@` or a lowercase DNS label, at most 63 characters |
| Profile name | Same label rule, without `@` |
| Target | `host:port`; supports IPv4, DNS, and bracketed IPv6; ports 1–65535 |
| Invalid target | Schemes, paths, missing host, or invalid port |
| SNI | Case-insensitive; base hostname selects `@`, one label selects that route; deeper/unrelated names do not match |

Each channel exposes an internal `net.Conn` to `tls.Server`, which terminates
visitor TLS with the current certificate. Decrypted streams then go to the
selected TCP target. ALPN advertises HTTP/1.1 rather than HTTP/2 for ordinary
HTTP/1.1 targets. Streaming, application WebSocket upgrades, and arbitrary
post-TLS application bytes are preserved.

The relay-selected route does not authorize the channel by itself. During the
TLS handshake, the visitor's ClientHello SNI must map to that same route. A
missing SNI, a different route name, a deeper hostname, or an unrelated hostname
fails the handshake before the local target is dialed.

Handshake or upstream dial failure resets only that channel. Connection limits
are enforced before allocating channel TLS state. Duplicate IDs abort the
existing channel rather than silently replacing it.

A single writer uses a 32-message data queue of at most 32 KiB payloads,
approximately 1 MiB, and a separate 32-message cleanup-control queue. Cleanup
controls get priority; exhausting that queue closes the session rather than
dropping resets. Logical sends have channel cancellation and a finite timeout
that includes queue admission. Physical WebSocket writes use session cancellation
and the transport timeout, so canceling one channel does not close the shared
socket. Changes to a pending write deadline wake a joined per-call watcher.
Canceled queued sends are discarded.

Each channel has an 8 MiB inbound payload cap. Fragments coalesce into blocks of
at most 32 KiB, bounding allocation and slice metadata independently of frame
count. A partial head and spare tail can add up to 64 KiB of block capacity above
the payload cap, plus bounded slice headers. Overflow resets the channel without
blocking the bridge reader; blocked writes stop local reads. Events use a
bounded, lossy queue with a dropped-event counter.

Set `TransportOptions.IdleTimeout` to close a channel after that duration with no
application bytes in either direction. Zero disables it. Use a value longer than
valid quiet periods for streaming or long-lived protocols. Independently, a
large upload to a slow local target can fill `MaxInboundBytes` and be reset even
while the bridge and other channels remain healthy.

The protocol has no per-channel flow control: sustained outbound pressure can
delay unrelated channels. See [resource limits](IMPLEMENTATION.md#default-resource-limits)
for aggregate memory costs and configurable limits.

Inbound `end` yields EOF while preserving the other direction. Forwarding
completion closes that direction without prematurely aborting its response.
`reset` aborts both directions. Session shutdown cancels channels and joins their
workers, including blocked upstream sockets.

## Reconnection, route updates, and renewal

| Trigger | Behavior |
| --- | --- |
| `bad_token` / `cert_not_ready` attach code | Stops the connection with a typed error |
| Other attach errors, socket loss, heartbeat timeout, drain | Retries with jittered exponential backoff, 250 ms to 30 s; an attached session lasting at least `BackoffMax` resets backoff; cancellation interrupts it |
| Target-only route change | New channels use the new target; existing channels retain theirs |
| Added/removed route name | Reattaches and closes the previous session's channels; `SetRoutes` returns before replacement attachment finishes |
| Certificate refresh | Runs on connect, then every 12 hours, every minute within the 30-day renewal window, or at the certificate poll interval after expiry |

Renewal reuses the existing key, validates and saves the new certificate, and
emits an event. New TLS connections use it; established connections continue.
Transient refresh failures remain observable and retain the last valid
certificate. Shutdown stops refresh work.

The client emits `certificate-expiring`, `certificate-expired`,
`certificate-recovery-started`, `certificate-refresh-failed`, and
`certificate-renewed` events as applicable.
An expired certificate cannot complete a visitor handshake. A `failed` remote
state rebinds a CSR with the same key; ordinary near-expiry polling waits for
server renewal and does not submit a new CSR. Pending issuance uses
`CertificatePollInterval`; failed-issuance retries share a per-profile cooldown
within this client. Installing a valid replacement clears that cooldown. The
cooldown is in memory, so restarting the client resets it.

## CLI, examples, and verification

`otgo` provides `profiles`, `list`, `get`, `pending`, `create`, `resume`, `ensure`,
`remove`, `inspect`, `connect`, and `listen`. It displays public metadata and
accepts common API/storage/profile/JSON/timeout flags. `connect` supports
interactive `status`, `routes`, and `quit`; `listen` serves an HTTP diagnostic
handler directly over tunnel TLS. It does not daemonize or install services.

The webapp example embeds `Client.Listen` by default, consumes events, and shuts
down through context cancellation. `--forward` uses `Client.Connect` with a
loopback server; `--local-only` starts just that local test target.
See [TESTING.md](TESTING.md) for runnable commands,
[VERIFICATION.md](VERIFICATION.md) for local evidence, and
[LIVE_TESTING.md](LIVE_TESTING.md) for hosted interoperability results and gaps.
The [security model](SECURITY.md) distinguishes relay encryption, metadata,
endpoint plaintext, and active domain/certificate operator impersonation. The
[hardening guide](HARDENING.md) collects the current review changes and remaining
limits.

## Scope

The package provides a tunnel-backed TLS `net.Listener` for direct HTTP serving
and forwards to an application's local TCP server. It supplies no hosted relay,
daemon, installer, or application authentication layer.

## Direct HTTP embedding

`Client.Listen` adds a TLS `net.Listener` alongside TCP forwarding. Both modes
share the connection/session lifecycle, certificate refresh, route claims, and
admission limits. After the existing SNI-validated handshake, listener channels
enter a bounded accept queue and remain session-owned until application close,
reset, idle timeout, or session shutdown. The exact `*tls.Conn` reaches HTTP
handlers. No loopback socket or synthetic HTTPS marker is required. See
[LISTENER.md](LISTENER.md) for the API and shutdown/peer contracts.

## otgo authentication boundary

The CLI's private `internal/authproxy` subsystem adds browser login and machine
tokens around a fixed HTTP backend. It uses the existing listener API; the public
SDK remains an authentication-neutral transport. Each named CLI profile binds
its auth configuration to one tunnel ID, hostname, and control API origin.
Proxy startup cannot provision a missing identity. OS file locks prevent two
protected proxies for the same profile, while token commands use separate locks
and remain available during service. Sessions live in memory; token hashes and
secret configuration use protected, bounded, atomically replaced XDG files.
