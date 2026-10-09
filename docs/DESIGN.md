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
- `Routes` maps names to `host:port`. Caller maps are copied; identities, routes,
  and status return snapshots. Events and typed errors support structured handling,
  including `errors.Is`/`errors.As`, API status/tag, and attach code.
- The package needs no logger, CLI output, signals, or process exit. HTTP-client
  customization also applies to WebSocket dialing where supported by the dependency.

### Connection lifetime

`Connect` validates inputs before provisioning, ensures an identity, and returns
after the first successful attachment. Its context controls the entire lifetime,
including provisioning and reconnects.

Initial routes must be nonempty. Once connected, `SetRoutes` can clear them;
state becomes `waiting-routes` until routes are added.

A client supports multiple profiles and sessions. Same-profile provisioning and
deletion are serialized within that client. `Client.Close` cancels and joins its
owned operations and connections. `Connection.Close` is idempotent and waits for
transport, certificate refresh, and forwarding workers before completion.
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
responses, and preserves upstream error tags. It closes response bodies and keeps
request deadlines active through consumption. Errors and CLI output omit tokens,
private keys, and raw error response bodies. `Client.API().Get` enables remote
inspection using a stored identity's ID and token.

## Certificate provisioning

1. Create a tunnel, then generate a local P-256 key and ECDSA-SHA256 PKCS#10 CSR.
   Set `CN=<hostname>` and SANs `<hostname>` and `*.<hostname>`.
2. Persist the PKCS#8 key, token, and pending CSR **before** requesting issuance.
   The private key never goes to the API.
3. Poll every two seconds until ready, failed, or cancelled. Resumed issuance
   accepts a certificate-in-progress conflict; other failures retain pending state.
4. Validate the issued certificate's key, validity, exact hostname, and wildcard
   SAN before saving or installing it.

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

- Unix directories use `0700`; files use `0600`.
- Writes use private temporary files and atomic per-file replacement. Metadata
  is written last as the completion marker; a completed save removes pending metadata.
- Missing identities differ from corrupt or incomplete ones. Read failures do
  not silently overwrite credentials or create replacement remote tunnels.
- Profile traversal, symlinked profile directories, and symlinked credential
  files are rejected. Writes also reject a symlinked storage root. Profile and
  tunnel listings are sorted.
- Provisioning across clients/processes requires caller coordination; the file
  format has no cross-process transaction. Memory identities cannot be recovered
  after exit: explicitly remove temporary remote tunnels before losing credentials.

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
of ASCII control characters. Negotiated durations must be positive and at most
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

Handshake or upstream dial failure resets only that channel. Connection limits
are enforced before allocating channel TLS state. Duplicate IDs abort the
existing channel rather than silently replacing it.

A single ordered writer uses a 32-message queue of at most 32 KiB payloads,
approximately 1 MiB. Each channel has an 8 MiB inbound cap. Overflow resets the
channel without blocking the bridge reader; blocked writes stop local reads.
Events use a bounded, lossy queue with a dropped-event counter.

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
| Other attach errors, socket loss, heartbeat timeout, drain | Retries with jittered exponential backoff, 250 ms to 30 s; successful attachment resets backoff; cancellation interrupts it |
| Target-only route change | New channels use the new target; existing channels retain theirs |
| Added/removed route name | Reattaches and closes the previous session's channels; `SetRoutes` returns before replacement attachment finishes |
| Certificate refresh | Runs on connect, then every 12 hours, or every minute within the 30-day renewal window |

Renewal reuses the existing key, validates and saves the new certificate, and
emits an event. New TLS connections use it; established connections continue.
Transient refresh failures remain observable and retain the last valid
certificate. Shutdown stops refresh work.

## CLI, examples, and verification

`otgo` provides `profiles`, `list`, `get`, `pending`, `create`, `resume`, `ensure`,
`remove`, `inspect`, and `connect`. It displays public metadata, accepts common
API/storage/profile/JSON/timeout flags, and supports interactive `status`,
`routes`, and `quit`. It does not daemonize or install services.

The webapp example runs a loopback server, embeds `Client.Connect`, consumes
events, and shuts down through context cancellation. `--local-only` starts just
the test target. See [TESTING.md](TESTING.md) for runnable commands,
[VERIFICATION.md](VERIFICATION.md) for local evidence, and
[LIVE_TESTING.md](LIVE_TESTING.md) for hosted interoperability results and gaps.
The [security model](SECURITY.md) distinguishes relay encryption, metadata,
endpoint plaintext, and active domain/certificate operator impersonation.

## Scope

The package forwards to an application's local TCP server. It supplies no
hosted relay, daemon, installer, app authentication layer, direct HTTP-handler
adapter, or tunnel-backed public `net.Listener`.
