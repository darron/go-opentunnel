# go-opentunnel review: security, ergonomics, API

Reviewed at `50523ec` (2026-10-09): all non-test Go sources, `cmd/otgo`,
`examples/webapp`, and the docs. `go vet` and `go test ./...` pass.

Findings marked **[verified]** were reproduced with a throwaway test against the
repo's own relay fixture (the test was deleted afterwards). Everything else is
from reading the code and has not been executed.

## Summary

The package is in good shape for a 0.1: lifecycle ownership is careful, limits
are bounded, storage writes are atomic and symlink-aware, and the docs are
honest about the trust boundary. Three things are worth fixing before anyone
depends on it:

1. **The relay picks the route, not the visitor's TLS handshake.** A relay can
   deliver a visitor who verified `demo.host` to the `admin` route's backend.
   This contradicts the "relay sees only ciphertext" model. [verified]
2. **`Connect`'s context is both the connect deadline and the connection
   lifetime.** There is no clean way to say "give up after 30 s, otherwise run
   until closed", and the idiomatic `WithTimeout` + `defer cancel()` kills the
   tunnel.
3. **A long-running connection does not recover from a failed or expired
   certificate.** Only a restart (via `Ensure`) re-requests issuance, and an
   already-expired stored certificate may make `Connect` fail permanently.

The rest is hardening and polish. Suggested order is in the last section.

---

## Security

### S1. Route is chosen from the relay's `open.sni`, not the ClientHello — High [verified]

`session.open` (`session.go:250`) selects the target from the relay-supplied
`m.SNI`. `channelTLS` (`session.go:301`) then serves the one wildcard
certificate for whatever SNI the visitor actually sent. Nothing compares the two.

Reproduction: routes `@` → backend A and `admin` → backend B. The fixture relay
sent `open` with `sni: "admin.demo.test"` while the visitor's TLS client used
`ServerName: "demo.test"`. The handshake succeeded, the visitor verified the
certificate for `demo.test`, and received backend B's bytes.

Impact: a malicious or compromised relay can cross-wire routes without breaking
TLS. A visitor's cookies and request bodies for one hostname land on another
route's backend, or a visitor is served by a backend they did not ask for.
`docs/SECURITY.md` currently says a normally operating relay sees only
ciphertext and metadata; this gives it an active capability short of
certificate mis-issuance.

Fix: make the handshake authoritative. In `GetConfigForClient` (or
`GetCertificate`), compute `RouteForSNI(hello.ServerName, hostname)` and reject
the handshake unless it equals the route chosen at `open`. Better still, dial
the target only after the handshake and choose it from `hello.ServerName`,
treating `open.sni` as a hint for early rejection only. Also decide what to do
with a ClientHello that has no SNI (today it is served).

### S2. Plaintext `http://` API base is accepted silently — Medium [verified]

`NewAPI` (`api.go:39`) accepts `http`. The bearer token then travels in
cleartext on every API call, and the bridge uses `ws://` with the token in the
`attach` message. `docs/SECURITY.md` says "The client has no flag to disable"
HTTPS verification, which is true but misleading: `API: "http://…"` is
effectively that flag.

Fix: reject `http` unless the host is loopback, or require an explicit
`AllowInsecureAPI` option. Tests can keep using `httptest` either way.

### S3. Credentials leak through `fmt`/`slog` — Medium [verified]

`Identity` and `PendingIdentity` hide `Token` and `PrivateKey` from JSON only.
`fmt.Sprintf("%+v", identity)` prints both, and so does `slog.Any("id", identity)`
or `log.Printf("%v", conn.Identity())`. SECURITY.md asks users to keep them out
of "struct formatting", but the type does not help.

Fix: implement `String()`, `GoString()` and `slog.LogValuer` on both types (or
`Format`), or move the secrets behind a small `Secret` string type that redacts
itself. A redacting type also fixes the next point.

Related ergonomics trap: because of `json:"-"`, anyone writing a custom
`Storage` who does `json.Marshal(identity)` silently persists an identity
without its token or key. Document it on `Storage`, or provide an explicit
`MarshalSecret`-style helper.

### S4. No idle or total limit on established channels — Medium

A channel has a handshake timeout and a dial timeout, then nothing
(`channel.go:53-88`). Up to `MaxConnections` (256, global across all routes and
visitors) can be held open indefinitely by idle visitors, after which every new
`open` is reset with `too_many_connections`. A single client can also stall 256
handshakes for 10 s each, repeatedly.

The hosted relay may enforce its own limits, but the package should not rely on
that. Add an optional `IdleTimeout` (reset on bytes in either direction), and
consider a per-route cap so one route cannot starve the others.

### S5. Long-lived connections never recover from certificate failure — Medium

- `refreshOnce` (`connection.go:321`) returns `nil` when the remote state is
  not `ready`. A `failed` renewal is never re-requested while connected and
  emits no event. `ensure` handles `failed` by re-binding a CSR, but only at
  the next `Connect`/`Ensure`.
- Nothing re-checks validity at runtime. Once the certificate passes
  `NotAfter`, the connection keeps serving it and visitors get browser errors
  while `Status()` says `connected`.
- At startup, if the stored certificate has expired and the API still reports
  the same certificate as `ready`, `ensure` fails at `parseCertificate`
  (`client.go:340`) with "certificate outside validity period". The only way
  out is `Remove`, which gives up the hostname.

I could not tell from this repo whether the hosted service renews on its own or
expects a new CSR; whichever it is, the client needs a path. Suggested: in
`refresh`, treat `failed` like `ensure` does; emit `certificate-expiring` /
`certificate-expired` events; and in `ensure`, re-bind with the existing key
when the stored certificate is expired or inside the renewal window.

### S6. File storage: symlink checks are check-then-use, and the root is chmod'd — Low

- `readRegular`, `write`, and `profileDir` do `Lstat` and then open by path.
  Inside a `0700` directory this needs a same-user attacker, so the exposure is
  small, but with `go 1.25` in `go.mod` you can use `os.OpenRoot` and do every
  operation relative to the root, which removes the race and most of the manual
  checks.
- `ensureProfileDir` (`storage.go:470`) unconditionally `chmod 0700`s the
  storage root. `NewFileStorage(root)` takes any caller directory, so
  `otgo create --data-dir .` or pointing it at a shared directory changes that
  directory's permissions as a side effect. Either only chmod directories the
  package created, or refuse a pre-existing root with wider permissions and say
  so.
- `Profiles` treats every label-shaped subdirectory of the root as a profile,
  and `fileStorage.Remove` does `RemoveAll` on it. `Client.Remove` guards this
  by loading an identity first, but the `Storage` method itself will delete an
  unrelated directory. Require `tunnel.json` or `pending.json` before removing.
- `Save` replaces five files one at a time. A crash mid-renewal can leave a new
  `certificate.pem` with an old `chain.pem`. Documented as per-file atomicity;
  writing a single bundle file, or a new directory plus rename, would close it.
- Unix permissions are a no-op on Windows; SECURITY.md should say so.

### S7. Smaller items — Low

- **Errors discard their cause.** `session.run` replaces dial, write and read
  errors with fixed strings ("bridge handshake failed"). None of those errors
  carry the token (it is in the `attach` body, not the URL), so wrapping the
  cause is safe and makes DNS, TLS and HTTP-status failures distinguishable.
  Same for `certificate issuance failed`, which drops `State.Reason`.
- **Two connections on one profile fight.** Nothing stops a second `Connect`
  (same client or another process) for the same tunnel. If the relay replaces
  the older session, both sides reconnect in a loop, and because `attempt`
  resets after each successful attach (`connection.go:221`) the loop runs at
  the 125–250 ms floor forever. Reject duplicates within a client, and only
  reset backoff after a session has survived for some minimum time.
- **`open.alpn` is ignored and ALPN is fixed to `http/1.1`.** Go's TLS server
  rejects a client whose ALPN list has no overlap, so h2-only clients (gRPC)
  and non-HTTP protocols that set ALPN fail the handshake. DESIGN.md's
  "arbitrary post-TLS application bytes are preserved" holds only for clients
  that send no ALPN or include `http/1.1`. Make `NextProtos` a per-route option.
- **Targets are unrestricted.** Intended, and SECURITY.md recommends loopback.
  A `LoopbackOnly` option (default on would be a reasonable 0.x choice) would
  turn the recommendation into a guard; hostnames are re-resolved per dial.
- **`terminalText`** filters C0 and DEL but not C1 controls (U+0080–U+009F).
  Harmless on most UTF-8 terminals; trivial to include.
- **User-Agent differs** between HTTP (`opentunnel/0.1.0`) and the bridge
  (`go-opentunnel/0.1.0`).

### What is done well

Locally generated keys that never leave the process; key/SAN/validity checks
before saving a certificate; bounded response bodies, frames, queues and
buffers; pending state persisted before issuance; deletion that finishes local
cleanup after confirmed remote deletion; redirect handling left to `net/http`
(which strips `Authorization` cross-host); no verification-disabling switch;
fuzz targets for the parsers.

---

## API

### A1. `Connect(ctx)` conflates connect deadline and lifetime — High

`connection.go:67` derives the connection's whole lifetime from the `Connect`
context. This is documented, but it cuts against the convention users know from
`net.Dialer.DialContext`, `database/sql` and gRPC, where the context bounds the
call only.

Consequences:

- The reflexive `ctx, cancel := context.WithTimeout(ctx, 30*time.Second); defer cancel()`
  tears the tunnel down when the calling function returns or after 30 s.
- `Connect` blocks until the first attach and retries forever. With a
  background context it can hang indefinitely; with a timeout the tunnel dies
  at the timeout. There is no supported way to bound only the first attach.

Recommendation: the context bounds `Connect` only; lifetime ends through
`Connection.Close` or `Client.Close`. If context-scoped lifetime is wanted too,
make it explicit (`ConnectOptions.Lifetime context.Context`), or split the call
into `Start` (returns immediately) plus `WaitReady(ctx)`.

### A2. No `net.Listener` — High value

DESIGN.md lists this as out of scope, but for an *embedding* library it is the
most natural Go surface:

```go
ln, err := client.Listen(ctx, opentunnel.ListenOptions{Profile: "demo"})
http.Serve(ln, mux)
```

`bridgeConn` already implements `net.Conn` and `tls.Server` already wraps it,
so most of the work exists. It removes the loopback hop and the plaintext
segment, needs no free port, and gives handlers the real visitor address via
`RemoteAddr()`. Today the target sees every request from `127.0.0.1`; the peer
is only in the lossy `connection-opened` event, with no PROXY protocol or
forwarded header to carry it. Keeping `host:port` routes alongside is fine.

### A3. Stringly-typed states, events and codes — Medium

`ProvisionStage` is a typed constant set, but `Event.Type`, `Status.State`,
`AttachError.Code`, `CertificateState.Type` and `TunnelInfo.State` are bare
strings with no exported constants. Callers must copy literals such as
`"reconnecting"`, `"waiting-routes"`, `"certificate-refresh-failed"` or
`"bad_token"` out of the source. Add typed constants (`EventType`,
`ConnState`, …) and a `RootRoute = "@"` constant.

`Event` is one struct with eleven optional fields; which are set for which type
is undocumented. At minimum document it per type.

### A4. `(nil, nil)` for "not found" — Medium

`Get`, `Pending`, `Resume` and the `Storage` loaders return `(nil, nil)` when
nothing exists (the code needs `//nolint:nilnil` to do it). Callers who check
only `err` dereference nil. `Resume` is the sharpest case: "nothing to resume"
and "resumed" look alike until the nil pointer is used. An `ErrNotFound`
sentinel is more conventional and works with `errors.Is`.

### A5. Errors are hard to act on — Medium

- `ValidateRoutes` returns bare `ErrInvalid` with no indication of which route
  or why; `validateCertificateInfo` likewise.
- `APIError.Message` is always `"request rejected"`, so the field carries
  nothing. Drop it or populate it.
- "certificate issuance failed", "unknown certificate state", "server
  draining" and "bridge disconnected" are inline `errors.New` values that
  cannot be matched. Export sentinels or types for the ones callers would
  branch on.
- `Status.LastError` and `Event.Error` are strings, so `errors.Is/As` stops at
  the event boundary.
- After a normal `Close`, `Connection.Err()` returns `context.Canceled`. The
  README example therefore returns `context.Canceled` on clean shutdown, and
  both binaries special-case it. Return `nil` (or `ErrClosed`) for a
  caller-requested close.

### A6. JSON output has zero-time noise — Low [verified]

`omitempty` does nothing for `time.Time`. Every event serialises as
`{"type":"connecting","expiry":"0001-01-01T00:00:00Z"}` and `Status` always
includes a zero `connectedAt`. Use `omitzero` (Go 1.24+). `Event.Delay` encodes
as integer nanoseconds, which is worth documenting or changing to milliseconds.

### A7. Naming and consistency — Low

- `ClientOptions.API` is a URL string while `Client.API()` returns `*API`.
  `BaseURL` for the former reads better.
- Profile is passed three ways: positional in `Create/Resume/Ensure/Remove/Get`,
  a struct field in `ConnectOptions`, and `""` silently means `"default"`.
- `Create` and `Resume` take `ProvisionOptions`; `Ensure` and `Connect` do not,
  so the two calls most apps use have no progress reporting during a first-run
  issuance that can take a while.
- `TransportOptions`: `CertificateDueInterval` is unclear (poll interval inside
  the renewal window); the 30-day window itself is hard-coded; zero means
  default so nothing can be disabled.
- `NewFileStorage` and `NewMemoryStorage` return the `Storage` interface rather
  than concrete types, which blocks adding methods later without widening the
  interface.
- `Storage` has seven methods, and `Save` is expected to clear pending state as
  a side effect. That contract is only in the implementations; put it in the
  interface doc.
- `Version` is a hand-maintained constant that will drift from tags.

### A8. `Connect` needs the API to be up even with a valid local identity — Low

`ensure` always calls `api.Certificate` (`client.go:314`), so a brief API outage
at startup fails `Connect` outright, while the same outage one second after
attach is retried forever. With a valid stored certificate, attach first and
let the refresh loop reconcile. This would also remove the duplicate
certificate fetch that `refresh` makes immediately after `ensure`.

---

## Ergonomics

### E1. Documentation on exported identifiers

Most exported types, functions, fields and constants have no doc comment
(`Routes`, `Event`, `Status`, `ConnectOptions`, `API` and its methods,
`NewClient`, `Connect`, the error sentinels, every `TransportOptions` field and
its default). pkg.go.dev will be nearly blank and the defaults live only in
`transportDefaults`. The contracts are well written in `docs/DESIGN.md`; they
need to be on the symbols. Add `Example` functions so the README snippet is
compiled.

### E2. `otgo`

- **A typo in interactive mode kills the tunnel.** Any `interactiveCommand`
  error is returned from `connect` (`commands.go:354-358`), so `stauts` or a
  malformed `routes` line exits the process. Print the error and keep going.
- **Plain-text events drop most fields.** `formatEvent` prints only type, route
  and reason. `certificate-refresh-failed` and `stopped` show no error;
  `reconnecting` shows no delay or attempt; `connection-opened` shows no peer.
- `remove` permanently releases the hostname with no confirmation. Consider
  requiring `--yes` when stdin is a terminal.
- `get` and `pending` print "not found" and exit 0, which is awkward in scripts.
- Progress lines and the result both go to stdout for `create`/`resume`/`ensure`;
  progress belongs on stderr.

### E3. Inbound overflow resets the channel instead of applying backpressure

When a target reads more slowly than a visitor uploads, the 8 MiB buffer fills
and the channel is reset (`session.go:143`). The docs explain that the protocol
has no flow control, so this is a known limit rather than a bug, but users will
meet it as "large uploads to a slow handler fail". Say so plainly in the README
next to the traffic note, and surface a distinct `connection-closed` error for
it so it can be diagnosed.

### E4. Project hygiene

- `go 1.25.0` in `go.mod` is stricter than the code needs (it uses 1.22-era
  features; `os.OpenRoot` and `omitzero` would need 1.24). Pick the lowest
  version you intend to support.
- No CI configuration is tracked; `make check` and `make race` only run locally.
- The source is gofmt-clean but very dense: multi-statement lines, long
  one-line conditions (`protocol.go:212`, `storage.go:255`), and `e`/`err`,
  `x`/`c`/`s` naming that changes between files. Since this is security-relevant
  code that others will audit, it is worth loosening.

---

## Suggested order

1. S1: bind route selection to the ClientHello SNI, with a regression test.
2. A1: decide the `Connect` context contract now; it is the hardest thing to
   change after release.
3. S5: runtime handling for failed and expired certificates.
4. S2, S3: reject non-loopback `http`, redact credentials in formatting.
5. A3, A4, A5: typed constants, `ErrNotFound`, actionable errors. All are
   breaking changes, so do them before tagging.
6. S4, E2, A6, E1: idle timeout, CLI fixes, `omitzero`, doc comments.
7. A2: `net.Listener`, as the headline feature for a later minor.
