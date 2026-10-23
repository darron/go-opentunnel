# Upstream compatibility

Reviewed OpenTunnel v0.5.5 and v0.6.0 against our v0.5.4 baseline on 2026-10-22.
Current source pin:
[`c23b162409425a800245245b445a4230f6346429`](https://github.com/anomalyco/opentunnel/tree/c23b162409425a800245245b445a4230f6346429).
See the [upstream comparison](https://github.com/anomalyco/opentunnel/compare/v0.5.4...v0.6.0).

## Adopted in v0.16.0

| Upstream change | Go client behavior |
| --- | --- |
| Opt-in fatal route conflicts | `OnRouteConflict: RouteConflictFail` on Connect/Listen stops with a typed `AttachError` on startup or reconnect. The default still retries. |
| Startup events | `OnEvent` observes every lifecycle event, including startup. Calls are synchronous and serialized; callbacks receive their own route slice. The existing bounded event channel remains available. |
| Route-conflict events | `route-conflict` includes all attempted names, sorted; the relay does not identify the conflicting name. |
| Route helpers and URL snapshots | Export `RootRoute`, `RouteLabelPattern`, `IsValidRouteName` and `PublicURL`; Connection/Listener `URLs()` follows configured route changes. |
| Ensure progress | Add `EnsureWithOptions` and `checking-certificate`. `otgo ensure` reports progress; `--json` remains machine-readable. |
| Latest codec pin | Test the exact v0.6.0 Reader/Writer. Its source SHA-256 is unchanged from v0.5.4. |

Go already cancels startup attachment and provisioning and joins owned workers.
Unlike the TypeScript AbortSignal, Go's startup context stops owning a connection
after successful return; the optional `Lifetime` context controls it afterward.
That documented contract is preserved and covered by cancellation tests.

## Already covered or service-only

Upstream v0.5.5 distrusts compromised eMudhra intermediates. Our release binaries
already use Go 1.27.3, whose `crypto/x509` verifier rejects certificate chains
containing the eight affected public keys. CI and release packaging retain the
exact compiler pin and version checks. Embedded applications must also rebuild
with a patched compiler; updating a module cannot replace their standard library.

The Rust root-bundle/dependency checks do not apply directly: Go uses its verifier
and platform trust roots, with optional caller-supplied CA additions. We do not
copy a Rust source/binary grep as proof of Go trust-store behavior. A custom HTTP
client remains a trusted caller hook; see [custom CAs](CUSTOM_CA.md) and the
[security model](SECURITY.md#build-toolchain).

Mesh token migration, worker database cleanup/admin export, and Fly rollout
changes belong to the upstream service. There is no matching client component.
This update changes no wire format, persistent profile format, or visitor auth.

## Adopted in v0.15.0

| Upstream change | Go client behavior |
| --- | --- |
| Bridge reads must not wait on the send queue | Required pongs and resets enqueue without waiting. Both they and heartbeats precede queued application data; teardown keeps its own reserve. A full control queue closes/reconnects the session instead of allocating an unbounded queue. |
| Stalled local connections must not hold the bridge reader | Already enforced by nonblocking per-channel and aggregate inbound byte budgets. No five-second wait is needed; exceeding a budget resets that channel. |
| Explicit bridge message limits | Accept at most 64 KiB before attachment, then 32 KiB plus the channel ID. Outbound data was already split into payloads of at most 32 KiB. |
| Route/admission limits | Reject more than 128 routes per bridge before provisioning or changing configuration. Retain `too_many_routes` as a retryable attach diagnostic and recognize `RateLimitedError`. |
| Latest server WebSocket codec | Build the exact v0.5.4 Reader/Writer in the optional Rust test adapter, pinned by commit and SHA-256. |

The control-reply queue allows 8,192 pending messages for burst tolerance, alongside
the existing 32-message teardown reserve and 32-message data queue. This keeps
memory finite; sustained overload can reconnect and close active visitor streams.
Control priority cannot interrupt a physical write already in progress, which
remains bounded by the configured write timeout.

The hosted service also limits total routes per tunnel, concurrent connections,
tunnel creation and new CSR bindings. Limits shared with other processes are
enforced by the service. The existing client retry policy handles 429 and 503,
honors bounded `Retry-After` delays, and retains safe status/tag diagnostics.
It does not copy arbitrary server messages into logs.

## Existing protections and server-only work

- Owner-only storage, safe path handling, protected auth files and TLS verification
  were already enforced. otgo does not use the upstream daemon's control socket,
  service log or launchd/systemd unit, so those fixes have no matching component.
- Rustls dependency changes do not apply to Go. Release binaries and CI use the
  Go 1.27.3 security toolchain; see the [security model](SECURITY.md#build-toolchain).
- GitHub assets/checksums, pinned workflow actions, restricted publication jobs
  and binary Homebrew installation were already present.
- Database startup, server byte budgets, ACME/DNS cleanup, CA cooldown, certificate
  name/import checks, mesh authentication and server metrics listeners belong to
  the upstream service. This client does not operate those components.

## Evidence and limits

New regressions were first run against the prior behavior. They exposed blocked
reader-control admission, data overtaking pongs, acceptance of oversized bridge
messages, route-limit provisioning and loss of the new error tags. The fixes are
covered by real WebSocket/HTTP fixtures, route-update checks, existing control
burst tests and race testing. Commands are in [TESTING.md](TESTING.md#upstream-limits-and-bridge-backpressure);
dated results are in [VERIFICATION.md](VERIFICATION.md).

The Rust adapter tests the actual upstream codec, not the complete hosted service,
database or CA. Local fixtures do not establish which upstream revision is deployed
on the hosted service. Existing profile formats, authentication and identity
assertions are unchanged.
