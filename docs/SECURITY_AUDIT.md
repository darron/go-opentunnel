# v0.7.0 security and test audit — 2026-10-11

**Upgrade step:** reset and reissue existing machine tokens using the same
profile/storage flags. [Migration commands](AUTH_PROXY.md#machine-clients-and-mcp).
Browser login, saved tunnel identity and backend configuration remain available.

Scope: the Go SDK, `otgo` authentication proxy, transport/lifecycle code, tests
and CI for v0.7.0, based on main commit `a574449`. The goal was reproducible
hardening while retaining the hosted OpenTunnel API and wire protocol. No runtime
dependency was added.

Separate LLM passes examined authentication, transport and test quality. Claude
and Amp/Oracle reviewed the source and exercised isolated regressions/mutations.
Findings were checked against code and executable evidence before acceptance.
Raw reviewer transcripts and temporary credentials stay outside the repository.

## Accepted findings

| Finding and prerequisite | Change | Regression evidence |
| --- | --- | --- |
| Two auth configurations sharing an explicit token file accepted each other's machine tokens | Version-2 registries bind tokens to tunnel ID, hostname, API origin and backend; mismatches fail closed | Correct configuration succeeds; another configuration sharing the file gets 401 with zero backend requests; every binding component is checked |
| Existing unbound tokens had no safe automatic migration | Reject version-1 registries without modifying them; add explicit `auth token reset` | Legacy authentication/create/list/revoke are denied; bytes remain unchanged; reset retains auth config and revokes tokens |
| Default channel limits permitted up to 2 GiB of retained inbound payload per session | Add a configurable 64 MiB aggregate cap, retaining the 8 MiB per-channel cap | Partial reads and repeated abort release exactly once; concurrent reservations stay bounded; actual relay overflow resets one channel and a healthy visitor still works |
| Relay metadata could echo a known tunnel credential or control text into diagnostics | Bound/sanitize session IDs, peer strings and connected-event routes | Real fixture attachment checks `Status`, `Event` and listener `RemoteAddr`; ordinary values are preserved; route list counts/bytes are bounded |
| TLS handshake errors echoed visitor-controlled ALPN into close events | Use fixed handshake diagnostics and trusted sentinel classifications | Crafted ALPN is absent from the raw event and JSON; diagnostics stay bounded |
| Heartbeats and rejected-open resets waited behind ordinary data; idle detection waited for heartbeat ticks | Use separate bounded reader/teardown queues, coalesced best-effort heartbeat admission and an independent idle timer | Full data queues cannot block control admission; live ping/rejected-open/mixed-teardown bursts retain the session; a short idle deadline works with a longer heartbeat interval |
| Startup synchronously retried failed remote issuance despite a usable local certificate | Connect/Listen can attach with validated local material while background recovery runs | Both attach, emit recovery-started/renewed, submit one CSR with the same key, persist the replacement and clear pending state; expired local and synchronous Ensure/Resume paths retain their checks |
| Chain-only changes were ignored during running certificate refresh | Compare and install both leaf and chain | Same leaf/new chain is saved and served in an actual TLS handshake |
| Parsing/rebuilding Cookie headers changed backend cookie syntax | Filter reserved gate-cookie segments from raw headers | Backend array-style names, raw JSON and spaces survive; reserved names, case variants and ambiguous reserved segments are removed |
| JSON omitted visitor connection ID zero | Include `conn` for visitor lifecycle events | Open/close events encode zero and nonzero IDs; unrelated events still omit unused connection fields |

The token scope hashes length-prefixed fields; it is not a remote credential.
Password-to-GitHub changes retain tokens when the protected boundary is unchanged.

## Test audit

The audit looked for tests that pass broken implementations, not just missing
coverage percentages. Two deliberate mutations in private code copies exposed
weak assertions:

| Mutation | Old test result | Stronger test |
| --- | --- | --- |
| Raise active-request limit from 256 to 257 | `TestProxyStreamAdmissionLimit` passed: it only checked a closed handler | Hold 256 authenticated upstream requests, reject the 257th before any backend call, release one and admit a replacement; the mutant fails |
| Print `corrupted` as binary build state | `TestVersionCommand` passed: it only checked field count/prefix | Validate actual printer output: unknown metadata or a lowercase hexadecimal SHA and clean/dirty/unknown state; the mutant fails |

The old closed-handler test now has a name matching its assertions. GitHub
fetch-metadata tests now construct a GitHub authenticator before starting the
handler, rather than changing a password handler's mode label afterward.

A new streaming regression uses a real TLS connection and stops reading until
the backend output stalls. Revoking its token must release the handler lease,
cancel the backend and abruptly close the client transport. Removing the
`WithClientConnection` attachment in an isolated test copy makes it fail with a
blocked lease. This checks behavior missing from the older in-memory fixtures.
Slow-login tests now wait for an actual body read; rejected JSON/multipart forms
must be denied before that read. They no longer infer this from a short sleep.

The admission test initially opened all 256 client sockets simultaneously and
occasionally hit the local server's accept backlog on Go 1.27.2. It now admits
each request through an upstream barrier while keeping all previous requests
active. Ten current-Go repetitions and three minimum-Go race repetitions passed.
This removes a test-harness timing assumption without changing the proxy limit.

Claude's confirmations reproduced disconnect regressions in the first two
priority-queue implementations: pure bursts initially cancelled the session,
then reader backpressure collided with heartbeat or teardown admission. Separate
bounded reader and teardown queues now prevent that collision; heartbeat pings
coalesce and skip busy admission. Live 5,000-control bursts, including 100 actual
failed visitor handshakes, require every reply without reattachment. Tests also
check reserved capacity, prompt cancellation and two actual successive heartbeat
writes. The original data-queue and independent idle-expiry regressions remain.
The 32-message teardown reserve still cancels on saturation, as before the audit.

Amp/Oracle additionally mutation-tested token scope and chain installation.
Reducing scope to upstream-only exposed missing behavioral assertions for tunnel
ID, hostname and API origin. Leaving the serving TLS certificate unchanged passed
the original identity-only chain assertion. These observations distinguish weak
coverage from an actual defect in the correctly implemented boundary/refresh.
The tests now exercise each boundary component and the served certificate.

Amp's route-count mutation also survived a test dominated by the byte cap. The
revised live fixture separates 300 short routes (exactly 256 retained) from 200
routes of 200 bytes (exactly 81 retained, 16,200 bytes). Expectations are literals
independent of production limit constants.
Raising either cap independently makes its matching case fail. Removing the
writer's heartbeat re-arm makes the second live ping time out.

Claude's final confirmation found the queue failure resolved and no new P0/P1.
Its sustained-ping probe passed seven times, including six race runs; its
5,000-rejected-open/100-real-handshake-failure probe passed eleven times,
including ten race runs. Reconstructing the shared-queue defect made both probes
fail three times each. The reviewer also ran the focused race suite five times.
These were local relay-fixture checks on Go 1.27.2, not hosted-service checks.

Very large bursts of real failed handshakes can still saturate the teardown
reserve and cancel a session. Claude observed this on both baseline and current
code; the samples did not establish a regression. The declared bound remains
32 queued teardown controls. A stalled physical writer is also subject to the
finite write timeout; that stalled-peer path was reasoned about, not exercised
in the final review.

Amp/Oracle's focused confirmation found no unresolved P0/P1 and repeated the
changed transport, TLS, token-binding and chain tests five times under race on
Go 1.27.2. It independently confirmed both route-limit mutants fail. A remaining
proof gap is deterministic overlap of a blocked physical writer, saturated reader
queue and heartbeat execution; the review did not reproduce a defect there.
The checks above prove specific invariants, not resistance to every possible load.

`FuzzAnonymousBoundary` exercises the complete password and GitHub gate with
mutated methods, paths, Authorization/cookie/origin/upgrade headers and no issued
credentials. Its property is zero backend requests. CI fuzzes generated
inputs, rather than running only seed inputs, alongside the four protocol/routing
fuzz targets.

Static protocol vectors remain necessary: parser round-trip fuzzing can catch
crashes and serialization failures without proving every field's semantics.
Connect/Listen documentation examples compile but do not run a hosted tunnel in
CI. Hosted tests cover their runtime behavior separately. Generic authenticated
`/mcp` requests prove HTTP gating, not MCP OAuth interoperability.

## Toolchain and ongoing checks

CI retains Go 1.25 source-compatibility checks, adds current stable-Go tests and
`govulncheck`, and runs five bounded 45-second fuzz passes with two workers. Go
crash corpora are retained as CI artifacts. The scanner is a development tool,
not a module/runtime dependency.

The Go 1.27.2 scan found no known vulnerabilities. An intentional scan using
Go 1.25.0 reported 44 reachable standard-library advisories; this is a scanner
reachability result, not proof of 44 exploitable package bugs. Production builds
must use a [patched supported Go release](https://go.dev/doc/devel/release#policy).
The installed Homebrew v0.6.0 binary was built with Go 1.27.2.

## Compatibility and remaining boundaries

The hosted wire messages, TLS termination, certificate request format and
OpenTunnel API remain compatible. `MaxInboundTotalBytes` is an additive SDK
option; zero selects the new default. The cap measures retained payload, not
whole-process memory. TLS, WebSocket, allocator and socket overhead remains
additional, and separate relay sessions have separate budgets.

The relay/domain operator trust model, unverified peer identity, shared outbound
writer pressure, same-account local compromise and per-file storage crash window
remain as described in [SECURITY.md](SECURITY.md). Raw certificate failure reasons
and exported credential fields require deliberate caller handling.

No new real GitHub App/owner grant was created for this audit. GitHub OAuth/provider
behavior is covered by local fixtures and earlier dated owner-approved browser
checks; a current hosted GitHub grant is a separate live check. The service's
remote renewal-failure state was not deliberately induced on a hosted tunnel.
The corresponding recovery tests use controlled API/relay fixtures.

Dated command results and public-service checks are in
[VERIFICATION.md](VERIFICATION.md) and [LIVE_TESTING.md](LIVE_TESTING.md).
