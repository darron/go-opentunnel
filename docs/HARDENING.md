# Hardening disposition

This is the action record for the 2026-10-09 hardening pass. It maps every
finding in [the preserved review](CLAUDE_REVIEW.md) to its current disposition.
That review is a historical baseline, not a current statement of behavior: its
SHA-256 is `20495594e5cb64451cf85d3b684f279060d37efbde3ff925e7bac65932619a3c`.

## What changed

- Visitor ClientHello SNI now has to select the relay-proposed route before a
  local target is dialed.
- Connection startup and lifetime are separate; normal `Connection.Close()`
  leaves `Err() == nil`.
- Renewal handles server-driven expiry and failed issuance without abandoning
  the tunnel identity or private key.
- API redirects, storage deletion, credential rendering, CLI output, channel
  idleness, and CI have explicit hardening behavior.

## Evidence recorded for this pass

| Check | Recorded result |
| --- | --- |
| `make check` | Passed: tests, vet, formatting, zero lint findings, and builds |
| Hosted CI | [Implementation commit `7cbae9a`](https://github.com/darron/go-opentunnel/actions/runs/37985077768) passed Go 1.25 tests/vet/builds on Linux and macOS, Linux race tests, and repository-wide lint |
| Full race suite | Fresh `go test -race -count=1 ./...` passed |
| Go baseline | `GOTOOLCHAIN=go1.25.0 go test ./... -count=1` passed |
| Cross-compilation | Linux and Windows amd64 compilation passed; neither target was runtime-tested locally |
| Fuzz smoke, 5 seconds each | Frame: 40,495; control: 675,052; SNI: 772,076 executions; all passed |
| Focused concurrency | Hardening race tests passed at `-count=5`; all CLI tests at `-count=3`; focused reviewer redirect/recovery tests at `-count=10` |

## Follow-up review

The follow-up reviewer found no remaining material blocker after redirect-origin
pinning, nonblocking renewal, and the one-hour per-client/per-profile recovery
cooldown. The reviewer retained two bounded limits: API calls while the profile
lock is held use the default 15-second deadline and can delay a short-deadline
`Remove`; the recovery cooldown is in-memory rather than global across clients.

## Final rebuilt CLI/app retest

**Passed the listed functional checks on 2026-10-09** against the public service,
using binaries rebuilt after all behavior changes. The CLI and embedded app
were exercised twice. Each run used three dedicated temporary profiles; all
six identities were removed and all owned processes stopped.

- CLI provisioning/inspection: interrupted create, persisted pending state,
  resume, ensure, create conflict, all local views, and online/offline inspection.
- Public traffic: normally verified HTTPS, incremental streaming, WSS text and
  binary echo, exact 2 MiB POST echo, and eight concurrent 256 KiB POST echoes.
- Routes: add a name, replace its target, refuse a backend without disrupting
  root, suspend with empty routes, and restore attachment.
- Shutdown and embedding: interactive input errors preserve traffic; quit,
  deadline, and SIGINT work with open stdin; the webapp provisions and owns its
  own tunnel, serves HTTPS/stream/WSS, and exits cleanly on SIGINT.
- Cleanup: pending deletion, idempotent removal, empty local views, and SDK HTTP
  404 for all four completed tunnel IDs.

The temporary Python driver initially failed its extra post-deletion HTTP
assertion: its raw API probe returned 403 rather than the expected 404. This was
not a CLI/app failure. A Go consumer using this package's API transport returned
404 for every deleted completed tunnel. The reason for the Python 403 was not
established. See the [dated live record](LIVE_TESTING.md#post-hardening-cli-and-app-retest)
for the checks and their limits.

## Regression coverage added

This pass adds **43 test functions** and expands existing regressions. Tests use
real TLS/WebSockets and generated fixture certificates; they run without the
public service.

| Boundary | Regression sources |
| --- | --- |
| TLS route isolation, expiry, recovery, lifetime, idle channels, and backoff | [hardening_test.go](../hardening_test.go) and [tunnel_test.go](../tunnel_test.go) |
| API transport and cross-origin bridge redirects | [api_test.go](../api_test.go) and [bridge_redirect_test.go](../bridge_redirect_test.go) |
| Credential rendering | [redaction_test.go](../redaction_test.go) |
| Storage permissions, safe markers, and deletion boundaries | [storage_hardening_test.go](../storage_hardening_test.go) |
| CLI output, malformed input, quit, and output failures | [commands_test.go](../cmd/otgo/commands_test.go) |

The stuck-issuance and repeated-failure tests reproduced an indefinite removal
wait and ten CSR submissions within one retry interval before the fixes. Tests
now cover removal during pending recovery, shared cooldowns, eventual retry,
and cooldown reset after installing a valid replacement. Expiry and API-outage
tests also failed when their respective guards were temporarily removed, then
passed after restoration. Overflow coverage checks its distinct closure error
while a healthy channel keeps forwarding. The external-package embedding
[example](../example_test.go) is compiled by the normal suite.

## Security findings

| Review item | Disposition |
| --- | --- |
| **S1: relay route versus TLS SNI** | **Fixed.** The TLS callback derives the route from ClientHello SNI and rejects missing, unrelated, deeper, or mismatched names before dialing a target. Regression coverage exercises route isolation. |
| **S2: cleartext API transport** | **Fixed.** HTTP is limited to exact `localhost` or literal loopback IPs. Redirects must retain scheme, hostname, and effective port, including after a caller redirect hook. |
| **S3: credential formatting** | **Fixed with an explicit boundary.** `Identity` and `PendingIdentity` redact JSON, `fmt`, and `slog` output. Direct exported-field access and custom serializers can still expose secrets; storage guidance requires explicit persistence of secret fields. |
| **S4: indefinitely idle channels** | **Fixed in scope.** `TransportOptions.IdleTimeout` can close channels with no application bytes in either direction; zero remains disabled for streaming. A per-route connection cap was not added. |
| **S5: failed or expired certificate recovery** | **Fixed.** Expired material can attach to trigger the hosted service's automatic renewal, but `Connect` does not report ready until a valid replacement is installed. Near-expiry polling expects server renewal and does **not** submit an ordinary CSR. A remote failed state submits a same-key CSR with a per-client, per-profile cooldown. |
| **S6: file-store boundaries** | **Partly fixed.** New roots/profiles and credentials receive private modes; writable existing roots are rejected without chmodding caller-owned roots. Removal requires a safe marker and preserves unrelated data. Path-based check-then-use remains; `os.OpenRoot` and a transactional credential bundle are deferred. |
| **S7: smaller transport and diagnostic issues** | **Mostly fixed.** Channel limit/idle errors are distinguishable; same-client, same-profile bridges may use disjoint route names while overlaps fail; backoff resets only after a sufficiently stable attachment; C1 controls are sanitized. Wrapped local causes aid diagnostics, but raw remote response bodies remain intentionally redacted. Per-route ALPN, `LoopbackOnly`, and a unified User-Agent are deferred. |

## API findings

| Review item | Disposition |
| --- | --- |
| **A1: `Connect` context ownership** | **Fixed.** `ctx` bounds startup only. `ConnectOptions.Lifetime` optionally owns the running tunnel; nil leaves closure to `Connection.Close` or `Client.Close`. CLI and webapp explicitly pass their command/application context as lifetime. |
| **A2: no `net.Listener`** | **Deferred.** It remains a later API feature, not a hardening prerequisite. Current `host:port` routes stay compatible. |
| **A3: stringly states and events** | **Partly fixed.** Event-field contracts and exported identifiers are documented; actionable sentinels were added for new hardening paths. Full typed enums and a `RootRoute` constant are deferred to avoid a broad API redesign. |
| **A4: absent results as `(nil, nil)`** | **Unchanged by design.** `Get`, `Pending`, and `Resume` retain their documented missing-result contract, including CLI JSON `null`. This matches the upstream SDK's absent-value contract; callers must check the pointer as well as the error. An `ErrNotFound` redesign adds no security protection and is deferred. |
| **A5: actionable errors and normal close** | **Mostly fixed.** Certificate, route, idle, inbound-limit, and issuance paths expose sentinels; requested `Close` yields nil terminal error. API errors retain status/tag while raw remote bodies stay redacted to avoid credential or service-detail leakage. |
| **A6: JSON zero-time noise** | **Fixed.** Relevant `time.Time` fields use `omitzero`; `Event.Delay` remains a duration and JSON encodes it as nanoseconds. |
| **A7: consistency and documentation gaps** | **Partly fixed.** Public identifiers, event fields, transport defaults, storage obligations, and lifetime behavior are documented. API renames, a different profile shape, widening storage constructors, and `Ensure` progress callbacks are deferred. |
| **A8: API availability at startup** | **Improved.** A valid local identity may attach through a temporary server-side API failure when safe; rejection/authentication errors still fail. This is bounded by normal API deadlines, not an offline-first guarantee. |

## Ergonomics and project findings

| Review item | Disposition |
| --- | --- |
| **E1: exported documentation and examples** | **Fixed in scope.** Public API and event contracts are documented, and compiled examples exercise the embedding path. |
| **E2: `otgo` behavior** | **Fixed where scripting and safety required.** Interactive malformed input reports to stderr and keeps the tunnel active; JSON stdout stays valid; event output includes operational fields; provisioning progress uses stderr and results use stdout. `remove` has no confirmation gate, by explicit product decision. Missing `get`/`pending` keep their documented `null` contract. |
| **E3: inbound overflow diagnosis** | **Fixed in scope.** Overflow has a distinct error and the documentation states that a large upload to a slow target can reset despite a healthy session. Protocol-level flow control/backpressure remains unavailable. |
| **E4: hygiene and CI** | **Fixed in scope.** Go 1.25 is the stated minimum; CI tests, vets, builds CLI/example, races on Linux, and runs pinned golangci-lint formatting/lint. The source was clarified where hardening required it; a wholesale style rewrite is deferred. |

## Remaining operational limits

- The certificate-recovery cooldown is in memory and per client, not global
  across processes; restarting a client resets it.
- Background renewal releases the profile lock while issuance is pending, but
  bounded API calls under that lock use the default 15-second request deadline
  and can delay a short-deadline `Remove`.
- File storage has no cross-process transaction or lock. Same-user races and
  mixed credential generations after a crash remain possible.
- The hosted service and its deployed revision have not received an independent
  audit. Read [SECURITY.md](SECURITY.md) for its trust boundary.

Use [TESTING.md](TESTING.md) for repeatable local commands and
[LIVE_TESTING.md](LIVE_TESTING.md) for dated public-service evidence.
