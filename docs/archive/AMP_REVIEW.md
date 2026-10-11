# Amp security and correctness review

Reviewed on **2026-10-09**, using the `amp-review` workflow with an actual Oracle
second opinion. The initial review covered clean `main` at
[`3ce7efc`](https://github.com/darron/go-opentunnel/commit/3ce7efc8f48a35dc92d284983b821becffa56b55),
with emphasis on the hardening since `50523ec`.

**Initial recommendation: hold release.** Amp reproduced four blocking defects,
two other correctness/security defects, and a memory amplification case. Oracle
independently identified the channel cancellation, foreground recovery, expired
replacement, and fragmentation concerns. All seven findings were accepted after
source inspection and local reproduction. Confidence in those defects is high.

**Focused confirmation: PASS.** Amp reviewed the working-tree fixes, reran the
full race suite, repeated focused checks three times, and ran four independent
probes five times. It found no remaining blocker in those paths. No second Oracle
call was made.

## Findings and dispositions

| Finding | Initial severity | Fix |
| --- | --- | --- |
| Channel abort left outbound writes blocked | High; blocking | Channel-owned logical cancellation wakes sends. Queue waits have finite deadlines; canceled queued messages are discarded. Physical writes remain session-owned to avoid closing a shared WebSocket on channel cancellation. |
| Foreground recovery bypassed cooldown and blocked removal | High; blocking | Creation, resume, foreground recovery, and runtime recovery share submission accounting. Issuance releases the profile lock between polls and rechecks persisted ownership before saving. |
| Cancellation after creation lost deletion credentials | Medium; blocking | Known creation credentials are persisted with a bounded independent context. Persistence/key-generation failures attempt remote deletion. If deletion also fails, a typed `ProvisioningError` returns the known secret credentials. |
| A different expired remote certificate prevented attachment | Medium; blocking | Cached and replacement material use the same attachment-only expiry policy. `Ensure`, visitor TLS handshakes, and startup readiness still require a valid certificate. |
| Tiny fragments amplified retained memory | Medium; nonblocking on available exploit evidence | Fragments coalesce into bounded blocks rather than allocating one slice per frame. Payload limits still apply. |
| Arbitrary API error tags reflected credentials into logs | Medium; nonblocking given hostile-server precondition | Only recognized protocol tags/codes reach public error fields; other tags become `HttpError`, other attach codes become `unknown`. |
| Invalid interactive route targets terminated otgo | Low; nonblocking for the package | Invalid routes and route conflicts report to stderr, preserving the interactive tunnel. Lifecycle and output failures remain fatal. |

A related channel check also reproduced a write-deadline update failing to
interrupt an already pending send. Deadline changes now wake a per-call watcher;
the watcher is joined before the write returns and does not cancel the socket.

Implementation and regressions were committed as
[`556b16f`](https://github.com/darron/go-opentunnel/commit/556b16f5998e0d0047ff95e9e277749be3d04f7e).

## Regression evidence

The primary regressions failed on the reviewed behavior before their fixes.
The initial foreground cooldown case submitted **ten CSRs** during one retry
interval. A 64 KiB one-byte-fragment payload retained about **2.3 MiB** of slice
capacity and payload allocations. The fixed cases pass.

[`amp_regression_test.go`](../../amp_regression_test.go) exercises:

- Channel-only abort while a send waits for delivery; the shared session survives.
- Reset cleanup behind a full data queue, canceled-message discard over a real
  WebSocket, queue admission/result timeouts, and changing a pending write deadline.
- Runtime-to-foreground cooldown sharing through `Ensure`, `Resume`, and `Connect`.
- Removal during foreground issuance, followed by a ready response that must not
  recreate the profile.
- Distinct expired cached/remote generations, strict `Ensure`, and a valid
  replacement after renewal-triggering attachment.
- Cancellation immediately after remote creation; pending credentials remain
  removable. Persistence failure attempts deletion; combined persistence/deletion
  failure returns usable recovery credentials. Malformed known creation responses
  and key-generation rejection also compensate.
- Tiny-fragment allocation bounds, exact byte preservation, and payload overflow.
- A server reflecting its received Authorization header into `_tag`; ordinary
  and structured API errors omit that reflected value.

[`amp_confirmation_test.go`](../../amp_confirmation_test.go) retains Amp's four
additional probes: ambiguous initial/runtime bind failures, repeated resume of
active issuance without rebinding, and bounded cleanup-queue saturation. These
passed five race repetitions after being added to the repository.

[`commands_test.go`](../../cmd/otgo/commands_test.go) exercises invalid targets,
invalid names, and route conflicts, followed by a successful next command.
[`redaction_test.go`](../../redaction_test.go) also verifies that recovery errors
keep their pending token/key out of ordinary formatting, hex formatting, and
JSON. Existing real-TLS, half-close, route-isolation, renewal, and lifecycle tests remain
part of the complete suite.

## Validation status

Passed locally with Go **1.27.2** on macOS arm64 and golangci-lint **2.14.0**:

```sh
make check
go test -race ./... -count=1
GOTOOLCHAIN=go1.25.0 go test ./... -count=1
make fuzz
```

Lint reported **0 issues**, including package, tests, CLI, and example. Focused
fix regressions passed ten race repetitions; Amp's additional retained probes
passed five. Linux and Windows amd64 package/CLI test compilation and example
builds passed; Windows runtime behavior remains untested.

[Hosted CI for `556b16f`](https://github.com/darron/go-opentunnel/actions/runs/37991416328)
also passed: Go 1.25 tests, vet, and CLI/example builds on Linux and macOS,
Linux race tests, and repository-wide formatting/lint.

**The rebuilt CLI/app public workflow passed with exit 0.** It exercised new
provisioning, cancellation/resume, all inspection commands, normal-trust HTTPS,
incremental streaming, text/binary WSS, large/concurrent uploads, route changes,
invalid input, shutdown, and remote/local deletion. All three dedicated identities
were removed; the Go API confirmed HTTP 404, and all owned processes stopped.
See the [post-Amp live record](../LIVE_TESTING.md#post-amp-review-retest).

A tool-server interruption lost the first run's final command result. Its test
processes had stopped and storage was empty. The complete workflow was repeated
with output and exit status recorded to files; only that explicit exit-0 result
is used as the final live verification.

## Remaining boundaries

- A create request whose successful response is lost can still allocate a remote
  tunnel with credentials unknown to the caller. The protocol has no idempotency
  key or allocation lookup that solves this client-side.
- `ProvisioningError.Pending` contains secret credentials. Handle it with
  `errors.As`; securely persist a complete pending record or use ID/token with
  `API.Remove`. If key generation failed, the record supports deletion only.
  Bounded persistence and compensating cleanup can outlive caller cancellation.
- The retry cooldown is in memory and scoped to one client/profile. Restarting
  the client resets it; separate clients/processes need coordination.
- Polling releases the lock, but a finite API/storage operation still holds it.
  Custom storage must honor cancellation. A short-deadline removal can time out
  while an individual operation is in progress.
- A physical WebSocket write already in progress can complete after logical
  channel cancellation. Its session timeout remains finite. Cleanup controls use
  a separate bounded queue; saturation closes the session instead of losing resets.
- The default aggregate inbound payload budget is 2 GiB, plus block/slice, TLS,
  socket, and other overhead. Reduce limits for smaller applications.
- Tiny-fragment memory amplification was reproduced with fixture framing.
  Ordinary visitor control of deployed relay framing was not established; no
  Internet-facing exploit is claimed.
- Storage retains the documented same-account check-then-use race, per-file
  crash-consistency window, and Windows ACL setup requirement. The hosted
  operator remains inside the domain/certificate trust boundary.

No established SNI authorization bypass or cross-origin credential transfer was
found. AI review and tests provide evidence for these cases, not proof of every
input or long-running production behavior. See [SECURITY.md](../SECURITY.md) and the
[dated live tests](../LIVE_TESTING.md).
