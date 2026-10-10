# Local verification record

**Passed:** local acceptance checks, race tests, parser fuzz smoke tests, and
minimum-version/cross-platform compilation. **golangci-lint: 0 issues.**

Verified on **2026-10-09**, macOS arm64, Go 1.27.2, golangci-lint 2.14.0.
Upstream compatibility baseline: `22156aa6ab209515186c3ca4f111901b7cedc284`.
Use [TESTING.md](TESTING.md) to rerun the checks.

## Tests and analysis

| Command | Result |
| --- | --- |
| `make check` | Tests, vet, lint, and CLI/example builds passed |
| `go test -race -count=1 ./...` | Both tested packages passed; example built |
| `go test -race -run 'TestLifecycle\|TestTunnelStalledChannel\|TestTunnelRoutesReconnect' -count=10 .` | Repeated stress regressions passed |
| `golangci-lint run ./...` | 0 issues across library, tests, CLI, and example |
| `golangci-lint fmt --diff` | No formatting differences |

## Compatibility and example

| Command | Result |
| --- | --- |
| `GOTOOLCHAIN=go1.25.0 go test ./...` | Declared minimum Go version passed |
| `GOOS=linux GOARCH=amd64 go build -o bin/otgo-linux-amd64 ./cmd/otgo` | Passed |
| `GOOS=windows GOARCH=amd64 go build -o bin/otgo-windows-amd64.exe ./cmd/otgo` | Passed |
| `./bin/otgo help` | All diagnostic commands available |

Linux and Windows were compile-checked, not runtime-tested. The local-only
example returned the expected root response and all three `/stream` chunks.
Ctrl-C exited successfully.

## Parser fuzz smoke

Each run used `go test -run '^$' -fuzz '<name>' -fuzztime=5s .` and completed
without failure. Counts include the local fuzz cache and can vary on later runs.

| Parser | Executions |
| --- | ---: |
| `FuzzDecodeFrame` | 499,333 |
| `FuzzDecodeControl` | 591,655 |
| `FuzzRouteForSNI` | 196,736 |

## Behaviors covered by local fixtures

The fixture uses real WebSockets, real TLS handshakes, and generated test
certificates against a fake API/relay.

### API, certificates, and storage

- **API/protocol:** upstream vectors, strict HTTP statuses, authentication,
  escaped IDs, bounded responses, cancellation, delayed bodies, and redacted errors.
- **Certificates:** local key/CSR generation, exact and wildcard SANs, mismatched
  keys, validity, interrupted provisioning, resume, and failed issuance using
  the original key.
- **Storage:** memory/file implementations, upstream layout, permissions,
  corruption, cancellation, copies, traversal, symlinks, and pending transitions.

### Forwarding, lifecycle, and CLI

- **Forwarding:** root/named routes, concurrent large transfers, ciphertext at
  the relay, HTTP streaming, application WebSocket upgrades, and half-close.
- **Relay failures:** refused upstreams, bad TLS, duplicate IDs, connection
  limits, unknown controls, heartbeat, drain, and reconnection.
- **Lifecycle races:** route updates, renewal/deletion, cancellation before attach,
  blocked-upstream reset, stalled-channel isolation, renewal racing deletion,
  route names racing teardown, and bounded outbound queue cancellation.
- **Snapshots/events:** concurrent status and close, copy isolation, and lossy
  event buffering.
- **CLI:** help, flags, cancellation, JSON null/results, redaction, remote
  inspection, terminal sanitization, and interactive-reader shutdown.

An independent integrated code review found lifecycle issues that were fixed
with regression tests. Follow-up review found no remaining important code blocker.
This was a development review, not an independent security audit.

## Public artifact checks

- Source, docs, and the initial design commit were checked for private filesystem
  paths and common credential patterns.
- The only committed private-key-shaped fixture is invalid text containing
  `KEY`. Working test keys and certificates are generated at runtime.
- Build artifacts and local profile directories are ignored.
- The project carries an MIT license. Copied upstream vectors retain their MIT
  notice and commit provenance.

## Live evidence and confidence

The **2026-10-09** [live exercise](LIVE_TESTING.md) checked the deployed API,
certificate issuance, relay, CLI, and embedding example. It found a CLI stdin
shutdown bug; the fix passed a repeated live sequence, full local checks, and
fresh race tests. Both temporary tunnels were deleted.

**Confidence: high** for the behaviors covered by these local and live checks.
Long-term renewal, hosted server drain, and runtime behavior on Linux/Windows
remain outside the short live exercise. The hosted service's deployed source
revision was not established.

## Documentation and comment cleanup

The 2026-10-09 cleanup applied the
[i-have-adhd skill](https://github.com/ayghri/i-have-adhd/blob/main/skills/i-have-adhd/SKILL.md)
to all eight Markdown files and reviewed comments throughout the package, tests,
CLI, example, and lint configuration.

- `make check` passed again: tests, vet, formatting, lint (**0 issues**), and builds.
- All 20 tracked Go files retained identical non-comment token streams.
- Lint/compiler directives, lint configuration values, licenses, and upstream
  vector data were unchanged.
- The README embedding snippet compiled as an external package consumer.
- All 26 local Markdown links and heading anchors resolved.

The edits changed documentation and comments only. Earlier race, fuzz, and live
results above remain the records of those checks.


## Amp hardening verification, 2026-10-09

The subsequent [Amp/Oracle review](AMP_REVIEW.md) reproduced additional defects
in the prior baseline. All seven were fixed; Amp's focused confirmation passed.
New tests are in `amp_regression_test.go`, `amp_confirmation_test.go`, and the CLI
command tests. The full test/race suites, Go 1.25 tests, formatting, vet, builds,
and repository-wide golangci-lint passed with 0 issues. Focused fixes passed ten
race repetitions; four retained confirmation probes passed five. Parser fuzz
smokes and Linux/Windows amd64 compilation passed.

The rebuilt CLI and app also passed the [recorded post-Amp public workflow](LIVE_TESTING.md#post-amp-review-retest)
with exit 0 and remote/local cleanup verified. These results cover the listed
cases; they do not establish all inputs, Windows runtime behavior, long-term
production renewal, or hosted operator security.

## TLS listener verification, 2026-10-10

Implemented [issue #1](https://github.com/darron/go-opentunnel/issues/1) with
`Client.Listen` / `Listener`, `otgo listen`, and a direct-listener webapp example.
No external dependency was added. The existing forwarding API remains available.

Verified on macOS arm64, Go 1.27.2, golangci-lint 2.14.0:

| Check | Result |
| --- | --- |
| `make check` | All tests, vet, format, CLI/app builds passed; golangci-lint **0 issues** |
| `go test -race ./... -count=1` | Full race suite passed |
| `go test -race -run '^TestListener' . -count=10` | Ten repetitions passed |
| `GOTOOLCHAIN=go1.25.0 go test ./... -count=1` | Minimum supported Go version passed |
| Linux/Windows amd64 | Package/CLI test compilation and webapp builds passed; Windows runtime untested |
| `make fuzz` | Frame 64,474; control 1,105,775; SNI 610,384 executions, no failures |
| Sharing check | Relative documentation links resolved; no private workstation paths or private key material found. The preexisting storage test contains an invalid `KEY` PEM placeholder. |

The listener fixtures use the real relay framing, generated certificates, TLS
handshakes, and HTTP server. Coverage includes `Request.TLS`, Secure cookies,
HTTPS origin construction, exact relay peer despite forged forwarding headers,
wrong SNI, streaming HTTP/WSS with normal close, preserving buffered responses
for slow readers, limits and stalled visitors, idle cleanup,
certificate refresh, pending recovery, repeated reconnects without accepting,
disjoint forwarding/listener route ownership, concurrent Accept, lifetime/fatal
errors, client shutdown/removal, and joining write-deadline workers. The CLI
regressions cover valid name parsing, invalid/duplicate names, help, and metadata.

The first hosted attempt exposed reuse of the forwarding flag parser, which
rejected `--route @` before listener startup. A failing CLI regression reproduced
it; separate route-name parsing fixed it. That attempt cleaned up its identities.
The next hosted attempt exposed response truncation on ordinary application
close: an immediate reset could discard already-written bytes buffered by the
relay. A slow-reader regression reproduced the truncation. Ordinary close now
sends protocol `end` so preceding bytes drain; failures and forced shutdown retain
reset/session-abort behavior. Normal WebSocket close is also asserted locally.
The final rebuilt hosted rerun is recorded in [LIVE_TESTING.md](LIVE_TESTING.md).
See [LISTENER.md](LISTENER.md) for lifetime, shutdown, and trust contracts.

The [first hosted Linux CI run](https://github.com/darron/go-opentunnel/actions/runs/38080724255)
timed out in the slow-reader test because its tiny TCP buffer drained much more
slowly on Linux than macOS. The regression now pauses relay output explicitly
after TLS setup, queues a response, observes orderly `end`, then releases output
and checks every byte. Restoring the original reset behavior makes it fail.
This removes an OS-dependent throughput assumption; production code is unchanged.

[Follow-up hosted CI](https://github.com/darron/go-opentunnel/actions/runs/38080929130)
passed for `8b4365cf38b6ac4802bf21d09bb161c554f9034c`: Go 1.25 tests/vet/builds
on Linux and macOS, the Linux race suite, and all-package formatting/lint.

## v0.3.0 review follow-up, 2026-10-10

The [Amp/Oracle listener review](AMP_REVIEW_V0.3.0.md) reproduced a terminal-error
race during profile removal and found stale design documentation. Both were
fixed before release. The new 64-paused-listener regression failed on every
listener before the fix, then passed ten race repetitions. After the fixes,
`make check`, the fresh full race suite, and Go 1.25 full tests passed; lint
reported **0 issues**. Amp's focused confirmation also passed all listener tests
with ten race repetitions, the full race suite, ten Go 1.25 repetitions of the
removal regression, vet, formatting, lint, and diff checks.

The CLI and webapp were rebuilt after the removal fix. The entire public-service
workflow was repeated and recorded with **exit 0**, including forwarding and
direct listeners, streaming, normal WebSocket close, route changes, shutdown,
and cleanup. All three owned identities were deleted with authenticated API
404 confirmations; local state was empty and all owned processes stopped.
See [the post-review live record](LIVE_TESTING.md#v030-post-review-retest-2026-10-10).
