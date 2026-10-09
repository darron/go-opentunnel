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
