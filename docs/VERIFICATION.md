# Local verification record

## Go API documentation — 2026-10-10

Added `doc.go` with startup, lifetime, concurrency, recovery and authentication
contracts. Expanded public declaration/field comments and added local examples.
The runtime client version remains 0.4.0; these changes are recorded under
Unreleased for the planned v0.5.0.

- A standard-library AST audit checked 184 public declarations and fields;
  none lacked a doc comment. The audit covered the public root package, not
  implementation-only methods or internal packages.
- Go 1.25's `go/doc` renderer checked all 32 explicit Go-symbol links without
  unresolved references. `go doc .` and `go doc -all .` rendered the overview
  and public contracts. Field references link to their containing types for
  Go 1.25 compatibility.
- All three output-bearing examples passed on Go 1.25.0 and the local Go 1.27.2.
  The two public-tunnel examples compiled with the suite and were not executed.
  The README's complete Go example compiled as a separate module.
- `make check` passed tests, vet, formatting, full golangci-lint (**0 issues**)
  and the CLI build. All 131 local Markdown links/anchors resolved, and
  `git diff --check` passed.
- Ignoring comments and optional semicolons, a token comparison confirmed all
  11 existing production Go files were unchanged. `doc.go` adds only a package comment;
  runtime behavior, public signatures and dependencies are unchanged.
- Requested pkg.go.dev indexing for the already published v0.4.0 through its
  fetch endpoint. Both the versioned and latest package pages then returned
  HTTP 200 with API documentation and the Connect/Listen examples; the Go
  Reference badge also returned HTTP 200. The README links to that page.
  New main-branch comments will appear there with the next published version.

Use [the API documentation checks](TESTING.md#check-go-api-documentation) to read
the docs and rerun examples. No generated HTML or new documentation dependency
was committed. Existing public-service results below remain the live evidence;
this documentation pass did not create another tunnel or GitHub App.

## Documentation navigation — 2026-10-10

Applied i-have-adhd to the README, auth setup steps and documentation navigation.
The protected proxy quick start now precedes library embedding and validation.
Older reviews moved to `archive/`; their findings remain available through the
[documentation index](README.md).

- All local Markdown links and heading anchors in the README, changelog and docs
  resolved after the move.
- The complete README Go example compiled as a separate module using this checkout.
- The original Claude review remained byte-for-byte identical. Other archived
  review records changed only their relative links.
- `git diff --check` passed. Changes are limited to documentation; package code,
  tests, workflows and the released v0.4.0 tag were not changed.

## v0.4.0 publication and stable Homebrew — 2026-10-10

Published [v0.4.0](https://github.com/darron/go-opentunnel/releases/tag/v0.4.0)
from `6e1ab1401daeb7a967925cf3027865647e8a5dfc`. The CHANGELOG entry is committed;
release notes are attached to GitHub, with no release-note document in the repo.

- [Release-commit CI](https://github.com/darron/go-opentunnel/actions/runs/38104904964)
  and [tag-triggered CI](https://github.com/darron/go-opentunnel/actions/runs/38105031656)
  passed Linux/macOS tests, vet, CLI/example builds and updater tests, plus Linux
  race and full golangci-lint.
- The actual `release: published` event ran the
  [source hook](https://github.com/darron/go-opentunnel/actions/runs/38105042751),
  which passed and automatically dispatched the
  [tap workflow](https://github.com/darron/homebrew-tap/actions/runs/38105048371).
  Its macOS source build/style/strict audit/install/test and isolated publishing
  jobs both passed. No manual dispatch was used for this release.
- Tap commit `3b9db550b502d97a27c70647040f84689da04c8d` changed only
  `Formula/otgo.rb` to v0.4.0. The source archive SHA-256 is
  `2c0fd0d1946c5157ace2237bd3caa95111a9c760e227562ba978f1dcf54b6852`.
- Locally fetched and verified that archive, replaced the HEAD installation with
  stable v0.4.0, built only the CLI, and passed `brew test darron/tap/otgo` plus
  `auth github --help` and `proxy --help`. `brew list --versions otgo` reports
  `otgo 0.4.0`; the executable resolves to `Cellar/otgo/0.4.0/bin/otgo`.
  Saved XDG profiles were outside the installation directory and were untouched.
- The final test-only GitHub App was owner-approved for deletion, disappeared
  from the Apps list, and subsequently returned HTTP 404 from GitHub's public App
  endpoint. Temporary tunnel API 404 cleanup is recorded below.

## Pre-v0.4.0 security follow-up — 2026-10-10

The final source/tests passed `make check`: all package tests, vet, formatting,
full golangci-lint (**0 issues**) and CLI build. A fresh
`go test -race -count=1 ./...` passed all packages (auth: **61.758 seconds**).
The example rebuilt and all five Homebrew updater tests passed.

Claude’s focused confirmation resolved its original findings with no new blocker.
Amp/Oracle then found two P2 lifecycle races and no P0/P1: cancellation could save
GitHub credentials during shutdown, and a revocation close could reach a reused
connection. Both reproduced in regressions and were fixed; focused Amp confirmation
and Oracle found both resolved and no new material finding/commit blocker.
Wizard cancellation/commit and TLS/keep-alive regressions also passed
three focused race repetitions. Removing callback joining reproduced the committed
callback failure again before restoring the correction. The conversion-cancellation
regression also passed 100 race-enabled repetitions.

The post-Amp rebuilt password smoke and full public CLI/listener/embedding-app
workflow both passed, including cleanup API 404; SSE/WSS revocation was **0.236
seconds**. Real GitHub wizard/OAuth, visible backend, logout, excluded/restored
identity and restart checks passed before these final lifecycle changes, with
local cleanup and remote API 404. Their changed wizard paths were retested through
loopback HTTP/provider fixtures. GitHub accepted the approved test-App deletions
and queued them. The [hardening-commit CI](https://github.com/darron/go-opentunnel/actions/runs/38104516058)
passed Linux/macOS tests, vet, CLI/example builds and updater tests, plus Linux
race and full lint. Homebrew upgraded to `HEAD-c59eeae`; source build, `brew test`
and auth/proxy help passed. The v0.4.0 version update passed another `make check` with zero lint issues;
the rebuilt CLI repeated the complete hosted password smoke (revocation:
0.222 seconds), confirming service compatibility and API 404 cleanup.
Release-candidate CI passed before publication, as recorded above.

See [AUTH_SECURITY_REVIEW.md](AUTH_SECURITY_REVIEW.md) and the
[final live repeat](LIVE_TESTING.md#post-amp-auth-lifecycle-repeat--2026-10-10).
The 0.389-second record is the preceding post-Claude build; 0.370 seconds refers
to the earlier cache/admission build.

After the cache-policy and password-admission corrections, `make check` passed
all package tests, vet, formatting, full golangci-lint (**0 issues**) and CLI build.
A fresh `go test -race -count=1 ./...` passed all packages; the affected auth
package passed another fresh race run after the final NGINX-header filter.
New regressions cover both-mode anonymous access/cache policy, OAuth failure
boundaries and rejected
password forms; occupied hash slots preserve the budget. The cache and admission
regressions were observed failing before their production corrections.

An independent fresh-context reviewer rechecked the fixes and ran focused tests.
Real GitHub registration, allowed/denied identity, logout/restart invalidation,
public-service anonymous gating, token stripping/revocation and protected-response
headers passed. That cache/admission build also repeated the full public password
smoke, including cache overrides, uploads, streams, restart and profile isolation;
revocation closed SSE/WSS in 0.370 seconds and API 404 confirmed cleanup. See
[AUTH_SECURITY_REVIEW.md](AUTH_SECURITY_REVIEW.md) and the
[dated live record](LIVE_TESTING.md#github-auth-and-security-follow-up--2026-10-10).

Browser form policy correction: regression tests, `make check` (zero lint issues),
`make race`, and native Chrome password login/root redirect/logout passed. See
[LIVE_TESTING.md](LIVE_TESTING.md#browser-login-regression--2026-10-10).
The [browser-fix CI run](https://github.com/darron/go-opentunnel/actions/runs/38100391440)
passed all jobs. The owner also confirmed the protected Inbox loads at `/`.

## Auth proxy and Homebrew — 2026-10-10

Verified on macOS arm64 with Go 1.27.2 and golangci-lint 2.14.0. Auth adds no external
dependency; the existing WebSocket dependency is unchanged. The default build
produces only the CLI; the example has a separate target.

| Check | Result |
| --- | --- |
| `make check` | Full tests, vet, formatting, lint, CLI build passed; **0 lint issues** |
| `make race` | All packages passed |
| GitHub Actions (Go 1.25.x) | Linux/macOS tests, vet, builds and updater tests passed; Linux race and full lint passed |
| `GOTOOLCHAIN=go1.25.0 go test ./...` | Minimum Go version passed |
| `make fuzz` | Frame 66,434; control 1,026,590; SNI routing 572,652 executions, no failure |
| Linux/Windows amd64 CLI cross-build | Passed; not runtime-tested |
| Solaris amd64 auth test cross-build | Passed; protected auth storage deliberately unsupported |
| Homebrew updater unittest | Five tests passed |
| `actionlint` | Workflow checks passed |
| Stable Homebrew formula | Syntax/style/strict audit, source install and `brew test` passed |
| Official `darron/tap/otgo` HEAD install | Source build, `brew test`, CLI help and auth paths passed |
| Tap-owned Actions workflow | Manual v0.3.0 run passed macOS validation and isolated publishing jobs |
| Source-to-tap release hook | Secret-backed dispatch, macOS source build/audit/test and publisher passed using existing v0.3.0 |

The [live tap run](https://github.com/darron/homebrew-tap/actions/runs/38096719658)
validated the existing stable release without changing it. The hourly schedule was
subsequently removed in favor of a published-release hook. With `HOMEBREW_TAP_TOKEN`
configured, the [source dispatch](https://github.com/darron/go-opentunnel/actions/runs/38100661207)
successfully started the [tap run](https://github.com/darron/homebrew-tap/actions/runs/38100668461).
Both tap jobs passed: macOS source build, style/strict audit, installation and
`brew test`, followed by isolated publishing. The formula was already current,
so publishing was a no-op. This used manual dispatch with existing v0.3.0 to
exercise the complete job chain; the `release: published` event itself was not
exercised. No new tag/release was published. Local HEAD upgrade and `brew test`
also passed with the browser fix installed as `HEAD-d6d5a28`.

The first Linux CI run exposed a test fixture race: manual renewal competed with
a newly started background worker. Four manual renewal tests now use a worker-free
connection fixture; background recovery integration coverage is retained. Twenty
race-enabled repetitions of these checks passed, including shared cooldown and
renewal reset behavior. Production renewal code did not change. The
[implementation CI run](https://github.com/darron/go-opentunnel/actions/runs/38096875112)
passed all jobs after this fixture correction.

The fresh-context [auth review](archive/AUTH_PROXY_REVIEW.md) reproduced defects and fixes;
final source review found no remaining Critical/Important issue. It independently
ran full/focused tests, race tests, vet, formatting, lint and workflow checks.

The rebuilt CLI and embedding app passed the full public-service workflow again.
The auth smoke passed real public HTTPS, including eight concurrent 2 MiB uploads,
SSE/WSS revocation in **0.347 seconds**, corrupted-token denial, restart and two
isolated concurrent backends. All owned processes stopped, local credentials were
removed and API 404 confirmed remote deletion. See [LIVE_TESTING.md](LIVE_TESTING.md)
for coverage and browser/provider limits. Older records below describe their own
SDK revisions and checks.

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

The subsequent [Amp/Oracle review](archive/AMP_REVIEW.md) reproduced additional defects
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

The [Amp/Oracle listener review](archive/AMP_REVIEW_V0.3.0.md) reproduced a terminal-error
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
