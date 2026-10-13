# Local verification record

## Setup feedback and upstream API retries — 2026-10-13

These development changes start from `127cc68`. Go 1.27.2 on macOS arm64 was
used for the checks below. No dependencies were added.

| Check | Result |
| --- | --- |
| `make check` | Full tests, vet, formatting, golangci-lint (0 issues) and CLI build passed |
| `make race` | All packages passed |
| `govulncheck` v1.9.0 | No vulnerabilities found |
| Release tooling | All 16 Python tests passed |
| Documentation links | All 193 local Markdown links resolved |
| Secret scan | Gitleaks found no leaks |
| Independent security/correctness review | No remaining Critical or Important findings after fixes |
| Native CLI terminal check | A local delayed/rejected API showed advancing spinner frames; `TERM=dumb` showed plain steps. Failure left no password or success output |
| Hosted auth smoke test | Complete fresh-state run passed, including both profiles and confirmed cleanup; see [live results](LIVE_TESTING.md) |

Setup fixtures observe progress before a blocked API call finishes, preserve JSON
output, join the spinner on shutdown and exercise successful saving. CLI-level
GitHub tests run the real loopback wizard with a fixture GitHub HTTP response and
an executable launcher fixture. Default launch, `--no-browser`, launcher failure,
usable printed fallback, cancellation and token-free warnings passed. The existing
GitHub setup/callback/security suite and all-package race suite also passed. No new
hosted GitHub App or identity grant was made during this run.

The pinned upstream API retry vectors match the documented statuses, backoff
bounds and fixed Cloudflare diagnostics. Local HTTP tests verify replayed bytes
and credentials, six-retry limits, cancellation, body cleanup, logical statistics
and interrupted success-body reads. Saved-certificate tests distinguish API
outages/internal deadlines from caller deadlines, 401/404, invalid redirects,
malformed responses and TLS verification failures. Truncated/oversized error
bodies retain their known status, so a broken 401 body cannot enable fallback.
Raw-body message vectors remain deliberately redacted.

Three temporary broken-code mutations were independently detected by behavioral
test failures: reverting to the official CLI User-Agent, allowing an ambiguous
502 creation to retry, and disabling CLI setup progress. Original source was
restored and those tests passed again. Earlier CSR cooldown and failed-cleanup
regressions now assert seven permitted HTTP attempts followed by no new logical
operation inside the cooldown, rather than assuming a single HTTP attempt.


## Release binary packaging — 2026-10-12

The release workflow builds only the CLI from the requested stable tag. Four
macOS/Linux archives (amd64 and arm64) contain `otgo` and `LICENSE`; each has an
individual SHA256 file, and `SHA256SUMS` covers all four. Homebrew automation is
unchanged. See [the release guide](RELEASES.md).

| Check | Result |
| --- | --- |
| Go 1.27.2 `make check` | Full tests, vet, formatting, lint (0 issues) and CLI build passed |
| Python release tooling | All 16 tests passed: seven Homebrew tests and nine archive/publication tests |
| Four-target build from clean v0.9.0 source | Passed; version and embedded SHA match `4726e313309302c838e2093e5ab221ae32084084` |
| Archive and checksum verification | All four archives contain exactly the executable and license; individual and combined hashes passed |
| Extracted native macOS arm64 binary | Exact version/SHA/clean output, help, proxy help and profile help passed |
| Workflow syntax | `actionlint` passed |
| Documentation links | All 179 local links resolved |
| Independent security/correctness review | Ready; no Critical or Important findings |

Publication tests replace the GitHub CLI boundary and use real archive files.
They cover draft/prerelease rejection, moved tags, downloading existing assets,
missing-only uploads without overwrite, conflicting bytes rejected before upload,
and an identical retry doing no upload. Foreign architecture binaries were
cross-compiled and inspected locally; they were not executed locally.

The [v0.9.0 backfill workflow](https://github.com/darron/go-opentunnel/actions/runs/38332624493)
passed its Ubuntu build/native check, macOS arm64 archive smoke check and
publication jobs. All nine assets are attached to the
[existing release](https://github.com/darron/go-opentunnel/releases/tag/v0.9.0).
Downloaded copies passed combined and individual checksum checks. Both macOS
archives contain the expected Mach-O architecture; both Linux archives contain
statically linked ELF executables for their expected architecture. All four
report matching target/CGO build metadata and contain the full release SHA.
The downloaded macOS arm64 CLI passed version and command help checks.
Running the publisher again against those downloads reported **0 uploaded,
9 already identical**, confirming that it preserved the published assets.
The release tag and Homebrew automation were unchanged.

## Observability and half-close cleanup — 2026-10-12

These v0.9.0 changes are based on `2d9fc0b`; the final
runtime changes are through `fc52f06`. The optional adapter and CLI use the
official Prometheus client. The root client does not import it. The minimum Go
version is now 1.26; the service API and relay framing are unchanged.

| Local check | Result |
| --- | --- |
| Go 1.27.2 `make check build-example` | Full suite, vet, formatting, full golangci-lint (0 issues), CLI and example builds passed |
| `go test -race ./... -count=1` | Fresh full suite passed after the auth counter isolation correction |
| `GOTOOLCHAIN=go1.26.9 go test ./... -count=1` | All packages passed on the patched minimum Go series |
| Go 1.26.9 runnable root and metrics examples | Passed; `go doc Stats` exposes scope, byte accounting and copied failure maps |
| Current-Go `govulncheck` v1.9.0 | No known reachable vulnerabilities found |
| Parser/routing fuzz smoke tests | All four `make fuzz` targets passed, five seconds each |
| Anonymous auth-boundary fuzzing | Five seconds with two workers passed; no unauthenticated backend request |
| Built CLI with isolated XDG directories | Long-command help, invalid-address/negative-timeout rejection, clean JSON stdout and zero state writes passed |
| Workflow and Homebrew updater checks | `actionlint` and all seven Python updater tests passed |
| Root compiled dependency graph | No Prometheus imports; the optional adapter uses the official library |
| Relative documentation links | All 173 local links resolved |
| Working-directory and full-history secret scans | Redacted Gitleaks scans reported no findings; history scan covered all 55 commits before the final documentation correction |

The statistics tests compare real WebSocket/TLS relay payload with counters,
cover API body/validation errors and durations, retain totals after closure,
exercise partial successful sends, admission/buffer limits, dropped events and
concurrent collection, and gather/scrape through the official registry and
handler. Certificate tests cover all eleven classes, copied snapshots, validated
failure responses and rejection of arbitrary metric labels. Repeated polling
counts observations, not additional remote issuance attempts.

Half-close tests first reproduced retained admission capacity, then verified
cleanup and reuse in both forwarding directions. Continued traffic, a fresh
half-close epoch, intermediate transport progress during a pending large write,
fully open quiet streams, cancellation joins and Listen's observation boundary
have regressions. The focused transport/certificate/collector race checks also
passed five repetitions on Go 1.26.9.

CLI fixtures exercise separate private scrapes, multiple listeners, port reuse,
cancellation and unexpected serving failures, bounded scrapes, Host/Origin
checks, and rejection before remote work. Saved `metrics_listen` config loads
without changing old configurations; actual startup fixtures check inheritance,
override, explicit disable, invalid/occupied ports and unchanged config bytes.
Pending-timeout messages require actual stored state and preserve quoted custom
API/storage arguments without leaking credentials into stdout.

Password and fake-GitHub flows count terminal login outcomes at session creation.
Wrong-scope machine tokens and anonymous requests never reach the backend.
Backend headers, transport errors and WebSocket `101` responses are counted
separately; existing SSE/WebSocket revocation tests remain green.

Independent task reviews reproduced and corrected two defects: half-close EOF
renewed the optional application idle timer, and a reused authenticator redirected
login counts to another handler. Their independent reproductions changed from
RED to GREEN. Separate timer epochs preserve idle semantics; a private request
context owns login accounting without mutating authenticators. New regressions
cover both auth modes and concurrent handler construction/login under race
checking. All task reviews approved the corrected source. A separate integrated
review approved the complete change set with no critical or important findings;
its one minor documentation correction clarified that a saved metrics address
also starts the listener without a flag.

These checks used isolated local fixtures. No personal profiles or running
proxies were changed, no real GitHub grant was created, and fresh hosted issuance
or deployed relay interoperability was not exercised for this update. Earlier
[hosted tests](LIVE_TESTING.md) cover only their recorded revisions. Failure
classes remain best-effort terminal-text diagnostics; the client cannot observe
server ACME attempts. Listen still returns exact `*tls.Conn` values and cannot
infer unread encrypted `close_notify`; applications must close their sockets.
See [observability](OBSERVABILITY.md) for metric meanings and access boundaries.

### v0.9.0 publication and Homebrew

Published [v0.9.0](https://github.com/darron/go-opentunnel/releases/tag/v0.9.0)
from `4726e313309302c838e2093e5ab221ae32084084`. The remote annotated tag and
Go's public module proxy resolve to that commit. Release notes are attached to
the GitHub release; the dated changelog and client version are committed.

- `make check build-example` passed after the version update, with full
  golangci-lint at 0 issues. [Main CI](https://github.com/darron/go-opentunnel/actions/runs/38214658796)
  and [tag CI](https://github.com/darron/go-opentunnel/actions/runs/38214996148)
  passed every job, including Linux race detection, current-Go vulnerability
  checks and all five sustained fuzz targets.
- The [release hook](https://github.com/darron/go-opentunnel/actions/runs/38215007967)
  automatically dispatched the [tap workflow](https://github.com/darron/homebrew-tap/actions/runs/38215016179).
  Style, strict audit, source build, install, formula test and publication passed.
  Tap commit `db6543328404089918ff6565cb23dfc5ec249027` changed only `Formula/otgo.rb`;
  the source archive SHA-256 is
  `5cad9c1134742036fa9713d12815d836579773efff159f16900690082de828cf`.
- Local Homebrew upgraded from 0.8.0 to 0.9.0. `brew test darron/tap/otgo`,
  `profiles --help` and `proxy --help` passed. Proxy help includes the metrics
  listener and half-close timeout flags. Both version aliases report the release
  SHA and `clean`; the binary uses Go 1.27.2. No running proxy was restarted or
  authentication state changed during publication.

## Visual pages and profile inventory — 2026-10-11

The v0.8.0 changes use self-contained dark templates for password/GitHub login,
GitHub registration, completion and logout. The original otgo SVG mark and the
attributed GitHub icon are embedded. There is no new Go dependency or service
protocol change. The expanded inventory reads local state without a remote API
request; `ready` describes matching configuration, not live availability.

| Check | Result |
| --- | --- |
| Go 1.27.2 `go test ./... -count=1` | All packages passed |
| `go test -race ./... -count=1` | All packages passed |
| Go 1.25.0 focused inventory, command and page tests | Passed on the minimum supported toolchain |
| `make vet lint build build-example` | Vet, formatting, full golangci-lint (0 issues), CLI and example builds passed |
| Real-file inventory fixtures | Completed, pending, auth-only, unsafe config, empty inventory, custom config/API selection (including base paths), combined pending/auth state and old names output passed; secret canaries absent; no API calls |
| Command quoting | A real POSIX shell parsed custom paths with spaces, quotes, HTML and command substitutions without executing their contents; explicit storage paths became absolute and resulting flags round-tripped through the CLI parser |
| Setup completion | Real callback fixture saved credentials, rendered the selected command with escaped HTML and no provider/setup secrets, rejected replay, and authorized exactly the clipboard script’s rendered SHA-256 |
| Browser layout | Chrome desktop and 375px layouts inspected; password/GitHub pages and long commands had no horizontal overflow; GitHub button retained its existing auth route |
| Clipboard | Chrome copy/paste produced the expected profile command; copying still worked after the preview server stopped; a Node harness checked success, permission denial and missing API branches |
| Installed-state inventory | Rebuilt CLI found the existing inbox profile and its launch command through read-only listing; its proxy/config were unchanged |

An independent review found two diagnostic defects: auth settings overwrote
pending state, and deriving a custom API base URL from its origin dropped a
possible path. Combined-state regressions and explicit custom-API selection now
cover both. Isolated mutations confirmed that the new tests reject removal of
identity matching, shell argument quoting and command HTML escaping.
The reviewer repeated inventory/command tests ten times and setup/page/GitHub
tests five times after the fixes, with no remaining actionable findings.

The synthetic preview uses the actual templates and response headers; reproduce it
with [the preview instructions](TESTING.md#preview-the-auth-pages). It creates no
remote resources. The clipboard script is hash-authorized only on completion;
login pages remain script-free. The screenshot/copy fixtures contain no real
credentials. Chrome’s extension blocked the fixture sign-in navigation even though
the server received the correct route; successful authentication and denial are
covered by the full handler/OAuth/TLS regressions, not inferred from that click.
A fresh hosted GitHub grant was not created for these presentation changes.

### v0.8.0 publication and Homebrew

Published [v0.8.0](https://github.com/darron/go-opentunnel/releases/tag/v0.8.0)
from `abec630db748d80bf88fe9cf166ade786db0ed3d`. The remote annotated tag and
Go's public module proxy resolve to that commit. Release notes are attached to
the GitHub release; the dated CHANGELOG entry and client version are committed.

- `make check` passed after the version update, with full golangci-lint at 0 issues.
  [Main CI](https://github.com/darron/go-opentunnel/actions/runs/38180252676) and
  [tag CI](https://github.com/darron/go-opentunnel/actions/runs/38180252736)
  passed every job, including Linux race detection, current-Go vulnerability
  checks and all five sustained fuzz targets.
- The [release hook](https://github.com/darron/go-opentunnel/actions/runs/38180262015)
  automatically dispatched the [tap workflow](https://github.com/darron/homebrew-tap/actions/runs/38180268507).
  Style, strict audit, source build, install, formula test and publication passed.
  Tap commit `edbb46a889a592208f9869f3649a210f796da71b` changed only `Formula/otgo.rb`;
  the source archive SHA-256 is
  `6f9e7b87ce4eef9430ff8315fa8db1a1f1340dea1191852fefb936507fd9d87b`.
- Local Homebrew upgraded from 0.7.0 to 0.8.0. `brew test darron/tap/otgo`,
  `profiles --help` and `proxy --help` passed. Both version aliases report the
  release SHA and `clean`; the binary uses Go 1.27.2. Read-only inventory found
  the existing profile and launch command. No proxy was restarted or auth state
  changed during publication.

## v0.7.0 security and test audit — 2026-10-11

The [audit record](SECURITY_AUDIT.md) separates reproduced defects, test gaps,
compatibility changes and remaining boundaries. Baseline: `a574449`; changes are
recorded in the v0.7.0 changelog. No runtime dependency or service wire format changed.

| Final local check | Result |
| --- | --- |
| Go 1.27.2 `go test ./... -count=1` | All packages passed |
| Go 1.25.0 `go test -race ./... -count=1` | All packages passed |
| Current Go `make vet lint build build-example` | Vet, formatting, full golangci-lint and CLI/app builds passed; lint 0 issues |
| Seven Python Homebrew-updater tests and `actionlint` | Passed |
| Linux/Windows amd64 cross-builds | Passed; Windows runtime was not exercised |
| Relative Markdown links and anchors | 157 checked, all resolved |
| Current Go `govulncheck` v1.9.0 | No known vulnerabilities found |
| Gitleaks, complete local history and working directory | No findings; reports were redacted and kept private |

An intentional Go 1.25.0 vulnerability scan reported 44 reachable standard-library
advisories. The source minimum remains compatible, but production builds should
use a patched supported toolchain. This scan is not evidence of 44 exploitable
defects in this package. At audit startup, the installed Homebrew v0.6.0 binary used Go 1.27.2.

Deliberate mutations in isolated code copies established that the revised tests
reject an incorrect admission limit, corrupted version state, missing TLS client
connection attachment, incomplete token scope and stale serving certificate.
The original admission test measured only a closed handler; it now holds 256
authenticated requests at the backend and checks overflow and recovery. A dial
burst initially made the new test flaky; per-request upstream barriers removed
that OS-dependent setup assumption. Ten current-Go repetitions and three
minimum-Go race repetitions passed.

The [first audit CI run](https://github.com/darron/go-opentunnel/actions/runs/38172500939)
passed macOS tests, full lint and sustained fuzzing, but both Linux toolchains
failed the new TLS fixture's client-drain deadline. Local Linux reproduction
confirmed that the artificial 1 KiB receive window delayed buffered data after
the transport closed; the lease and backend cancellation checks had succeeded.
The portable fixture now observes raw transport close directly with normal TCP
buffering. Twenty repetitions and five race repetitions passed on each of
macOS/Linux; removing the client-connection attachment still fails in Linux.
The production revocation code did not change.

The corrected implementation at `ced87108fd2849c74cb3209e31751e7afa75e354`
passed [all audit CI jobs](https://github.com/darron/go-opentunnel/actions/runs/38173165835):
Linux/macOS tests, vet, CLI/example builds and updater tests; Linux race detection;
full golangci-lint; current-Go tests and vulnerability scan; and all five sustained
fuzz targets. The rebuilt CLI reports `otgo 0.7.0` with that SHA and `clean` state.

The README and current guides were checked against source, CLI help, defaults,
XDG storage paths, dependencies and CI. Setup comes before validation; duplicate
historical fix lists were removed; token migration and certificate recovery are
explained beside their commands. Historical reviews remain labeled as records
of older revisions. All 157 local documentation links and anchors resolve.

Five 45-second current-Go fuzz targets passed with 7,316,805 executions; an
earlier complete pass also succeeded. An initial minimum-Go 120-second `FuzzDecodeControl` run
ended with `context deadline exceeded` and no failing-input corpus. Its cause
was not established. Repeating with an isolated fuzz cache on the same Go 1.25.0
toolchain passed 4,582,160 executions; the anomaly is not claimed as a reproduced
parser defect or silently counted as a pass.

Claude's final focused confirmation passed its sustained-ping and mixed-teardown
probes, including repeated race runs. Reconstructing the shared-queue defect made
both probes fail. Amp/Oracle's focused confirmation found no unresolved P0/P1,
repeated the changed security regressions five times under race and confirmed
both independent route-cap mutants fail. These are local reviewer checks;
[the audit](SECURITY_AUDIT.md) records their scope and residual limits.

Connect/Listen examples compile in CI; the [fresh-state hosted checks](LIVE_TESTING.md#v070-security-audit--2026-10-11)
exercise their runtime behavior. Fixture recovery tests deliberately induce
certificate failures; the hosted check did not. No new GitHub App grant was made.

### Publication and installed Homebrew

Published [v0.7.0](https://github.com/darron/go-opentunnel/releases/tag/v0.7.0)
from `5fca156c7257fd6ff4bab1a0687ea1a70d3cfcc7`. The annotated tag resolves to
that commit. Its CHANGELOG entry is committed; release notes are attached to the
GitHub release, with no release-note document under `docs/`.

- [Main CI](https://github.com/darron/go-opentunnel/actions/runs/38174069499) and
  [tag CI](https://github.com/darron/go-opentunnel/actions/runs/38174078595) passed
  every job: Linux/macOS tests, vet, builds, updater tests, Linux race detection,
  full lint, current-Go vulnerability checks and sustained fuzzing.
- The published-release event ran the
  [source hook](https://github.com/darron/go-opentunnel/actions/runs/38174083463),
  which dispatched the
  [tap workflow](https://github.com/darron/homebrew-tap/actions/runs/38174089495).
  Candidate style/strict audit/source build/install/test and publishing passed.
  No manual dispatch was needed. Tap commit
  `18808593f504ffc0807803173f02ae7df5aefec9` changed only `Formula/otgo.rb`.
  Its source archive SHA-256 is
  `32fc5d56303df4d22a7f62b1c473a621c01b1df241d7309e2273011045d4004e`.
- The local stable Homebrew installation upgraded from 0.6.0 to 0.7.0.
  `brew test darron/tap/otgo`, `proxy --help` and `create --help` passed. Both
  version aliases report
  `otgo 0.7.0 sha=5fca156c7257fd6ff4bab1a0687ea1a70d3cfcc7 clean`.
  `go version -m` reports Go 1.27.2. Saved auth profiles were not changed.
- Go's public module proxy resolves `github.com/darron/go-opentunnel@v0.7.0`
  to the same release commit, with minimum source version Go 1.25.0.

Existing unbound machine-token registries require explicit reset and reissue;
[the migration guide](AUTH_PROXY.md#machine-clients-and-mcp) gives the commands.
Publication and CLI installation do not automatically reset them.

## v0.6.0 release checks — 2026-10-11

Added optional per-route PROXY v1/v2 forwarding and safe certificate diagnostics,
then increased the CLI provisioning/password-setup default to five minutes.
The package still uses the caller's startup context; request timeouts remain
separate. The advertised client version is 0.6.0 and dependencies are unchanged.

- Go 1.25.0 `go test -race -count=1 ./...` passed every package, including auth.
  Vet, full golangci-lint (**0 issues**), formatting and `git diff --check` passed.
  All seven Homebrew updater tests passed and the CLI-only `make build` succeeded.
- The new CLI deadline regression failed against the old two-minute defaults
  for create/resume/ensure/password setup, then passed after the change. It
  observes actual outgoing request contexts with a longer request budget and
  tests explicit overrides, disabled overall deadlines, parent deadlines and
  cancellation before network access. It does not wait for real timers to expire.
- Rebuilt CLI help reports `5m0s` for all four provisioning/setup paths.
- Version command regressions cover both `version` and `--version`, unexpected
  arguments and output errors. Metadata tests cover clean/dirty builds, archive
  fallback, missing or invalid metadata, and recorded VCS precedence.
- Real Go 1.25.0 binaries from an isolated clean checkout and a modified checkout
  reported the same commit as `clean` and `dirty`, respectively. Supplied linker
  values could not hide the dirty checkout. An archive built with
  `make build BUILD_REVISION=<commit> BUILD_STATE=clean` reported that commit as
  clean; the same archive without supplied metadata reported `sha=unknown unknown`.
- The [fresh-state live comparison](LIVE_TESTING.md#fresh-state-version-comparison-and-v060-live-checks--2026-10-11)
  passed v0.3.0/v0.5.0/current embedded examples and actual CLI forwarding, plus
  final direct listening and public plain/v1/v2 preambles. Fresh CLI provisioning
  took 186 seconds with `--timeout 5m`. All five owned remote identities returned
  authenticated API 404 after deletion; saved profiles and the existing proxy
  process were untouched. The first v0.5.0 attempt remained pending at 120 seconds;
  a later fresh attempt passed with a longer test window.

Earlier terminal hosted nonce failures remain unexplained. Longer pending waits
do not prove that the service's earlier failure was a timeout. These tests did
not establish the deployed server revision or induce provider rate limits.

### Publication and installed Homebrew

Published [v0.6.0](https://github.com/darron/go-opentunnel/releases/tag/v0.6.0)
from `50fcd131a7c4b5a67ed8471c3b1c174e0a0b5402`, with the CHANGELOG committed
and release notes attached to GitHub. No release-note document was added.

- [Release-commit CI](https://github.com/darron/go-opentunnel/actions/runs/38165425557)
  and [tag CI](https://github.com/darron/go-opentunnel/actions/runs/38165656413)
  passed Linux/macOS tests, vet, CLI/example builds and updater tests, plus Linux
  race detection and full lint.
- The actual release event ran the
  [source hook](https://github.com/darron/go-opentunnel/actions/runs/38165661840),
  which dispatched the
  [tap workflow](https://github.com/darron/homebrew-tap/actions/runs/38165668841).
  Its macOS style/strict audit/source build/install/test and isolated publishing
  jobs passed. No manual dispatch was used. Tap commit
  `d12cbec37b26a88f0dd34ea4bea5bfcf85e09356` changed only `Formula/otgo.rb`.
  The archive SHA-256 is
  `3b37f7dd9dec8523464932f016cdf746a14420f974c6bc8066172f8bc1626796`.
- Locally upgraded stable Homebrew from 0.5.0 to 0.6.0 and passed
  `brew test darron/tap/otgo`, `proxy --help` and `create --help`. Both version
  aliases reported `otgo 0.6.0 sha=50fcd131a7c4b5a67ed8471c3b1c174e0a0b5402 clean`.
  Create help reports the five-minute default. Older kegs were retained;
  saved profiles and the running inbox proxy were untouched.
- `go mod download -json github.com/darron/go-opentunnel@v0.6.0` succeeded and
  returned the release commit as its origin. The temporary local audit tap was
  removed after its checks.

The tap's initial generic CI run failed because its existing trust-bypass
environment variable is deprecated by Homebrew. Removed that variable and
added explicit formula trust to the release validation workflow; the release's
own validation and publishing then passed.

## v0.5.0 publication and stable Homebrew — 2026-10-10

Published [v0.5.0](https://github.com/darron/go-opentunnel/releases/tag/v0.5.0)
from `4dd2042e9e2608d51c7864c3f85a2f252e31d63d`. The CHANGELOG entry is committed;
release notes are attached to GitHub, with no release-note document in the repo.
The advertised client version is 0.5.0. Other changes since v0.4.0 are API
comments, examples and documentation; public signatures and dependencies are unchanged.

- Local `make check` passed tests, vet, formatting, full golangci-lint
  (**0 issues**) and the CLI build. Go 1.25.0 passed the runnable examples;
  all five Homebrew updater tests and `git diff --check` passed.
- [Release-commit CI](https://github.com/darron/go-opentunnel/actions/runs/38107054170)
  and [tag-triggered CI](https://github.com/darron/go-opentunnel/actions/runs/38107595731)
  passed Linux/macOS tests, vet, CLI/example builds and updater tests, plus Linux
  race detection and full lint.
- The actual release event ran the
  [source hook](https://github.com/darron/go-opentunnel/actions/runs/38107604014),
  which automatically dispatched the
  [tap workflow](https://github.com/darron/homebrew-tap/actions/runs/38107609548).
  Its macOS source build/style/strict audit/install/test and isolated publishing
  jobs passed. No manual dispatch was used. Tap commit
  `143ddb221620cef01e9fb2dde3478c2b46026841` changed only `Formula/otgo.rb`.
  The locally downloaded archive matched its SHA-256:
  `fc1fac934452fe84371d197dd4949bd30dbe94c7441cd72d7a31dd48d08658be`.
- Locally upgraded stable Homebrew from 0.4.0 to 0.5.0, built only the CLI and
  passed `brew test darron/tap/otgo`, `proxy --help` and `auth github --help`.
  `brew list --versions otgo` reports `otgo 0.4.0 0.5.0` because the old keg was
  retained; the active executable resolves to `Cellar/otgo/0.5.0/bin/otgo`.
  The upgrade did not touch saved XDG profiles.
- The public module proxy returned v0.5.0 at the release commit. After an
  indexing request, both the versioned and latest pkg.go.dev pages returned
  HTTP 200 and selected v0.5.0. Checked the startup/lifetime/trust overview and
  all five example sections. Three examples run locally; Connect/Listen are
  compiled examples. The Go Reference badge returned HTTP 200.

### Hosted retest: certificate issuance prevented completion

The first `python3 scripts/auth_smoke.py` run passed anonymous denial for every
tested method/route with zero backend requests, password login/CSRF, machine
MCP access, credential/header stripping, cookie/redirect handling, cache
protection, foreign subresource checks, eight concurrent 2 MiB uploads, corrupt
registry denial and restart/session invalidation. Revoking a machine token
closed SSE and WebSocket streams in **0.210 seconds**.

Certificate issuance failed while provisioning the second profile. A repeat
failed while provisioning its first profile. Both v0.5.0 attempts stopped all
owned processes, removed local credentials and confirmed remote removal with
API 404. The full simultaneous two-backend check did not complete.

A control using the installed v0.4.0 CLI also returned
`opentunnel: certificate issuance failed`. Its `remove` command succeeded and
the temporary directory contained no remaining files. Independent Python HTTP
inspection returned 403, so it did not establish the certificate failure reason
or independently confirm API 404 for that control. The underlying service
issuance failure remains undiagnosed; no provisioning code changed for this release.
The earlier completed public-service tests below remain the full live evidence.

## Go API documentation — 2026-10-10

Added `doc.go` with startup, lifetime, concurrency, recovery and authentication
contracts. Expanded public declaration/field comments and added local examples.
At this stage the runtime client version remained 0.4.0; these changes were
recorded under Unreleased for the planned v0.5.0.

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

## Unreleased PROXY forwarding and certificate diagnostics — 2026-10-10

Added per-route PROXY v1/v2 preambles and typed certificate failures without an
external dependency. Ordinary route forwarding, listener serving and the auth
gate retain their defaults. Runtime version remains 0.5.0 until another release.

Verified using Go 1.25.0 on macOS arm64 and golangci-lint 2.14.0:

| Check | Result |
| --- | --- |
| `GOTOOLCHAIN=go1.25.0 make check build-example` | Full tests, vet, formatting, lint and CLI/app builds passed; lint **0 issues** |
| `GOTOOLCHAIN=go1.25.0 go test -race ./... -count=1` | Full race suite passed, including password/GitHub auth regressions |
| Focused CLI, header and certificate recovery race tests | Five repetitions passed |
| `FuzzProxyPeer`, five-second smoke | **1,116,142** executions, no failures |
| Linux/Windows amd64 `go build ./...` | Passed; Windows runtime remains untested |
| Rebuilt `otgo connect --help` | New per-route flag and interactive command documented |
| Rebuilt webapp, local-only | Root response, request metadata, streamed chunks and clean SIGINT exit passed |
| Go documentation/examples | New exported contracts rendered; executable examples passed |
| Repository documentation | 143 relative Markdown links and anchors resolved |

`TestCLIProxyProtocolForwarding` runs the real CLI process through a local relay
and real TLS to prove both preambles arrive before payload, status carries copied
options, option clearing preserves existing streams, and quit exits cleanly.
Byte-for-byte checks cover all 19 peer and 12 header vectors from upstream v0.5.0.
Additional regressions cover malformed/oversized peers, bounded authority data,
plain routes, rejected updates before remote creation, TLS route mismatch before
backend dial, partial preamble writes and deadline clearing. Removing deadline
clearing made the strengthened regression fail; restoring it passed five race
repetitions. See
[the testing commands](TESTING.md#proxy-headers-and-certificate-diagnostics).

A fresh security/correctness review found a foreground recovery-cooldown path
that still returned the generic certificate sentinel. That was fixed before
final checks. New tests cover typed failures from Create, Ensure, Resume, Connect
and background refresh, raw-reason bounds, known provider classifications,
format/JSON/slog redaction and unchanged recovery submission limits. The review
found no remaining critical or important defect. Cancellation still closes the
backend before header delivery, and WriteTimeout bounds a stalled write; the
local deadline test does not simulate cancelling an entire channel during that
small preamble write.

The [single public-service attempt](LIVE_TESTING.md#unreleased-proxy-and-certificate-diagnostic-check--2026-10-10)
failed during issuance with a typed `unknown` failure, without a recognized HTTP
status. No live PROXY forwarding success is claimed. Remote cleanup was confirmed
by authenticated API 404; saved user profiles were untouched. No rate-limit
cause or hosted deployment version was established.
