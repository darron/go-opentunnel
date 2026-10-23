# Local verification record

## v0.16.0 preparation — 2026-10-22

Reviewed upstream v0.5.5/v0.6.0 against v0.5.4; the
[adoption record](UPSTREAM_COMPATIBILITY.md) explains the API additions, existing
Go 1.27.3 certificate mitigation, and service-only changes left upstream.

| Check | Result |
| --- | --- |
| Compiler and dependencies | Go 1.27.3 retained; no new Go runtime dependency |
| `make check build-example` | Full tests, vet, formatting, golangci-lint v2.15.0 and CLI/example builds passed |
| Full race suite | `go test -race -count=1 ./...` passed after the review fix |
| Focused SDK checks | Ten race-enabled repetitions passed: retry/fail startup, reconnect failure, callback isolation/serialization/shutdown, URL validation/snapshots, Ensure progress and cancellation |
| CLI integration | Real HTTP/WebSocket fixture proves valid `--on-route-conflict=fail` reaches Connect and Listen; `run(ensure)` proves progress reaches stderr and JSON stays silent. Both passed ten race-enabled repetitions |
| Release tooling | All 18 Python tests, `actionlint`, and `git diff --check` passed |
| Vulnerability scan | `govulncheck` v1.9.0 found no vulnerabilities |
| Upstream codec | Exact v0.6.0 Reader/Writer at `c23b162409425a800245245b445a4230f6346429`, SHA-256 `c49e727c9cc9b8d8085d32eb70e99004892a4e7f77031fc803ff881a78b988d1`, passed under the race detector |
| Hosted tests | Fresh SDK/PROXY and complete auth-proxy smoke tests passed; [scope and cleanup](LIVE_TESTING.md#v0160-sdk-and-auth-regression-check--2026-10-22) |

Independent correctness/security and test review found one progress-contract bug:
failed-certificate recovery omitted CSR generation and announced submission too
early. A regression reproduced it; callbacks now bracket the operations in the
correct order. Exact create/reuse/replacement/recovery sequences are tested.
The reviewer also identified missing CLI wiring coverage; real relay fixtures and
an ensure command test now cover it.

Temporary Go overlays deliberately disabled fatal reconnect conflicts and callback
route-slice copying. The respective tests failed with `conflict did not stop
reconnect` and `observer mutated buffered event or source routes`. The actual
source tree was not mutated. Go startup/Lifetime ownership and profile/auth formats
remain unchanged. Local Go/lint caches used temporary writable directories because
some host cache entries were inaccessible to the sandbox; CI checks normal runners.


## v0.15.0 publication — 2026-10-20

The [v0.15.0 release](https://github.com/darron/go-opentunnel/releases/tag/v0.15.0)
points to `767ef153377325ed321fdb2d4a2d0691bfde1c54`.

| Check | Result |
| --- | --- |
| [Release-source CI](https://github.com/darron/go-opentunnel/actions/runs/39500189016) | All five jobs passed before tagging: Linux/macOS tests, Linux race tests, lint, vulnerability scanning, exact upstream v0.5.4 codec and six sustained fuzz targets |
| [Binary publication](https://github.com/darron/go-opentunnel/actions/runs/39501053201) | All four jobs passed, including native Linux/macOS checks and Homebrew dispatch |
| Downloaded archives | All nine assets verified: combined/individual checksums, exact contents/license/modes, targets, full source SHA and `CGO_ENABLED=0`; all four binaries report compiler `go1.27.3` |
| [Homebrew](https://github.com/darron/homebrew-tap/actions/runs/39501389018) | Validation/publication passed; formula commit `8ecacf517de65b51783b0ece95ca1f9a4fdbd5d9` |
| Local install | Upgraded 0.14.3 to 0.15.0; `brew test darron/tap/otgo` passed; installed binary matches the release byte for byte |

The installed macOS arm64 executable has SHA-256
`ea5bcfebfa812568273f5edeef89f880eb389278102a1de1badcd7386eb9f104`.
Its version is `otgo 0.15.0 sha=767ef153377325ed321fdb2d4a2d0691bfde1c54 clean`.

Restart existing otgo processes after upgrading. Embedded applications need their
own rebuild with patched Go to update their standard library. The adoption and
test-scope limits are documented in [UPSTREAM_COMPATIBILITY.md](UPSTREAM_COMPATIBILITY.md);
no hosted service, personal tunnel or live GitHub login was changed or tested
for this release.


## v0.15.0 preparation — 2026-10-20

Reviewed the canonical OpenTunnel v0.5.2…v0.5.4 changes. The
[adoption record](UPSTREAM_COMPATIBILITY.md) separates client work from server-only
changes. No public tunnel, personal profile or GitHub App was changed by these checks.

| Check | Result |
| --- | --- |
| Compiler | Go 1.27.3; release/CI pins retained from v0.14.3 |
| `make check build-example` | Full tests, vet, formatting, golangci-lint v2.15.0 and CLI/example builds passed |
| Complete lint output | `golangci-lint run --max-same-issues 0 --max-issues-per-linter 0 ./...`: 0 issues |
| Release tooling | All 18 Python tests, `actionlint` and `git diff --check` passed |
| Vulnerability scan | `govulncheck` v1.9.0 found no vulnerabilities |
| Native CLI | Built binary reports v0.15.0 and compiler Go 1.27.3 |
| Race suite | `go test -race -count=1 ./...`: all packages passed |
| Upstream codec | Exact v0.5.4 Reader/Writer, commit `8e6f7ed6da49d524b46ff27d6704879725c40300`, SHA-256 `c49e727c9cc9b8d8085d32eb70e99004892a4e7f77031fc803ff881a78b988d1`, passed under the Go race detector |
| New regression coverage | Real WebSocket priority/overload, exact 64 KiB attach and 32 KiB data boundaries, oversize reconnect, route validation/update preservation, retryable `too_many_routes`, and create/bind 429/503 diagnostics |
| Existing burst coverage | Race-enabled 5,000-control bursts and failed-handshake/teardown interaction passed without reattachment |

The new tests first exposed the previous blocked reader-control admission, queued
data overtaking pongs, oversized bridge acceptance, route-limit provisioning and
loss of the new diagnostic tags. The revised behavior passed the focused race
checks. An independent security/correctness review found no production blockers.
It identified a boundary-test loophole: a fallback attachment could hide failure
to accept the exact-size frame. The corrected test requires a matching pong on
the first attachment and checks the attempt count; ten race-enabled repetitions
passed. The oversized branch requires close status 1009 and successful replacement
attachment. A temporary Go overlay restoring the old 1 MiB attach limit made
that regression fail with the missing oversize close; the source tree was not
mutated. Ten race-enabled repetitions of the complete new focused group passed.

The newer Rust codec uses `tokio::time`; the locked test adapter now enables that
feature. This adds no Go runtime dependency. The codec adapter tests framing;
it does not exercise the complete hosted server, database or CA. Authentication,
profile formats and identity assertions are unchanged.

## v0.14.3 publication — 2026-10-20

The [v0.14.3 release](https://github.com/darron/go-opentunnel/releases/tag/v0.14.3)
points to `ee32736f3c274e759ba09a7cc8713500aa1f96ba`.

| Check | Result |
| --- | --- |
| [Release-source CI](https://github.com/darron/go-opentunnel/actions/runs/39497085555) | All five jobs passed before tagging, including Linux race tests, macOS, lint, vulnerability scanning, the pinned upstream codec and six sustained fuzz targets |
| [Binary publication](https://github.com/darron/go-opentunnel/actions/runs/39497935170) | All four jobs passed, including native Linux/macOS execution and Homebrew dispatch |
| Downloaded archives | All nine assets verified: combined/individual checksums, exact contents/license/modes, target, full source SHA and `CGO_ENABLED=0`; all four binaries report compiler `go1.27.3` |
| [Homebrew](https://github.com/darron/homebrew-tap/actions/runs/39498241381) | Validation and publication passed; formula commit `ecd721789dbfce4b666a058c398536c1c45025e1` |
| Local install | Upgraded 0.14.2 to 0.14.3; `brew test darron/tap/otgo` passed; installed binary matches the release byte for byte and reports `go1.27.3` |

The installed macOS arm64 executable has SHA-256
`0b38269552ba98d0a058d95f60a4e4314e248af2cdf0682508805c6e6b0eb281`.
Its version is `otgo 0.14.3 sha=ee32736f3c274e759ba09a7cc8713500aa1f96ba clean`.
Restart existing otgo processes after upgrading. Embedded applications need their
own rebuild with a patched compiler; the library module cannot replace a running
application's standard library. No hosted-service or live GitHub login test was
needed for this compiler/configuration release.


## v0.14.3 preparation — 2026-10-20

Security rebuild for the Go `crypto/x509` mitigation
[CVE-2026-111943](https://github.com/golang/go/issues/82345). CI and release builds
pin Go 1.27.3 with `GOTOOLCHAIN=local`; release packaging also checks the compiler
version before building. Checkout builds select Go 1.27.3 through the toolchain
directive. Source compatibility remains Go 1.26; embedding applications must be
rebuilt with a patched compiler to receive the standard-library fix.

| Check | Result |
| --- | --- |
| Local compiler | `go version go1.27.3 darwin/arm64`; CLI build metadata also reports `go1.27.3` |
| `make check build-example` | Full tests, vet, formatting, golangci-lint v2.15.0 and CLI/example builds passed |
| Complete lint output | `golangci-lint run --max-same-issues 0 --max-issues-per-linter 0 ./...`: 0 issues |
| Race suite | `go test -race ./... -count=1`: all packages passed |
| Release tooling | All 18 Python tests, `actionlint` and `git diff --check` passed |
| Vulnerability scan | `govulncheck` v1.9.0 on Go 1.27.3 found no vulnerabilities |
| CLI/example smoke | Built CLI reports v0.14.3; example help and signed-identity options passed |

The first Linux CI race pass exposed a fixture ordering bug in
`TestLifecycleRenewalSaveCannotResurrectRemovedIdentity`: the test published a new
certificate before arming its Save barrier. A temporary Go overlay forced that
schedule and reproduced the exact failure. The barrier is now armed while the
fixture API lock still prevents refresh from observing the replacement. Runtime
code and the removal/renewal assertions are unchanged. The corrected test passed
100 race-enabled repetitions. Removing the production profile lock with another
temporary overlay made the test fail because Remove completed while Save was
blocked, confirming that the synchronization fix preserves its regression value.
The full checks and root-package race suite were rerun after this test-only fix.

These checks use local fixtures. No public tunnel, personal profile or GitHub
login was created or changed. The release changes the compiler and delivery
configuration, without changing the client API, authentication or wire protocol.


## v0.14.2 publication — 2026-10-17

The annotated [v0.14.2 release](https://github.com/darron/go-opentunnel/releases/tag/v0.14.2)
points to `0de13c2231322629bc4abd93b73661a018fe208f`. Release notes are on GitHub; the dated
entry is in [CHANGELOG.md](../CHANGELOG.md).

| Check | Result |
| --- | --- |
| [Release-source CI](https://github.com/darron/go-opentunnel/actions/runs/39076015892) | All five jobs passed before tagging: Linux/macOS tests, Linux race suite, pinned upstream codec, v2.15.0 lint, current-Go security checks and six sustained fuzz targets |
| [Binary publication](https://github.com/darron/go-opentunnel/actions/runs/39076406993) | All four jobs passed, including native Linux/macOS checks, asset publication and Homebrew dispatch |
| Downloaded assets | Exactly nine files; all combined/individual SHA-256 checks, exact archive contents/license/modes, target, revision and CGO metadata passed |
| Native downloaded CLI | Reports v0.14.2, the full release SHA and clean state; general, proxy, profiles, public-key and offline-verifier help checks passed |
| [Homebrew update](https://github.com/darron/homebrew-tap/actions/runs/39076556341) | Validation and fresh-runner publication passed; formula commit `0d25356010518e9567e029ad4f0b6cef03bb61ac` matches all four archive checksums and the release SHA |
| Local Homebrew installation | Upgraded 0.14.1 to 0.14.2 from the release archive; `brew test darron/tap/otgo` passed |
| Installed/released comparison | Byte-for-byte equality passed; both macOS arm64 executables have SHA-256 `9f50a3dd8a45ae915bf4d7d6e68fafc16e25573ded7ec757e034340f219f766b` |
| Public Go module | Resolves v0.14.2 to the exact release commit and includes the verified-auth example and walkthrough |

The installed binary reports
`otgo 0.14.2 sha=0de13c2231322629bc4abd93b73661a018fe208f clean`.
Linux arm64 and macOS amd64 binaries were inspected rather than executed locally;
native Linux amd64 and macOS arm64 checks passed in the release workflow. Existing
profiles were unchanged. The local browser fixture results and their scope are
recorded in the preparation entry below.

## v0.14.2 preparation — 2026-10-17

CI now pins golangci-lint **v2.15.0**. Its newer errcheck checks receives from
error channels. Reviewed all 15 findings: these sites intentionally join shutdown,
cancellation or test completion without asserting the returned error. Each now
has a line-specific `nolint:errcheck` with its reason. Both errcheck and staticcheck
remain enabled; no global exclusions or runtime behavior changes were added.

| Check | Result |
| --- | --- |
| `golangci-lint config verify` | Passed with v2.15.0 |
| Full lint, without issue-count limits | `golangci-lint run --max-same-issues 0 --max-issues-per-linter 0 ./...`: **0 issues** |
| `make check build-example` | Full tests, vet, formatting, v2.15.0 lint and both builds passed |
| Final race suite | `go test -race ./... -count=1`: all packages passed after the version update |
| Release checks | All 18 Python release-tool tests, `actionlint`, all 212 relative file links across 28 Markdown files and `git diff --check` passed; `govulncheck` v1.9.0 found no vulnerabilities |
| Focused example regressions | Invalid assertions, verified user/streaming and real HTTP/WebSocket tests passed with verbose output |
| Browser fixture demo | Actual built webapp returned `200` with verified user JSON for a current assertion; an untrusted signature, expired assertion and absent assertion each returned `401` with `GitHub sign-in required` |
| Direct backend request | Without the fixture adapter or a signed assertion, `/whoami` returned `401` |
| Chrome | The localhost demo displayed all four expected backend results; DOM assertions and visual screenshot inspection passed |

The temporary demo uses a separate localhost adapter to sign requests with
ephemeral test keys. Its username and ID are fixture data, not a new GitHub
authorization. The adapter source and keys are outside the repository. No personal
profiles or credentials were used, and no public tunnel was created.

## Verified-identity webapp example — 2026-10-17

The optional identity mode wraps every example route with the strict backend
verifier and returns the verified GitHub login and numeric ID at `/whoami`.
Without identity flags, the original unauthenticated demonstration is unchanged.

| Check | Result |
| --- | --- |
| Test-first access boundary | Before the verifier was added, unsigned requests reached the handlers; route/method denial regressions failed, then passed with the gate |
| `make check build-example` | Full suite, vet, formatting, golangci-lint v2.14.0 **0 issues**, CLI and example builds passed on Go 1.27.2 |
| Race checks | `go test -race ./... -count=1` passed; the final example changes also passed a focused race rerun |
| Signed request fixtures | Independently signed current assertions succeed; expired assertions, wrong keys/audiences, changed methods/targets, forged usernames and duplicate assertions are rejected |
| Real HTTP and WebSockets | `/whoami` returned the signed user over HTTP; unsigned WebSocket admission failed and a signed WebSocket echoed a message |
| Streams and configuration | Signed streaming still flushes all chunks; partial/explicitly empty identity flags, invalid origins, missing files and invalid keys fail closed |
| Built example CLI | Help lists the identity flags; the wrong run mode, incomplete/empty configuration and a missing public key all exit nonzero before serving |
| Expiry mutation control | A temporary Go overlay replacing `VerifyRequest` with `InspectRequest` made the expired-assertion test fail; the checkout was unchanged |
| Documentation | Relative links in the updated guides and `git diff --check` passed |

The initial lint pass used the repository's then-pinned v2.14.0. Local v2.15.0 reported
pre-existing channel-receive errcheck findings that conflict with staticcheck's
blank-assignment rule. The subsequent upgrade and its resolution are recorded above.
These checks used local fixtures, without reading personal profiles, creating a
public tunnel or repeating GitHub browser authorization. The browser walkthrough
is documented for a separate live check.

## v0.14.1 preparation — 2026-10-16

The new offline `auth verify` command checks the selected profile's pinned key
and the same signed request fields as backend verification. Expired assertions
report their signed timestamps and `ValidNow: false`; `--require-current` rejects
them. Backend `identity.VerifyRequest` continues to reject expired assertions.
The separate diagnostic `identity.InspectRequest` does not authorize access.

| Check | Result |
| --- | --- |
| Test-first CLI coverage | Valid assertion tests failed with `unknown auth command` before implementation; the expiry change first failed on expired acceptance and missing current-validity reporting, then passed |
| `make check build-example` | Full suite, vet, formatting, golangci-lint **0 issues**, CLI and example builds passed |
| `go test -race ./... -count=1` | All packages passed |
| CLI and verifier regressions | Current/expired assertions, strict expiry, wrong signatures/keys/issuer/audience/method/escaped target/query, future issuance and not-before, invalid lifetimes, forged companion headers, HTTP/HTTPS, text/JSON, bounded stdin and read errors passed |
| Stored keys | Missing/unpinned/corrupt/unsafe/foreign/mismatched keys rejected; verification leaves profile config/key bytes unchanged and does not create a missing key |
| Signed identity/inspection fuzz | 45 seconds, two workers, **2,888,506 executions**, passed with current and expired positive controls and independent request mutations |
| Vulnerabilities | `govulncheck` v1.9.0: no vulnerabilities found |
| Release tooling and docs | All 18 Python release-tool tests passed; tracked Markdown relative file links and `git diff --check` passed |
| Test mutation controls | Temporary Go overlays that misreported expired text or disabled strict expiry each caused the intended regression test to fail; checkout files were unchanged |
| Independent reviews | Claude and Amp/Oracle found no security blockers; review follow-ups added expired text/strict-error checks, accurate issued-at labeling for later not-before claims, stale-key-state preservation and a signed-target binding regression |
| Actual captured assertion | The rebuilt executable verified the user's previously captured assertion against the existing local profile, reported expiry in text and JSON, and rejected strict expiry, a changed method and a forged username |

The captured assertion and private profile material are not stored in the repo.
The command made no service requests, created no public tunnel and did not change
the running proxy. This patch's live check is cryptographic verification of an
existing capture, not a new GitHub authorization/browser session. Earlier hosted
transport and authentication results retain their original release scope below.


## v0.14.0 publication — 2026-10-16

The annotated [v0.14.0 release](https://github.com/darron/go-opentunnel/releases/tag/v0.14.0)
points to `160589d55ab1c1ff3006500e8d7187636f9ab500`. The release notes are on
GitHub and the dated entry is in [CHANGELOG.md](../CHANGELOG.md).

| Check | Result |
| --- | --- |
| [Final-source CI](https://github.com/darron/go-opentunnel/actions/runs/38998172464) | All five jobs passed before tagging: Linux/macOS tests, Linux race suite, pinned upstream codec, lint, current-Go security checks and six sustained fuzz targets |
| Independent reviews | Claude and Amp/Oracle confirmed the security/correctness fixes and the final fuzz-harness correction; no remaining release blocker |
| [Binary publication and dispatch](https://github.com/darron/go-opentunnel/actions/runs/38998547974) | Four archives and five checksum files published after native Linux/macOS checks; automatic Homebrew dispatch succeeded |
| Downloaded assets | Exactly nine files; all combined/individual SHA-256 checks, exact archive contents/license/modes, embedded release SHA, target and CGO metadata passed |
| Native downloaded CLI | Reports v0.14.0, full release SHA and clean state; general, proxy, profiles and public-key help checks passed |
| [Tap update](https://github.com/darron/homebrew-tap/actions/runs/38998690661) | Validation and fresh-runner publication passed; commit `57989ccb2e5458c9fd3611a3ebfa502a31129ce5` updated the binary formula to v0.14.0 |
| Local Homebrew installation | Upgraded 0.13.0 to 0.14.0 from the release archive; `brew test darron/tap/otgo` passed |
| Installed/released comparison | Byte-for-byte comparison passed; both macOS arm64 executables have SHA-256 `f9afaaa27617ffb421fcc46bf674113f6e57302b212b52c8889b51909b1ca252` |
| Public Go module | The public module proxy serves v0.14.0 at the exact release commit, including the optional `identity` package |

The installed binary reports
`otgo 0.14.0 sha=160589d55ab1c1ff3006500e8d7187636f9ab500 clean`.
Linux arm64 and macOS amd64 binaries were inspected rather than executed locally;
native Linux amd64 and macOS arm64 checks passed in the release workflow. Both
Linux executables are statically linked. Existing profiles and running proxies
were untouched. Hosted checks and their limits are recorded below and in
[Live testing](LIVE_TESTING.md#v0140-qr-and-identity-regression-check--2026-10-16).

## v0.14.0 preparation — 2026-10-16

Go 1.27.2 on macOS arm64; minimum supported Go remains 1.26. The core client
API and OpenTunnel wire protocol are unchanged. QR rendering is CLI-only; the
new optional `identity` package verifies backend assertions with pinned keys.

| Check | Result |
| --- | --- |
| `make check build-example` | Full tests, vet, formatting, golangci-lint **0 issues**, CLI and example builds passed after review fixes |
| `go test -race ./... -count=1` | Full race suite passed after the request-target and key-scope corrections |
| GitHub identity integration | Fixture OAuth callback, authenticated session, actual backend verification, forged/duplicate/case-varied headers, Connection nominations, late trailers, signed WebSocket admission and concurrent user isolation passed |
| Credential isolation | Password and machine-token requests carry no GitHub identity; machine-token precedence also tested with a valid GitHub session cookie |
| Request binding | Wrong key/issuer/audience/Host/TLS scheme/method/path/query, expired/future assertions, duplicate headers and unsupported algorithms rejected; an 8 KiB query verifies without growing the JWT |
| Raw HTTP parser regression | A signature for `/a%23b` admits that target but rejects `/a#b` and absolute-form aliases parsed by Go's real HTTP parser |
| Signing-key lifecycle | Stable offline export, running-proxy export, fingerprint checks, missing/corrupt/unsafe keys, changed backend/stale export metadata, reset and token-file collision checks passed |
| Terminal output | Independently decoded rendered QR cells match only the public HTTPS URL; JSON remains clean even with forced QR; a compiled test binary under a real PTY passed automatic detection and `TERM=dumb` suppression |
| Upstream compatibility | Exact pinned v0.5.2 WebSocket codec passed under the Go race detector; commit `9f451413341c502c40c6a55e51cb5ee0a5b60cb1`, source SHA-256 `c55cd51cee51926091202b43a7a7c4cb7dc24e7f1211a377a879610e813025f1` |
| Sustained fuzzing | All six 45-second targets passed; identity fuzzing was repeated with a worker-stable positive control, freshly signed per case so expiry cannot weaken request-binding coverage |
| Tooling | `govulncheck` found no vulnerabilities; all 18 Python release-tool tests, Actionlint and diff checks passed |
| API/docs | Go documentation renders, compiling examples pass, and 202 local Markdown file links resolve |

Review fixes were reproduced with failing regressions before implementation:
require a GitHub signing key, bind stored keys to the backend, reject stale
export metadata and transport scheme mismatches, and keep token files separate
from signing keys. Review also exposed long-URL assertion inflation and raw
request-target aliasing. Assertions now carry a fixed-size SHA-256 target digest;
the verifier checks the original server request target before hashing it.

Claude's focused confirmation recommended shipping after green gates. Amp
rechecked the corrected code with Oracle and reported no remaining P0/P1/P2
finding or launch blocker. An additional security pass found no remaining
critical or important issue. Review transcripts remained outside the repository.
The suggested positive terminal-detection check was added and passed under a PTY.
The full hosted smoke test also passed again after the fixes, including cleanup.
A final fuzz-harness check replaced the random serialized seed with a stable
marker signed inside each worker and required valid requests to succeed. The
positive control failed before the fixture correction, then passed under race
and sustained fuzzing; an overlay mutation that rejects every request was also
caught. Production code was unchanged by this test-only correction.

The public assertion proves profile testimony about a GitHub login. Bodies,
one-time replay prevention and continuous stream-message identity remain outside
its scope; validity is at most 30 seconds and clocks must be synchronized.
An HTTPS audience requires TLS at the verifier. New pinned-key config fields
require a protected pre-upgrade config backup for rollback to an older CLI.
See [signed identity](AUTH_PROXY.md#signed-backend-identity) for the full contract
and [live results](LIVE_TESTING.md#v0140-qr-and-identity-regression-check--2026-10-16)
for hosted checks, cleanup and limits.

## v0.13.0 publication — 2026-10-16

The annotated [v0.13.0 release](https://github.com/darron/go-opentunnel/releases/tag/v0.13.0)
points to `caec102691d804485f93804b316da3b953c3ae20`. Release notes are on
GitHub; the dated changes are in [CHANGELOG.md](../CHANGELOG.md). No Go runtime
dependency or tunnel wire-protocol change was added.

| Check | Result |
| --- | --- |
| [Release-commit CI](https://github.com/darron/go-opentunnel/actions/runs/38940456005) | Linux/macOS tests, Linux race suite, pinned upstream codec, lint, current-Go vulnerability checks and all five sustained fuzz targets passed before tagging |
| [Binary publication and dispatch](https://github.com/darron/go-opentunnel/actions/runs/38943941597) | Four archives and five checksum files published after native Linux/macOS checks; automatic Homebrew dispatch succeeded |
| Downloaded release assets | Exactly nine files; combined/individual SHA-256 checks, archive contents, embedded revision and all target/CGO metadata passed |
| Downloaded native CLI | Exact v0.13.0 version, full release SHA and clean state; general, proxy, profiles and both auth setup help checks passed, including the CA option |
| [Tap update](https://github.com/darron/homebrew-tap/actions/runs/38944110976) | Validation and fresh-runner publishing passed; commit `28e33a1f07e246ff70036882aa3b1a61f672fe67` changed only `Formula/otgo.rb` |
| Local Homebrew upgrade | Upgraded 0.12.0 to 0.13.0 from the release archive; `brew test darron/tap/otgo` passed |
| Installed/released comparison | `cmp` passed; both macOS arm64 executables have SHA-256 `960daf0780feddac7063e4725dd1e5d1953d66d6dac117615eb8670a62ec8414` |
| Independent reviews | Claude and Amp/Oracle confirmed the GitHub configuration fix and the CI-discovered test-fixture corrections; focused race checks passed with no remaining blocker |

The installed CLI reports
`otgo 0.13.0 sha=caec102691d804485f93804b316da3b953c3ae20 clean`.
Linux arm64 and macOS amd64 binaries were inspected rather than executed locally;
native Linux amd64 and macOS arm64 checks passed in the release workflow. Both
Linux binaries are statically linked. Existing saved profiles and running proxies
were untouched. Hosted-service results and the exact limits of the upstream codec
check are recorded in the preparation section below and [live results](LIVE_TESTING.md#v0130-custom-ca-and-hosted-regression-check--2026-10-16).

## v0.13.0 custom CA preparation — 2026-10-16

Go 1.27.2 on macOS arm64. The library and CLI share added CA trust for API
HTTPS and relay WSS; visitor TLS, backend HTTPS and GitHub trust stay separate.
No Go runtime dependency was added.

| Check | Result |
| --- | --- |
| `make check build-example` | Full tests, vet, formatting, golangci-lint **0 issues**, CLI and example builds passed |
| `go test -race ./... -count=1` | Full race suite passed after the GitHub setup fix |
| New CA integration tests | Real HTTPS provisioning, WSS relay attachment and separately verified visitor TLS; hostname/untrusted rejection and cross-origin redirect denial passed |
| Real CLI subprocess test | `auth init` saved the CA; proxy startup/restart without a CA flag or variable worked; anonymous MCP denied and machine bearer accepted |
| Config and GitHub regression tests | Flag/env/saved precedence, explicit empty option, absolute paths, quoted launch/resume commands, retained/changed/cleared CA and provider trust isolation passed |
| Failure-before-commit regression | Reproduced premature CA persistence with a failing test, then fixed it; failed setup and cancelled conversion preserve the config byte for byte |
| PEM regression | A malformed block followed by a valid one failed the new test before the parser fix; strict blocks, multiple certificates, bounds and invalid file types now pass |
| `python3 scripts/upstream_compat.py` | Exact pinned upstream v0.5.2 Reader/Writer passed text/binary fragmentation, interleaved pings, size boundaries and close checks under the Go race detector |
| `make fuzz-sustained` | All five 45-second targets passed, approximately 6.1 million executions combined |
| Vulnerability and release tooling | `govulncheck` found no vulnerabilities; all 18 Python release-tool tests and Actionlint passed |
| Hosted CLI and local example | [Public-service auth checks, cleanup, HTTP streaming and WebSocket echo passed](LIVE_TESTING.md#v0130-custom-ca-and-hosted-regression-check--2026-10-16) |

Claude and Amp/Oracle independently found the premature GitHub CA persistence
issue (P2), with no P0/P1 findings. The fix stages the CA in memory and commits
it alongside approved GitHub credentials. Added tests cover failed provider
requests, cancellation during conversion and successful retain/replace/clear.
Both reviewers confirmed the fix with focused tests, including race checks,
and reported no remaining release blocker. A final test also exercises the
legacy TLS dial hook, addressing Amp's remaining coverage note.
Custom TLS dialers are rejected because they bypass `TLSClientConfig`; the
legacy hook check has a narrow deprecation-lint annotation.

The first Linux CI run caught an existing relay-fixture teardown race: cleanup
could wait on a session before its HTTP handler registered the first worker.
Fixture and session shutdown now prevent late registration, and all worker
registrations share the session lock with shutdown. This changes test code only.
The full local race suite and 1,000 repetitions of the affected test passed.
Claude and Amp/Oracle also caught an existing failure-path worker reservation;
failed channel-open control writes now balance it and close both sockets before
reporting the test failure, so cleanup can finish. Both confirmed the correction;
repeated focused race tests and lint passed afterward.

The compatibility test uses the actual upstream codec, not the full Rust server,
database or ACME service. Hosted checks do not establish the operator's deployed
revision. No new GitHub App grant was created for this release. Hosted tests used
owned temporary identities and confirmed remote deletion; existing profiles and
running proxies were untouched.


## v0.12.0 publication — 2026-10-14

The annotated [v0.12.0 release](https://github.com/darron/go-opentunnel/releases/tag/v0.12.0)
points to `12d58b03b7faace29132de5b72e2b95674a38eb1`. Homebrew installs the
published CLI executable rather than compiling it. The API and tunnel protocol
are unchanged.

| Check | Result |
| --- | --- |
| [Release-commit CI](https://github.com/darron/go-opentunnel/actions/runs/38599293781) | Linux/macOS tests, Linux race suite, lint, current-Go vulnerability checks and all five sustained fuzz targets passed before tagging |
| [Legacy formula migration](https://github.com/darron/homebrew-tap/actions/runs/38599277664) | Published v0.11.0 binaries passed checksum checks, all four formula target evaluations, style/audit, native installation, formula tests and installed/released byte comparison |
| [Binary publication and dispatch](https://github.com/darron/go-opentunnel/actions/runs/38600038872) | All four archives and five checksum files published after native Linux/macOS checks; automatic Homebrew dispatch succeeded afterward |
| Downloaded release assets | Exactly nine files; combined/individual SHA-256 checks, archive contents and all target/CGO metadata passed |
| Downloaded native CLI | Exact v0.12.0 version, full release SHA and clean state; general, proxy, profiles and both auth setup help checks passed |
| [v0.12.0 tap update](https://github.com/darron/homebrew-tap/actions/runs/38600211495) | Validation and fresh-runner publishing passed; commit `0b3f7f330c17f46be97b8db120337ab741453fb2` changed only `Formula/otgo.rb` |
| Local Homebrew upgrade | Upgraded 0.11.0 to 0.12.0 from the release archive; `brew test darron/tap/otgo` passed |
| Installed/released comparison | `cmp` passed; both macOS arm64 executables have SHA-256 `630b8c36d956a15b9932ba8bd1e091927a448bfe677b226b11c62fadc5a21149` |
| Independent review | Both important findings and documentation feedback fixed and rechecked; 18 root and 9 tap Python tests plus workflow checks passed, with no remaining findings |
| Documentation links | All 186 local Markdown file links resolved before publication |

The installed CLI reports
`otgo 0.12.0 sha=12d58b03b7faace29132de5b72e2b95674a38eb1 clean`.
Linux arm64 and macOS amd64 binaries were inspected rather than executed locally;
native Linux amd64 and macOS arm64 checks passed in the release workflow.
The owned temporary local test tap was removed. Saved user profiles and running
proxies were untouched. This packaging release did not repeat hosted tunnel tests;
the previous hosted authentication/long-poll record remains below.

## v0.12.0 binary Homebrew preparation — 2026-10-14

Go 1.27.2 on macOS arm64: `make check` passed full tests, vet, formatting,
golangci-lint (0 issues) and the CLI build. All 18 Python release-tooling tests
and both workflow Actionlint checks passed. Homebrew style, strict audit and
real formula evaluation selected the expected URL and checksum for all four
targets using the published v0.11.0 archives.

Independent review identified permissive legacy-formula migration and a missing
stable-release recheck on the publishing runner. Both were fixed. New regressions
failed before the migration fix and pass afterward: manual source changes are
preserved by refusing migration, and same-version binary metadata cannot change.
The publisher rechecks release stability, tag revision and the validated formula
hash on a fresh runner. Script copies in the source and tap repos match.

New ACME diagnostic fixtures cover the hostname-prefixed DNS and unauthorized
messages in upstream's server recovery change. No production client behavior
changed apart from the release version. This packaging pass does not claim a new
hosted tunnel test; v0.11.0's hosted results remain recorded below.

## v0.11.0 long polling and publication — 2026-10-13

The annotated tag and [release](https://github.com/darron/go-opentunnel/releases/tag/v0.11.0)
point to `14620a57b0fe2dc88860304df90093cc24da09f5`. The auth proxy now waits
for backend headers without a 15-second deadline; request cancellation,
credential lifetime, shutdown and capacity limits remain in effect.

| Check | Result |
| --- | --- |
| Local checks | Go 1.27.2 `make check` passed: full tests, vet, formatting, lint (0 issues) and CLI build; all 16 release-tooling tests and `actionlint` passed |
| Long-poll race regressions | Delayed headers and pending-request cancellation on client cancellation, session revocation and handler shutdown passed |
| Regression sensitivity | Restoring the former deadline in an isolated temporary checkout made the delayed-header test fail with HTTP 502; the fixed source passed |
| [Release-commit CI](https://github.com/darron/go-opentunnel/actions/runs/38438527691) | Linux/macOS tests, race checks, lint, vulnerability checks and sustained fuzzing passed before tagging |
| [Binary publication](https://github.com/darron/go-opentunnel/actions/runs/38439335733) | Four archives and five checksum files published after native Linux/macOS checks |
| Downloaded assets | All nine present; archive contents and combined/individual SHA-256 checks passed; expected target/CGO metadata and release SHA verified |
| Native downloaded CLI | macOS arm64 reported the exact version, release SHA and `clean`; five command help checks passed |
| [Homebrew dispatch](https://github.com/darron/go-opentunnel/actions/runs/38439335640) and [tap workflow](https://github.com/darron/homebrew-tap/actions/runs/38439356971) | Passed; tap commit `a6c5814744cf0cadc3a3da699ad208ca28a69fcf` changed only `Formula/otgo.rb` |
| Local Homebrew upgrade/test | Source build and formula tests passed; installed CLI reported `otgo 0.11.0 sha=14620a57b0fe2dc88860304df90093cc24da09f5 clean` |
| Hosted auth smoke | Complete fresh-state run passed, including a 16.476-second wait for headers and confirmed cleanup; see [live results](LIVE_TESTING.md) |

The temporary mutation did not alter the release checkout. Linux arm64 and
macOS amd64 binaries were inspected but not executed locally; native Linux amd64
and macOS arm64 checks passed in the workflow. Existing saved profiles and
running proxies were untouched. Release notes remain on GitHub, and the dated
changes are in [CHANGELOG.md](../CHANGELOG.md).

## v0.10.0 publication — 2026-10-13

The annotated tag and [release](https://github.com/darron/go-opentunnel/releases/tag/v0.10.0)
point to `26886fc92cfdc5885b07ecb644c4a25d2726a203`. Release notes are attached
to GitHub; the dated changes are in [CHANGELOG.md](../CHANGELOG.md).

| Check | Result |
| --- | --- |
| Local release checks | `make check` passed, including full tests, vet, formatting, lint (0 issues) and CLI build; all 16 release-tooling tests and `actionlint` passed |
| [Release-commit CI](https://github.com/darron/go-opentunnel/actions/runs/38420603264) | Linux/macOS tests, race checks, lint, vulnerability checks and sustained fuzzing passed before tagging |
| [Binary publication](https://github.com/darron/go-opentunnel/actions/runs/38421364739) | Four CLI archives and five checksum files published after Linux/macOS native checks |
| Downloaded assets | All nine assets present; archive contents, combined and individual SHA-256 checks passed |
| Downloaded native CLI | macOS arm64 reported the exact version, full release SHA and `clean`; general, proxy, profiles and both auth setup help checks passed |
| [Homebrew dispatch](https://github.com/darron/go-opentunnel/actions/runs/38421364738) and [tap workflow](https://github.com/darron/homebrew-tap/actions/runs/38421381300) | Passed; tap commit `f0b89c9b3c29a71bb28060d3302c5fa004df3bc8` changed only `Formula/otgo.rb` |
| Local Homebrew upgrade | Source build and `brew test darron/tap/otgo` passed; installed CLI reported `otgo 0.10.0 sha=26886fc92cfdc5885b07ecb644c4a25d2726a203 clean` |
| Hosted release-version check | Fresh-state auth smoke passed with the CLI advertising 0.10.0, including confirmed deletion of both temporary tunnels; see [live results](LIVE_TESTING.md) |

All four downloaded binaries had the expected architecture and Go target/CGO
metadata, with the release SHA embedded. Linux executables are statically linked.
Linux amd64 and macOS arm64 execution were checked in the workflow; Linux arm64
and macOS amd64 were inspected but not executed locally. Existing saved profiles
and running proxies were untouched.

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
