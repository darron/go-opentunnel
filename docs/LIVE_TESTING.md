# Public-service validation

## v0.16.2 outbound proxy regression check — 2026-10-23

Both hosted smoke suites passed with ALL_PROXY pointing to a temporary local
HTTP CONNECT proxy requiring Basic authentication. HTTPS_PROXY/HTTP_PROXY were
unset; NO_PROXY covered loopback backends. The proxy forwarded encrypted TLS and
permitted only OpenTunnel destinations on port 443. It observed four authenticated
CONNECTs for the SDK suite and twelve for the CLI auth suite, with zero proxy
authentication failures.

- `go run ./scripts/proxy-smoke`: fresh in-memory provisioning/reuse progress,
  startup events and URL helpers, a typed fatal route conflict while the first
  connection stayed usable, and public HTTPS forwarding through plain/PROXY
  v1/PROXY v2 backends. Temporary remote deletion was confirmed by API 404.
- Rebuilt CLI with `python3 scripts/auth_smoke.py`: anonymous methods/routes,
  MCP and discovery denied with zero backend calls; password/machine auth,
  cookies, origin/CSRF, header stripping, cache policy, eight concurrent 2 MiB
  uploads, corrupt-registry denial, restart/logout and two isolated profiles
  passed. Revocation closed SSE/WebSocket streams in 0.287 seconds. All owned
  processes stopped, temporary local credentials were removed and API 404
  confirmed both remote deletions.

No personal profile or running proxy was changed. No live GitHub App grant was
made; the full local regression suite covers GitHub auth. Local fixtures separately
verify HTTPS proxies, SOCKS, bypasses, malformed replies and failure recovery.
The final case-insensitive localhost bypass was subsequently verified with a
real local HTTP origin and a proxy asserting zero requests. The hosted service's
deployed source revision is not observable.


## v0.16.0 SDK and auth regression check — 2026-10-22

`go run ./scripts/proxy-smoke` passed against the hosted service with a fresh
in-memory identity. `EnsureWithOptions` reported provisioning readiness and then
`checking-certificate`/`ready` on reuse. The startup observer saw `connected` before
Connect returned; `URLs()` matched `PublicURL`. A separate client using the same
temporary credentials received the expected typed `route_conflict` with fail
policy while the first connection stayed usable. Public HTTPS forwarding passed
with plain, PROXY v1 and PROXY v2 backends. Authenticated API 404 confirmed deletion
of the temporary tunnel.

The rebuilt v0.16.0 CLI also passed `python3 scripts/auth_smoke.py` using isolated
private state. Every anonymous method/path, MCP and discovery probe was denied
with zero backend hits. Password, machine tokens, secure cookies, origin/CSRF,
header stripping, cache controls, eight concurrent 2 MiB uploads, corrupt-registry
denial, restart/logout and two simultaneous profiles passed. Revocation closed
SSE and WebSocket streams in 0.243 seconds. All owned processes stopped; local
credentials were removed and API 404 confirmed both remote deletions.

No personal profile or running proxy was changed. No live GitHub App grant was
made; GitHub auth is covered by the existing local regression suite. Hosted
behavior is verified, but the service's deployed source revision is not observable.


## v0.14.0 QR and identity regression check — 2026-10-16

The rebuilt v0.14.0 CLI passed `scripts/auth_smoke.py` against the hosted
service using fresh private temporary state. Anonymous methods, paths, MCP and
discovery were denied with zero backend hits. Password and machine-token access,
CSRF/origin checks, secure cookies, credential/header stripping, cache controls,
eight concurrent 2 MiB uploads, corruption handling, restart, logout and two
profiles with different backends passed. Revocation closed active SSE and
WebSocket streams in **0.199 seconds** on the first run and **0.279 seconds**
on the final rebuilt rerun; cross-profile credentials were denied.

All owned processes stopped and local credentials were removed. Authenticated
API 404 confirmed deletion of both temporary tunnels. Existing profiles and
running proxies were untouched. No new GitHub App or authorization grant was
created. GitHub callback-to-session-to-backend identity, signed WebSocket
admission, trailer attacks and public-key export are covered by local integration
tests with a fixture provider and real HTTP/TLS transports.

The compiled example app separately passed local root, request metadata,
incremental streaming and real WebSocket echo checks, then exited cleanly on
SIGINT. QR output was independently decoded from rendered terminal cells and
matched only the public HTTPS URL. These checks do not claim a new live GitHub
browser authorization or a physical phone scan.

## v0.13.0 custom CA and hosted regression check — 2026-10-16

The rebuilt v0.13.0 CLI passed `scripts/auth_smoke.py` against the hosted service
with empty private temporary state. `OPENTUNNEL_CA_CERT` selected an additional,
locally generated test CA throughout the run. Public API and WSS certificates
still verified, demonstrating that the extra CA did not replace public trust.
The two fresh tunnels used normally issued visitor certificates.

Anonymous methods, paths, MCP and discovery were denied with zero backend hits.
Password and machine-token login, CSRF/origin checks, secure cookies,
credential/header stripping, cache controls, eight simultaneous 2 MiB uploads,
SSE/WebSocket forwarding, corruption handling, restart, logout and simultaneous
profiles with different backends passed. Revocation closed both streams in
**0.184 seconds**. Cross-profile credentials were denied.

All owned processes stopped, local credentials were removed, and authenticated
API 404 confirmed deletion of both temporary tunnels. Saved user profiles and
running proxies were untouched. No new GitHub App or authorization grant was
created; GitHub flow and CA isolation are covered by local regression tests.

Separately, the rebuilt example app passed local root, request metadata,
incremental HTTP streaming and real WebSocket echo checks, then exited cleanly
on SIGINT. That local-only run created no tunnel or persistent state. The
self-hosted TLS and exact upstream codec checks are described in
[Testing](TESTING.md#custom-ca-and-upstream-websocket-compatibility).


## v0.11.0 long-poll release check — 2026-10-13

The rebuilt v0.11.0 CLI completed the hosted auth smoke test with empty private
temporary state. A temporary adaptation of the existing backend withheld all
headers for 16 seconds on `/long-poll`. An authenticated request through the
public tunnel returned HTTP 200 and the expected JSON after **16.476 seconds**,
past the former 15-second deadline. This checks the complete hosted path rather
than only the local transport.

The rest of `scripts/auth_smoke.py` passed: anonymous methods/routes, MCP and
discovery were denied with zero backend requests; password and machine-token
authentication, origin/CSRF checks, credential/header stripping, cache policy,
uploads, corrupt-registry denial, restart, logout and two-profile isolation
remained intact. Revocation closed SSE and WebSocket streams in **0.158 seconds**.

All owned processes stopped, local credentials were removed and authenticated
API 404 confirmed deletion of both temporary tunnels. Existing profiles and
running proxies were untouched. Pending-header cancellation was checked by local
race tests; this hosted run checked the delayed successful response and existing
stream revocation. No new GitHub App grant was made. The temporary fixture
adaptations and raw logs stayed outside the repo.

## v0.10.0 release-version check — 2026-10-13

After updating `Version` to `0.10.0`, `make check` rebuilt the CLI and
`python3 scripts/auth_smoke.py` repeated the complete hosted auth run with exit 0.
The service accepted fresh provisioning and relay attachment with the updated
`opentunnel-go/0.10.0` User-Agent.

Anonymous methods/routes, MCP and discovery were denied with zero backend
requests. Password login, browser origin/CSRF rules, secure cookies, authenticated
MCP, header/credential stripping, redirects, cache policy, simultaneous uploads,
corruption handling, logout, restart and two-profile isolation all passed. Token
revocation closed active SSE and WebSocket streams in **0.213 seconds**.

All owned processes stopped, local credentials were removed and authenticated
API 404 confirmed removal of both temporary tunnels. Existing profiles and
running proxies were untouched. This repeat used password and machine-token
authentication; GitHub provider/browser-launch checks remain the local fixtures
described below, without a new hosted GitHub grant.

## Setup/retry development check — 2026-10-13

After the setup feedback and API retry changes, the rebuilt CLI completed
`python3 scripts/auth_smoke.py` against the hosted service with ordinary HTTPS
verification and empty private temporary state. API and relay requests use
`opentunnel-go/<version>`. Existing saved profiles and running proxies were
untouched.

- Fresh provisioning, certificate issuance and protected public traffic passed.
- Every anonymous method/route, including MCP/discovery, was denied with zero
  backend requests. Password login, invalid credential denial, browser
  origin/CSRF checks and secure cookies passed.
- Authenticated MCP access, credential/header stripping, backend redirects and
  cookies, private cache policy and foreign-subresource denial passed.
- Eight simultaneous 2 MiB uploads round-tripped intact. Machine-token
  revocation closed live SSE and WebSocket streams in **0.253 seconds**.
- Corrupt token registries failed closed. Restart retained the tunnel/backend
  and machine tokens while invalidating browser sessions; logout worked.
- Two simultaneous profiles used different backends. Credentials for one
  profile were denied by the other.
- All owned test processes stopped, local credentials were removed and
  authenticated API 404 confirmed deletion of both temporary tunnels.

Transient API failures were injected only in local fixtures. This hosted run
confirms service interoperability; it does not induce provider rate limits or
issuance failures. GitHub setup/browser-launch changes were checked locally with
fixture provider responses and launcher executables, without creating another
GitHub App. See [local checks](VERIFICATION.md) for the review and regression tests.


## v0.7.0 security audit — 2026-10-11

Built the v0.7.0 CLI and embedding example with Go 1.27.2 after the final queue
and diagnostic fixes. Tests used private,
empty state directories, ordinary HTTPS certificate verification and owned
temporary tunnels. Existing profiles and the running inbox proxy were untouched.

| Check | Result |
| --- | --- |
| Fresh CLI provisioning | Certificate ready in 62 seconds, within the five-minute default |
| CLI forwarding and embedded listener | Public root, streaming, actual TLS request metadata, text/binary WebSocket echo and clean shutdown passed |
| Plain, PROXY v1 and PROXY v2 forwarding | Public HTTPS response and backend preambles passed, including v2 authority |
| Password proxy anonymous boundary | Methods/routes, MCP and discovery denied with zero backend calls |
| Password/browser and machine authentication | Correct/wrong passwords, secure cookies, CSRF/origin rules, invalid-token denial and authenticated MCP HTTP requests passed |
| Credentials, cache and browser policy | Gate credentials/spoofed identity headers stripped; backend credentials preserved; redirects/cookies adapted; public-cache and foreign-subresource checks passed |
| Streaming and uploads | Eight simultaneous 2 MiB uploads intact; token revocation closed SSE/WSS in 0.186 seconds |
| CLI lifecycle | Live hostname/token inspection, duplicate-profile refusal, corrupt-registry denial, restart, logout and two-profile isolation passed |
| Cleanup | Every owned remote identity returned authenticated API 404; local credentials removed and all owned test processes stopped |

The password run used `python3 scripts/auth_smoke.py`. CLI/embedding/PROXY checks
used private adaptations of the existing service-test coordinator and forwarding
driver, sharing one fresh identity before confirmed deletion. Both drivers also
passed earlier hardening iterations. Raw logs, helpers and credentials stayed
outside the repo. Each run confirmed remote deletion, empty local profiles and
shutdown of all owned test processes.

No new GitHub App grant was made in this audit. Current GitHub-provider behavior
was checked with local fixtures; earlier owner-approved hosted GitHub checks
remain recorded below. These HTTP/MCP checks establish gating, not automatic MCP
OAuth client interoperability. Hosted certificate-renewal failure was not induced.
See [the audit](SECURITY_AUDIT.md) for fixture coverage and remaining boundaries.

## v0.4.0 release-candidate service check — 2026-10-10

After updating the advertised client version to `0.4.0`, `make check` passed and
the rebuilt CLI repeated the full `python3 scripts/auth_smoke.py` run with exit 0.
The service accepted provisioning and visitor attachment with the new version.
Anonymous gating, browser/password/CSRF/Origin checks, machine MCP access,
credential stripping, cache/referrer policy, uploads, corruption, restart, logout
and two-profile isolation passed. SSE/WSS revocation took **0.222 seconds**.
Every temporary identity returned API 404; local credentials were removed and all
owned processes stopped. This is the version-metadata check after the complete
post-Amp CLI/embedding-app run below.

## Post-Amp auth lifecycle repeat — 2026-10-10

After fixing the cancelled-wizard save race and late revocation close, the final
CLI and embedding example were rebuilt. Both public-service drivers completed
with exit 0:

- `python3 scripts/auth_smoke.py`: anonymous methods/routes denied with zero
  backend calls; MCP token access; running-profile inspection/token creation;
  browser login, CSRF/Origin, credential stripping, public cache/referrer
  overrides, foreign subresource denial/top-level navigation, eight concurrent
  2 MiB uploads, corruption denial, restart, logout and two-profile isolation.
  SSE/WSS revocation closed both streams in **0.236 seconds**.
- The full CLI/listener/embedding-app workflow repeated provisioning cancellation
  and resume, identity reuse/redaction, interactive inputs, root/named routes,
  target replacement/refusal isolation, transfers, stream/WSS contents, route
  suspension, quit/deadline/SIGINT, direct-listener TLS/peer/SNI behavior and
  embedded app provisioning/serving/shutdown.
- Cleanup confirmed API 404 for every temporary identity, idempotent removal,
  empty local identity views and every owned process stopped.

Real GitHub OAuth and App registration passed in the post-Claude run recorded
below, before the last two lifecycle fixes. The changed wizard shutdown paths
passed real loopback HTTP/provider-fixture regressions, including conversion
cancellation and a committed callback paused beyond HTTP graceful shutdown.
A third real-provider App was not created for those narrow corrections.

## GitHub auth and security follow-up — 2026-10-10

The later post-Claude-fix password run passed the full smoke again, including
foreign cookie subresource denial/top-level navigation and the backend response
referrer policy. SSE/WSS revocation took **0.389 seconds**. Two-profile isolation,
logout, restart, process/local-credential cleanup and remote API 404 all passed.
The 0.370-second result below belongs to the preceding cache/admission build.

The new one-use `/__otgo/github/setup` wizard was also exercised against real
GitHub after the Claude fixes: the owner created the App, conversion/persistence
succeeded and real OAuth established a session, verified by the protected sign-out
page. The anonymous GitHub matrix and token stripping/revocation passed. Chrome
initially blocked the plain-text root display with `ERR_BLOCKED_BY_CLIENT`. After
the owner dismissed an extension panel, the protected backend was visible in the
current tab. Logout returned to login. Reconfiguring the existing App to allow
only `octocat` left the owner behind login after a real OAuth attempt; automated
callback tests separately assert 403/no session. Restoring the owner’s allowlist permitted a session again, and restarting the
proxy invalidated that session: the public root returned to login. The newest
profile’s processes stopped, its local auth credentials were removed and remote
deletion was confirmed with API 404. With owner approval, GitHub removed the
test App from the list and reported its deletion queued.


A dedicated profile and instrumented loopback backend exercised real GitHub App
registration and OAuth through the hosted OpenTunnel service with normal public
TLS verification. The owner approved creation and the identity grant. No existing
user profile was modified.

| Check | Observed outcome |
| --- | --- |
| Guided registration | GitHub returned a manifest code; the CLI converted it and privately saved GitHub mode. No repository permissions/webhook deliveries were requested. |
| Allowed account | Real OAuth/state/PKCE established a local session; the public root displayed `protected-backend`, confirmed by the owner and native browser inspection. |
| Logout | Sign-out form returned to the GitHub login page. |
| Denied account | With only `octocat` allowlisted, the owner's real login did not redirect to the backend; the root remained behind login. Local callback tests separately assert 403 and no session. |
| Restore/restart | Restoring the owner's allowlist permitted login. A further restart invalidated that authenticated browser session and the root returned to login. |
| Anonymous boundary | Nine methods across ten routes, including MCP/discovery/assets/SSE/WebSocket and path variants, were denied; backend counters stayed unchanged. Forged session/token/identity and callback attempts were denied; password POST returned 405 in GitHub mode. |
| Machine boundary | A real CLI-created token enabled access; gate cookies, authorization and spoofed identity were stripped upstream; client-secret canary was absent; revoked token returned 401. |
| Protected cache headers | The rebuilt GitHub-mode proxy returned `private, no-store`, `Pragma: no-cache`, expired `Expires`, without secret values in the upstream response. Local tests in both modes separately verify overriding an intentionally public-cacheable backend. |
| Cleanup | Owned processes stopped, local auth credentials removed and remote deletion confirmed with API 404. With owner approval, GitHub accepted permanent test-App deletion and removed it from the Apps list; its UI reported asynchronous deletion queued. |

After the final cache/header and password-admission fixes, the rebuilt CLI passed
`python3 scripts/auth_smoke.py` again. It denied anonymous requests without
backend calls, enforced MCP tokens, stripped gate credentials, overrode a public
cache fixture including `X-Accel-Expires`, and preserved eight simultaneous 2 MiB
uploads. SSE/WSS revocation closed both streams in **0.370 seconds**. Corrupt
registry denial, browser-session restart invalidation, retained machine tokens,
logout and two concurrent isolated profiles with cross-token denial passed.
Every owned process stopped; local credentials were removed and API 404
confirmed remote cleanup. This repeat required no interactive GitHub approval.

Chrome intermittently showed `ERR_BLOCKED_BY_CLIENT`, including after successful
registration conversion and authenticated requests. Extension UI also interrupted
automation. The responsible extension was not established. The owner subsequently
saw the protected backend; no TLS verification or browser security protection was
disabled. Automated tests, rather than Chrome's blocked error display, establish
failure status/body and secret-reflection assertions.

See [AUTH_SECURITY_REVIEW.md](AUTH_SECURITY_REVIEW.md) for findings, fixes and
remaining availability/session limits. Public cache-policy tests verify response
headers and access denial; they do not claim a browser cache-replay experiment.

## Post-Claude CLI and app repeat — 2026-10-10

The CLI and embedding app were rebuilt and retested after the auth hardening.
The complete run passed interrupted provisioning/resume, saved identity reuse,
JSON redaction, online/offline inspection, interactive invalid inputs, root/named
routes, target replacement and refused-target isolation, route suspension,
timeout/quit/SIGINT, direct listener TLS/peer/deadline behavior, embedding-app
HTTPS/streaming/WSS, 2 MiB and concurrent transfers, pending deletion and cleanup.
API 404 confirmed all temporary remote identities were removed, all local identity
views were empty, and every owned process stopped.

The first copied harness omitted its Go deletion-inspection executable. Traffic
checks passed, but cleanup confirmation failed because the helper was missing.
The harness was corrected and the full run repeated successfully; this was a
harness failure, not a passing cleanup result from the first run.

## Browser login regression — 2026-10-10

A user reported `Invalid request origin` after password submission. The running
login page sent `Referrer-Policy: no-referrer`; browser HTML form POSTs under that
policy send `Origin: null`, which the exact-origin guard correctly refused.
The correction applies `same-origin` only to login/logout forms and the local
GitHub setup start form. OAuth callbacks and external registration responses
retain `no-referrer`; Origin/CSRF validation is unchanged. See the
[Fetch Origin algorithm](https://fetch.spec.whatwg.org/#append-a-request-origin-header).

The corrected CLI was tested in Chrome through a temporary public HTTPS tunnel
fronting the actual installed Plannotator Inbox. Password submission redirected
to `/`, created a session and loaded the complete Inbox. The logout confirmation
form redirected to login and revoked the session. Both pre-fix and corrected
temporary tunnels were stopped and removed; API 404 confirmed deletion.

Regression tests cover form policies, root redirect, rejection of null/missing/
foreign Origins and the GitHub setup/external registration policy boundary.
`make check` passed with zero lint issues; `make race` and an independent focused
review/race run passed. Real GitHub registration was not covered by that run;
the follow-up above records its completed interactive test.

## Auth proxy and full CLI/app retest — 2026-10-10

The final rebuilt binaries passed the following checks through the hosted service
using normal public TLS trust. Profiles and credentials were isolated from user
profiles. Earlier attempts failed during remote certificate issuance; their
identities were deleted and API 404 confirmed cleanup. A stable v0.3.0 provisioning
probe subsequently passed, and fresh complete runs then passed too. The server-side
cause of those earlier issuance failures was not established.

| Path | Tested outcome |
| --- | --- |
| Diagnostic CLI | Interrupted create/resume, saved identity reuse, JSON redaction, online/offline inspect, interactive invalid input, root/named routes, target replacement, refused backend isolation, route suspension/restoration, timeout/quit/SIGINT with stdin open |
| Direct listener | Root/named real TLS state, HTTPS origin, relay peer, ignored forged headers, deadline/SIGINT and offline state |
| Embedding app | Fresh provisioning, HTTPS root/stream/WSS, incremental chunks, 16,000-byte text/binary WebSocket messages, SIGINT and offline state |
| Transfers | Exact 2 MiB POST, eight concurrent 256 KiB diagnostic transfers; eight concurrent 2 MiB auth-proxy uploads |
| Universal auth gate | GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS/CONNECT denied on root/assets/health/MCP/discovery/encoded variants; backend counter stayed unchanged |
| Browser protocol | Wrong password/origin/CSRF denied, good password set a Secure/HttpOnly cookie, authenticated writes required Origin, invalid gate tokens could not fall back to a session, logout revoked access |
| Machine clients | MCP POST accepted with bearer; hostname lookup and token mint/list worked while proxy ran; duplicate profile refused |
| Upstream rewrite | Gate cookies/token and forged identity headers stripped; backend Authorization retained with X-Otgo-Token; Host/Origin/Referer, redirects and reserved Set-Cookie handling checked |
| Streaming/revocation | SSE and WSS streamed; revocation closed both in **0.347 seconds** and subsequent access returned 401 |
| Persistence/isolation | Corrupt registry denied machine access; restart retained hostname/backend/token but invalidated browser session; two profiles ran against different backends and rejected each other's credentials |
| Cleanup | Every owned process stopped; local auth/identity files removed; API 404 confirmed all temporary remote identities were removed, including interrupted provisioning |

The auth run is repeatable with `make build` and `python3 scripts/auth_smoke.py`.
It does not implement a full MCP OAuth client/server exchange; it verifies HTTP
MCP gating with configured machine credentials. Real GitHub browser approval and
allowlist denial were exercised separately in the follow-up above. Long-term
renewal and runtime behavior on other operating systems remain outside this
smoke test. Local GitHub
fixtures cover registration, PKCE/state/replay/expiry, numeric account IDs,
allow/deny behavior, errors/timeouts and restart configuration.

The installed Plannotator Inbox additionally returned its real HTML after
password login through public HTTPS. Chrome's initial form submission was blocked
with `ERR_BLOCKED_BY_CLIENT`; the equivalent HTTP login succeeded. Browser live
updates and attachment/reply interactions were not verified in this run. The
follow-up above records real GitHub registration; the preceding browser-regression
record verifies the corrected Inbox login. The temporary
Inbox proxy was stopped and removed; API 404 confirmed deletion.

The dated SDK records below describe their own revisions.

**Passed:** provisioning, HTTPS/WSS, streaming, large/concurrent transfers,
route updates, reconnection, embedding, shutdown, and deletion. Both temporary
tunnels were deleted; all test server/bridge processes stopped.

Tested **2026-10-09** against `https://opentunnel.xyz`, from macOS arm64 with
Go 1.27.2. The deployed server revision was not established. The client's source
compatibility baseline is `22156aa6ab209515186c3ca4f111901b7cedc284`.

To repeat the basic sequence, use [TESTING.md](TESTING.md#repeat-a-basic-live-test).

## Test setup

The exercise used the built `otgo`, the webapp embedding example, an external Go
program importing the public package, and Python standard-library HTTP clients
and loopback echo targets.

Two dedicated temporary identities were used: one fully provisioned, one deleted
while pending. Credentials stayed in private temporary storage outside the repo.
No production app or existing user profile was exposed.

## Provisioning and inspection

| Check | Result |
| --- | --- |
| Interrupted create | Stopped at `requesting-certificate`; pending identity was persisted and the cancelled process exited normally |
| Resume and issuance | Real API issuance completed; certificate matched the local key and required SANs |
| Local views and redaction | `profiles`, `list`, `get`, and `pending` returned expected results; JSON omitted tokens/private keys; completed `resume` returned `null` |
| Ensure and create conflict | `ensure` reused the tunnel ID; repeated `create` returned `ErrExists` |
| Remote inspection | `inspect` reported offline before attachment, online while connected, and offline after disconnection |

## Public traffic

| Check | Result |
| --- | --- |
| HTTPS | Root response matched the loopback target using normal public certificate verification; no insecure TLS option or test CA |
| Streaming | Three expected `/stream` chunks arrived incrementally; more than 250 ms elapsed between first and final receipt |
| WebSocket | WSS echoed text and binary messages of 16,000 bytes each, then closed normally |
| Large transfer | A 2,097,152-byte HTTP POST was echoed exactly through the named route |
| Concurrent transfers | Eight concurrent 262,144-byte HTTP POST/echo operations preserved their contents |

SHA-256 of the 2 MiB transfer:

```text
bc2c7f3922bfe264439943832357087870faedd70bea44b518fd7856c6c234a1
```

## Route changes

| Check | Result |
| --- | --- |
| Add a name | Adding `api` reattached; root and named hostnames both forwarded correctly |
| Replace a target | A second loopback target returned its distinguishable response; status stayed connected |
| Refused target | A closed named-target port failed that visitor request; root stayed usable |
| Empty routes | Interactive `routes` with no entries suspended attachment in `waiting-routes` |
| Restore routes | Restoring root reattached and served HTTPS again |

## Embedding and reconnection

| Check | Result |
| --- | --- |
| External SDK consumer | Imported the package, used file storage, and served public HTTPS |
| Bridge reconnect | Closed only the program's own upgraded bridge transport; observed `reconnecting`, then a new `connected` event and successful HTTPS |
| SDK close | `Client.Close` returned after `Connection.Done` closed and status became stopped |
| Embedded webapp | Without `--local-only`, the example owned its SDK connection, served HTTPS, and exited 0 on SIGINT |

## CLI shutdown

| Check | Result |
| --- | --- |
| Interactive quit | Exited 0 with the stdin writer still open; service then reported offline |
| Deadline | `connect --timeout 4s` exited 1 with `context deadline exceeded`, with stdin still open |
| Ctrl-C | SIGINT stopped the interactive CLI with open stdin and exited 0 |

## Deletion and cleanup

| Check | Result |
| --- | --- |
| Delete while active | `Client.Remove` joined the active session, removed the local identity, and authenticated remote inspection returned 404 |
| Delete pending identity | A second create was interrupted before completion; `otgo remove` deleted remote tunnel and local files |
| File permissions | Pending profile directory was `0700`; stored files were `0600` |
| Idempotent cleanup | Repeated `remove` succeeded; final profile/tunnel lists were empty and `get`/`pending` returned `null` |

No real tokens, private keys, or raw credential-bearing artifacts were committed.

## Shutdown bug found and fixed

The first interactive run passed traffic checks but hung on `quit` with the
stdin writer open. A native-process goroutine trace showed cleanup waiting for
a scanner already blocked in its next OS read. Closing inherited stdin did not
release that read.

The CLI now stops scanning immediately after enqueueing `quit`. Cancellation
does not close or join process-owned native stdin. SDK cleanup still joins the
tunnel/client before process exit ends the reader. The change is confined to
the CLI.

Regression evidence:

- `TestReadCommandsStopsAtQuitWithoutEOF` failed before the fix and passed after it.
- `TestNativeStdinCancellationDoesNotWaitForEOF` uses a child process with an
  inherited pipe whose writer stays open.
- The repeated live sequence passed quit, deadline, and SIGINT shutdown.

Final acceptance checks passed:

```sh
make check
go test -race -count=1 ./...
go test -race ./cmd/otgo -run 'TestReadCommands|TestNativeStdin' -count=3
```

Repository-wide golangci-lint reported **0 issues**. The test subprocess selects
its binary with `os.Executable()`; a local `G204` annotation explains that choice.

## Coverage limits

These results establish the listed paths at the test date, not all inputs or
long-running production behavior.

| Area | Evidence limit |
| --- | --- |
| Long-term renewal and server-initiated drain | Covered by local fixtures; not induced during this hosted-service exercise |
| Malformed controls, fatal attach codes, heartbeat expiry | Local fixture coverage; not all induced live |
| Queue/buffer overflow, TLS half-close, renewal racing deletion | Local fixture coverage; not all induced live |
| Linux and Windows | Compile-checked; no runtime tests on those operating systems |
| Hosted operator and infrastructure | No independent audit; deployed revision unknown |

Read [SECURITY.md](SECURITY.md) for the domain/certificate operator trust boundary.


## Post-hardening CLI and app retest

**Passed the listed functional checks on 2026-10-09**, after the final redirect
and certificate-recovery changes. `make check` rebuilt both binaries. These
checks supplement the earlier exercise above; they used dedicated profiles in
private temporary storage and did not touch existing applications.

Two complete CLI/app traffic runs each used three new identities: a CLI identity
resumed after cancellation, an identity provisioned by the embedded app, and an
identity deleted while pending. All six were removed. All test processes stopped,
local `profiles`/`list` were empty, and `get`/`pending` returned `null`.

### Provisioning and CLI

| Check | Result |
| --- | --- |
| Cancel create | Stopped at `requesting-certificate`; exited 0 and preserved pending credentials |
| Resume and reuse | `resume` completed issuance; `get` and `ensure` retained the tunnel ID; subsequent `resume`/`pending` returned null |
| Inspection and conflict | `profiles`/`list` matched storage; repeated `create` exited 1; `inspect` tracked offline/online/offline |
| JSON and input errors | Public views omitted token/key fields; `stauts` and malformed `routes` reported to stderr while HTTPS stayed usable |
| Open-stdin shutdown | `quit` and SIGINT exited 0; a 3-second command deadline exited 1 with `context deadline exceeded`; remote state became offline |

### Traffic and routes

| Check | Result |
| --- | --- |
| HTTPS and streaming | Root matched the loopback app with normal public trust; all three stream lines arrived incrementally, more than 250 ms from first to last |
| WSS | Text and binary messages of 16,000 bytes each echoed exactly, then closed normally |
| POST echo | Named target returned an exact 2 MiB payload and eight concurrent 256 KiB payloads |
| Route updates | Named attachment, target-only replacement, empty-route suspension, and restored root all worked |
| Failed backend isolation | A closed named-target port failed that request while root kept serving |

### Embedded app and cleanup

| Check | Result |
| --- | --- |
| Local-only app | Root served correctly; SIGINT exited 0 |
| App-owned tunnel | Without `--local-only`, the rebuilt app provisioned its own identity, served public HTTPS/stream/WSS, and exited 0 on SIGINT |
| Pending deletion | `remove` released the pending identity and removed its local credentials |
| Repeated removal | Every dedicated profile removed successfully; repeated removal was idempotent |
| Remote confirmation | A Go API consumer returned HTTP 404 for each of the four completed IDs after deletion |

The temporary Python harness initially reported a failure in its extra cleanup
probe: raw Python API requests returned HTTP 403 when it expected 404. CLI
removal had already succeeded and storage was empty. The confirmation was rerun
through the package's Go API transport and returned 404 for every completed
identity. The reason for the Python-specific rejection was not established;
this is a harness correction, not evidence of a package failure.

### Final local checks

```sh
make check
go test -race ./... -count=1
GOTOOLCHAIN=go1.25.0 go test ./... -count=1
go test -race ./cmd/otgo -count=3
make fuzz
```

All passed, with golangci-lint **0 issues**. Focused hardening races passed five
repetitions; follow-up review's redirect/recovery races passed ten. Overflow
and startup-lifetime cancellation regressions passed five repetitions each.
Linux/Windows amd64 cross-compilation passed locally. Hosted
[CI for implementation commit `7cbae9a`](https://github.com/darron/go-opentunnel/actions/runs/37985077768)
also passed Go 1.25 tests, vet, and builds on Linux and macOS, Linux race tests,
and repository-wide formatting/lint. Windows remains compile-only.

Long-term renewal, malformed relay controls, overflow, fatal attachment codes,
and forced server drain still rely on fixture evidence. A forced bridge loss
was exercised in the earlier record, not re-induced in this final live pass.
The hosted service's deployed revision remains unknown. See
[HARDENING.md](archive/HARDENING.md) for dispositions and remaining limits.


## Post-Amp review retest

**Passed on 2026-10-09, with recorded driver exit 0**, after all accepted Amp
fixes and the pending-write-deadline correction. The final source was rebuilt
with `make check`; no functional changes followed this live exercise.

A temporary Python standard-library driver launched `bin/otgo` and
`bin/webapp` against the public service, using three new profiles in private
storage. Small Go consumers checked WSS and authenticated deletion status through
the package API. Credentials stayed in private storage or process stdin and did
not appear in command arguments, this document, or committed artifacts.

| Area | Checks passed |
| --- | --- |
| Provisioning | Cancel create at `requesting-certificate`; exit 0 with pending credentials; resume issuance; reuse the same ID through get/ensure |
| Inspection | Profiles/list match; subsequent pending/resume return null; repeated create exits 1; inspect follows offline/online/offline; JSON views omit token/key |
| Public traffic | Normal HTTPS trust; exact root response; three incremental stream lines spanning more than 250 ms; exact 16,000-byte text and binary WSS echoes and normal closure |
| Uploads | Exact 2 MiB named-route POST echo; eight concurrent 256 KiB echoes |
| Routes | Add named route; replace its target; closed named backend fails while root stays usable; empty routes suspend; restoring root reattaches |
| Invalid input | Typos, malformed route syntax, port 0, and uppercase route names report on stderr while the tunnel remains alive and HTTPS keeps serving |
| CLI shutdown | Quit with stdin open exits 0; 3-second deadline exits 1 with context deadline exceeded; SIGINT with stdin open exits 0; remote state becomes offline |
| Embedded app | App provisions its own new identity and tunnel; public HTTPS, streaming, and WSS pass; SIGINT exits 0 and remote state becomes offline |
| Pending deletion | Cancel another creation; remove its pending remote/local identity; authenticated Go API returns 404 |
| Final cleanup | All three identities removed; repeated removal succeeds; authenticated Go API confirms 404 for the completed identities; get/pending return null; profiles/list are empty; all owned processes stop |

The tool server interrupted the first post-Amp command session before its final
result could be retrieved. Inspection showed no surviving test processes or
local profiles. The complete workflow was repeated with stdout and exit status
saved to files; that recorded run provides the results above. Its deletion
checks used the Go API consumer from the start, avoiding the earlier Python
transport-probe mismatch.

Final local validation passed `make check` (golangci-lint 0 issues), the full
race suite, Go 1.25 compatibility tests, parser fuzz smoke tests, ten repetitions
of focused fix races, and five repetitions of the retained Amp confirmation
probes. Linux and Windows amd64 package/CLI test compilation and example builds
passed. The [Amp review record](archive/AMP_REVIEW.md) describes accepted findings,
confirmation, and remaining boundaries.

Long-term renewal, malformed controls, overflow, cleanup saturation, forced
drain, and cancellation under bridge backpressure use local fixture evidence;
they were not all induced against the hosted service. Windows remains
compile-only. The hosted deployment revision and provider infrastructure were
not audited.

## TLS listener retest, 2026-10-10

**Passed against the public service using the final rebuilt CLI and webapp.**
The recorded workflow exited 0. It used three dedicated identities in isolated
private temporary storage; all were removed, authenticated API inspection returned
404 after deletion, local lists were empty, and every owned process stopped.
Credentials and raw logs stayed outside the repository. The deployed server
revision was not established. Public requests used normal certificate trust.

| Path | Verified behavior |
| --- | --- |
| Existing CLI forwarding | Interrupted create/resume; identity reuse and redaction; online/offline inspection; HTTPS; three incremental stream chunks; WSS text/binary 16,000 bytes each and normal close |
| Forwarding routes | Invalid interactive commands preserve traffic; root/named reattachment; exact 2 MiB POST echo; eight concurrent 256 KiB echoes; target replacement; refused named target leaves root usable; empty/restored routes |
| Forwarding shutdown | Quit and SIGINT exit 0 with stdin still open; 3-second deadline exits 1 and reports context deadline exceeded; attachment becomes offline |
| `otgo listen` | Root and named routes expose actual TLS state/SNI, HTTPS origin, and nonempty relay peer; forged `X-Forwarded-For`/`X-Forwarded-Proto` do not override those fields |
| Listener shutdown | SIGINT exits 0; 3-second listener deadline exits 1 with context deadline exceeded; remote state returns offline |
| Direct embedded webapp | New identity provisioned through `Listen`; HTTPS root; incremental streaming; WSS text/binary 16,000 bytes each with normal close; `/request` reports real TLS/SNI/peer; SIGINT exits 0 and leaves tunnel offline |
| Cleanup | Interrupted pending identity deleted; repeated removal succeeds; all three remote identities return 404, all local identities/pending records are absent, all processes stop |

Two earlier attempts found defects and cleaned up after themselves: the CLI
initially used the forwarding route parser; then immediate channel reset on
application close truncated a normal WSS close. Both now have regression tests.
Ordinary application close sends an orderly protocol `end` to preserve buffered
TLS/HTTP/WebSocket bytes. Failures and forced listener shutdown still abort.

Wrong-SNI rejection, renewal, reconnects, resource limits, fatal attachments,
concurrent Accept, and worker joining were exercised with local relay fixtures;
this hosted run does not claim those adversarial scenarios were induced at the
public service. See [VERIFICATION.md](VERIFICATION.md#tls-listener-verification-2026-10-10)
and [LISTENER.md](LISTENER.md) for evidence and contracts.

## v0.3.0 post-review retest, 2026-10-10

After fixing the [Amp/Oracle removal finding](archive/AMP_REVIEW_V0.3.0.md), the rebuilt
CLI and webapp repeated the complete TLS-listener workflow above. The driver
recorded **exit 0**. It used private temporary storage and normal public TLS
verification. No credentials or raw workflow artifacts were added to the repo.

- Provisioning and CLI inspection: canceled creation with saved pending state,
  resume, ensure, get, pending, profiles, list, create conflict, JSON redaction,
  and offline/online inspection.
- Forwarding: public HTTPS, three incremental stream chunks, 16,000-byte text
  and binary WSS with normal close, an exact 2 MiB upload, and eight concurrent
  256 KiB uploads.
- Routes and shutdown: invalid interactive input preserves traffic; named route
  attachment, backend replacement/refusal, empty-route pause and restoration,
  quit with open stdin, timeout, and SIGINT.
- Direct listening: root/named TLS state, SNI, secure origin, relay peer, ignored
  forged forwarding headers, SIGINT, timeout, and return to offline state.
- Embedded app: fresh provisioning through `Listen`, HTTPS, incremental stream,
  text/binary WSS with normal close, real request metadata, and SIGINT shutdown.
- Cleanup: pending deletion, idempotent removal, authenticated API 404 for all
  three owned identities, empty local profile/identity views, and stopped owned
  processes, including the local-only app.

The 64-paused-listener removal race was tested against local relay fixtures;
this live run did not induce that concurrency scenario at the hosted service.

## Unreleased PROXY and certificate diagnostic check — 2026-10-10

Ran `GOTOOLCHAIN=go1.25.0 go run ./scripts/proxy-smoke` against the public service.
The script used a fresh memory-backed identity and made one provisioning attempt.
It returned `CertificateIssuanceError` classified as `unknown`, without a
recognized HTTP status. Ordinary output omitted the raw remote reason.

Issuance failed before bridge attachment, so this run **did not validate public
plain/v1/v2 forwarding**. Local CLI/relay/TLS fixtures validate header behavior.
The result does not establish whether the service or certificate provider is
rate limiting requests, and does not identify the deployed server revision.

Cleanup completed: the temporary identity was removed and its authenticated
remote API lookup returned 404. No persistent user profile was changed. No
additional fresh issuance attempts were made for this check.

## PROXY public-service retry — 2026-10-11

Retried with the unchanged runtime at `365d09501b02389db3668982ce18f6c6c04dbfa3`.
Used a temporary copy of `scripts/proxy-smoke/main.go`, instrumented only to retain
an issuance error's raw reason in a private temporary file for inspection.
One fresh memory-backed tunnel was created; saved profiles were untouched.

Provisioning failed again. The typed error's safe classification was `unknown`
and no HTTP status was available. Private inspection found the provider reason:

```text
ACME server returned no nonce
```

This exact message occurs in upstream's
[`Session::fresh_nonce`](https://github.com/anomalyco/opentunnel/blob/bb81367416c78834e09bca569267cbbae50781fb/crates/opentunnel-server/src/acme.rs):
the hosted ACME client sends HEAD to the provider's `newNonce` URL, then fails if
it cannot read a usable `Replay-Nonce` header. That path does not preserve HTTP
status or response details. The upstream master commit was still
`bb81367416c78834e09bca569267cbbae50781fb` when checked.

The observed failure is in hosted certificate issuance, before local TLS or
PROXY forwarding. Its underlying cause remains unknown: the available reason
cannot establish whether the provider returned a rate-limit/error response or
why the header was absent. The source match does not independently prove which
revision is deployed at the service.

The script exited with status 1. Cleanup succeeded, with authenticated remote API
404 confirming deletion. A local safety hook refused deletion of the temporary
probe and diagnostic file; they remain in a private temporary directory. The
only captured diagnostic is the 29-byte reason above, with no tunnel credentials.
Public plain/v1/v2 forwarding remains unverified. No runtime code was changed.

## Fresh-state version comparison and v0.6.0 live checks — 2026-10-11

**Passed with v0.3.0, v0.5.0 and current code.** Built the CLI, embedding example
and private test helpers with Go 1.25.0. Historical releases came from `git archive`
at `b6eb12c77b48e3c33d63a7a2ddd470bf317f1362` (v0.3.0) and
`6c531cced6baa30466315ebaf51581565e288163` (v0.5.0). Initial current builds used
`36fc546`; final builds advertised 0.6.0 with the release changes.

Each fresh run started with a private, empty `--data-dir` and no XDG state.
Existing profiles and the running `otgo proxy --profile inbox` were untouched.
Visitor checks used normal HTTPS certificate verification.

| Check | Result |
| --- | --- |
| Each version's local-only embedding example | Root response, three stream chunks, request metadata, text/binary WebSocket echo and shutdown passed |
| v0.3.0 fresh public embedding example | Certificate issued; HTTPS, stream, real TLS metadata and text/binary WebSocket echo passed |
| v0.5.0 initial fresh attempt | Still in `challenge` when the test coordinator stopped it at 120 seconds; no terminal issuance error was reported |
| v0.5.0 second fresh attempt, 300-second window | Certificate issued; the same public embedding checks passed |
| Initial current fresh public embedding example | Certificate issued; the same public embedding checks passed |
| Final 0.6.0 CLI `create --timeout 5m` | Fresh provisioning passed in 186 seconds |
| v0.3.0, v0.5.0 and final 0.6.0 CLI `connect` | Reused the final identity sequentially; HTTPS, stream, metadata, text/binary WebSocket echo, interactive status and quit passed for each |
| Final embedding listener | Reused the same identity; public root, stream, actual TLS metadata, WebSockets and SIGINT shutdown passed |
| Final package plain/v1/v2 forwarding | Reused the same identity; public HTTPS response and each backend preamble passed, including v2 authority TLV |
| Cleanup | All five test identities deleted; authenticated API 404 and empty profiles confirmed; all owned processes stopped |

The final forwarding check used a private copy of `scripts/proxy-smoke/main.go`
that called `Ensure` on the existing test profile. Its deletion block was moved
to the enclosing test coordinator, so the CLI, listener and PROXY checks shared
one certificate before a single confirmed cleanup. Raw logs and helpers stayed
outside the repo in private temporary storage.

A Go scanner comparison, ignoring comments and formatting, found identical
v0.3.0/v0.5.0 code tokens in `api.go`, `client.go`, `certificate.go`, `listener.go`,
`session.go`, `connection.go` and `protocol.go`. During the longer v0.5.0 run,
both clients independently read the same certificate record as `issuing`.
The version comparison did not reproduce a release-specific provisioning or
forwarding regression. The 120-second cutoff was too early to establish failure.
The successful 186-second CLI run demonstrates why the new five-minute default
can matter. Because the longer v0.5.0 run used a new identity, it does not prove
that extra waiting alone would have completed the earlier request.

The earlier `ACME server returned no nonce` was a terminal remote failure,
not a local deadline. These successful later runs do not explain that failure
or establish rate limiting. No deployed-server revision was verified.

The version-display command was added after these hosted checks. Its dispatch,
output and error handling passed local tests and rebuilt-binary checks. The
longer default was verified at the HTTP request boundary; the hosted CLI create
above used an explicit five-minute limit.
