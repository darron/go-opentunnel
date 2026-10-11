# Public-service validation

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
[HARDENING.md](HARDENING.md) for dispositions and remaining limits.


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
passed. The [Amp review record](AMP_REVIEW.md) describes accepted findings,
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

After fixing the [Amp/Oracle removal finding](AMP_REVIEW_V0.3.0.md), the rebuilt
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
