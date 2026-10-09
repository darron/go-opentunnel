# Public-service validation

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
