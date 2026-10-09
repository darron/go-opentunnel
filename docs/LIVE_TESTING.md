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
