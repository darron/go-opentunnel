# Public-service validation

Date: 2026-10-09. Service: `https://opentunnel.xyz`.
Client platform: macOS arm64, Go 1.27.2. The public service's deployed source
revision was not established; the implementation's source compatibility baseline
remains upstream commit `22156aa6ab209515186c3ca4f111901b7cedc284`.

The exercise used the built `otgo`, the actual webapp embedding example,
an external Go program importing the public package, and Python standard-library
HTTP clients/loopback echo targets. No production application or existing user
profile was exposed. Two dedicated temporary identities were created: one was
fully provisioned; the other was removed while pending. Credentials were stored
in a private temporary directory outside the repository.

## Results

| Path | Actual check and result |
| --- | --- |
| Create and interrupted provisioning | Stopped `otgo create` at `requesting-certificate`; pending identity was already persisted and the cancelled process exited normally |
| Resume and certificate issuance | `otgo resume` completed against the real API; the returned certificate matched the locally generated key and required SANs |
| Completed/pending views | `profiles`, `list`, `get`, and `pending` returned the expected identities or empty results; JSON omitted tokens and private keys |
| Ensure and create conflict | `ensure` reused the existing tunnel ID; a repeated `create` returned `ErrExists` |
| Empty resume | `resume` after completion returned JSON `null` |
| Remote inspection | `inspect` reported offline before attachment, online while connected, and offline after orderly disconnection |
| Public HTTPS | Root responses matched the loopback example using normal public certificate verification; no insecure TLS option or test CA was used |
| Streaming | `/stream` returned three expected chunks incrementally, with more than 250 ms between receipt of the first and final chunks |
| Application WebSocket | Public WSS echoed both text and binary messages, each 16,000 bytes, then completed a normal WebSocket close |
| Named routes | Adding `api` triggered reattachment; both the root and named hostname forwarded correctly |
| Large transfer | A 2,097,152-byte HTTP POST was echoed exactly through the public named route |
| Concurrent transfers | Eight concurrent 262,144-byte HTTP POST/echo operations preserved their contents |
| Target-only replacement | Changing `api` to a second loopback target delivered that target's distinguishable response while status remained connected |
| Refused upstream | Replacing the named target with a closed loopback port failed that visitor request; the root route remained usable |
| Empty routes | The interactive `routes` command with no entries suspended attachment in `waiting-routes` |
| Restore routes | Restoring the root route reattached and served public HTTPS again |
| Interactive quit | With the input pipe writer still open, `quit` exited with status 0 and the service subsequently reported offline |
| CLI deadline | `connect --timeout 4s` exited with status 1 and `context deadline exceeded`, with stdin still open |
| CLI Ctrl-C | SIGINT stopped an interactive CLI with open stdin and exited with status 0 |
| SDK embedding | An external Go executable imported the package, connected using file storage, and served public HTTPS |
| Actual bridge reconnection | The importing program closed only its own upgraded bridge transport; it observed `reconnecting`, then a new `connected` event and a successful new HTTPS request |
| SDK close | `Client.Close` returned after `Connection.Done` closed and status became stopped |
| Actual webapp embedding | The example without `--local-only` owned its own SDK connection, served public HTTPS, and exited with status 0 on SIGINT |
| Delete while active | `Client.Remove` stopped and joined its owned active session, removed the local identity, and authenticated remote inspection returned HTTP 404 |
| Pending deletion | A second creation was interrupted before completion; `otgo remove` deleted that pending remote tunnel and its local files |
| File permissions | The live pending profile directory was 0700; its stored files were 0600 |
| Idempotent cleanup | A repeated `remove` succeeded; final profile/tunnel lists were empty and `get`/`pending` returned JSON `null` |

The 2 MiB transfer's SHA-256 was
`bc2c7f3922bfe264439943832357087870faedd70bea44b518fd7856c6c234a1`.
Both temporary tunnels were deleted and all test server/bridge processes stopped.
No real tokens, private keys, or raw credential-bearing artifacts were committed.

## Bug found by the live exercise

The first interactive run completed the traffic checks but hung on `quit` when
the stdin writer remained open. A native-process goroutine trace established
that cleanup was waiting for the scanner, which had already entered its next
blocking OS read. Closing the inherited stdin file did not release that read.

The fix stops scanning immediately after enqueueing `quit`. On cancellation,
the CLI does not close or join process-owned native stdin; its ordinary defers
still stop and join the tunnel/client, then process exit ends the reader. This
change is confined to the CLI, not the embeddable package.

`TestReadCommandsStopsAtQuitWithoutEOF` failed before the fix and passed after it.
`TestNativeStdinCancellationDoesNotWaitForEOF` runs a real child test process with
an inherited pipe whose writer stays open. The live traffic sequence was repeated
after the fix, and quit, deadline, and SIGINT shutdown all passed.

The final acceptance checks also passed:

```sh
make check
go test -race -count=1 ./...
go test -race ./cmd/otgo -run 'TestReadCommands|TestNativeStdin' -count=3
```

The repository-wide golangci-lint result was **0 issues**. The test subprocess
uses `os.Executable()` to select the current test binary; its localized `G204`
annotation explains why that invocation is intentional.

## Repeating the basic live sequence

Use an isolated storage directory, and keep the local target running while
the bridge is attached:

```sh
make build
OTGO_TEST_DIR=$(mktemp -d)
./bin/webapp --local-only --addr 127.0.0.1:8080
```

In a second terminal, use the same value of `OTGO_TEST_DIR`:

```sh
./bin/otgo create --data-dir "$OTGO_TEST_DIR" --profile live-check --timeout 5m
./bin/otgo connect --data-dir "$OTGO_TEST_DIR" --profile live-check \
  --route @=127.0.0.1:8080 --interactive
```

Visit the printed root HTTPS URL and `/stream`, and connect a WebSocket client
to `/ws`. In interactive mode, use `status`, add a named route with
`routes @=127.0.0.1:8080 api=127.0.0.1:8080`, suspend with `routes`, restore
with `routes @=127.0.0.1:8080`, and finish with `quit`.

Remove the temporary remote identity before discarding its credentials:

```sh
./bin/otgo remove --data-dir "$OTGO_TEST_DIR" --profile live-check
./bin/otgo profiles --data-dir "$OTGO_TEST_DIR" --json
```

## Limits of this exercise

The live run establishes the listed interoperability paths at this date. It
does not establish every possible input or long-running production behavior.
Automatic long-term certificate renewal, server-initiated drain, malformed relay
messages, fatal attach codes, heartbeat expiry, bounded queue/buffer overflow,
TLS half-close, and renewal racing deletion have deterministic local fixture
coverage. Those conditions were not all induced against the hosted service.

Linux and Windows were compile-checked, not runtime-tested. No independent audit
of the hosted operator or infrastructure was performed. The domain/certificate
operator trust boundary remains as documented in [SECURITY.md](SECURITY.md).
