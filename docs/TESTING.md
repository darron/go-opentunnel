# Run the tests

## Local checks

These commands do not create a public tunnel.

1. Check tests, vet, formatting, lint, and builds:

   ```sh
   make check
   ./bin/otgo help
   ```

2. Check concurrent behavior:

   ```sh
   make race
   go test -race -run 'TestLifecycle|TestTunnelStalledChannel|TestTunnelRoutesReconnect' -count=10 .
   ```

3. Run the focused hardening regressions:

   ```sh
   go test -run 'TestTunnelHandshakeRouteIsolation|TestConnectStartupContextDoesNotOwnLifetime' -count=1 .
   go test -run 'TestConnectExplicitLifetimeCancellation|TestConnectRejectsOverlappingRoutes' -count=1 .
   go test -run 'TestRuntimeFailedCertificateRecoversSameKey|TestExpiredIdentityAttachesToTriggerServerRenewal|TestFileStorage' -count=1 .
   go test -run 'Test(ChannelAbort|ChannelReset|WriterDiscards|QueuedSend|WriteDeadline|CleanupQueueSaturation)' -count=1 .
   go test -run 'Test(ForegroundCertificate|RemoveDuringForeground|DifferentExpiredRemote|Ambiguous|ResumeDoesNotRebind)' -count=1 .
   go test -run 'Test(CancellationAfterRemote|PendingPersistence|MalformedKnownCreation|TinyInboundFragments)' -count=1 .
   go test -run 'Test(APIErrorTag|RecognizedAPITags|AttachErrorCode)' -count=1 .
   go test -run 'TestInteractiveInvalidRoutes' -count=1 ./cmd/otgo
   go test -run 'TestEstablishedChannelIdleLimit|TestActiveChannelRenewsIdleDeadline|TestJSONOmitsUnsetEventTimes|TestAPI|TestIdentityFormatting' -count=1 .
   ```

4. Run a five-second fuzz smoke test for each parser:

   ```sh
   make fuzz
   ```

Local fixtures use a fake API/relay with real WebSockets, TLS handshakes, and
generated test certificates. They cover request encoding, redaction,
cancellation, storage, route ownership, SNI-to-route isolation, certificate
renewal, framing, forwarding, and CLI dispatch. Hosted API, certificate issuance,
and relay interoperability have a separate dated [live test record](LIVE_TESTING.md).
That record does not prove later hardening changes were revalidated live.
Recorded local results are in [VERIFICATION.md](VERIFICATION.md); current review
changes and remaining limits are in [HARDENING.md](HARDENING.md) and
[AMP_REVIEW.md](AMP_REVIEW.md).

## Lint scope and exceptions

`make lint` runs `golangci-lint fmt --diff` and `golangci-lint run ./...`.
It includes the package, tests, CLI, and example. There are no excluded package
or file patterns.

The version-2 [configuration](../.golangci.yml) enables standard linters plus
`bodyclose`, `durationcheck`, `errorlint`, `gocritic`, `gosec`, `nilerr`, `nilnil`,
`noctx`, `prealloc`, `unconvert`, and `wastedassign`.

| Exception | Reason and scope |
| --- | --- |
| `gosec G704` | Disabled in configuration: caller-selected TCP destinations are the SDK's purpose |
| `gosec G304` | Disabled in configuration: the storage implementation validates profile paths and rejects symlinks |
| `nilnil` | Local annotations: missing identities return `(nil, nil)` by the storage contract |
| `gosec G302` / `G404` | Local annotations: owner-executable private directories / non-cryptographic retry jitter |
| `gosec G204` | Local test annotation: `os.Executable()` selects the current test binary, never a caller-selected program |

The temporary-file cleanup also has a local `errcheck` annotation for best-effort
removal. These are documented exceptions; static analysis is not a security audit.

## Repeat a basic live test

This sequence creates a public tunnel. Use a dedicated profile and isolated
storage; keep its credentials until remote deletion succeeds.

1. In terminal A, build and start the loopback target. Leave it running:

   ```sh
   make build
   ./bin/webapp --local-only --addr 127.0.0.1:8080
   ```

2. In terminal B, create private test storage, provision, and connect:

   ```sh
   OTGO_TEST_DIR=$(mktemp -d)
   ./bin/otgo create --data-dir "$OTGO_TEST_DIR" --profile live-check --timeout 5m
   ./bin/otgo connect --data-dir "$OTGO_TEST_DIR" --profile live-check \
     --route @=127.0.0.1:8080 --interactive
   ```

3. Visit the printed HTTPS URL. Check `/stream` and a WebSocket connection to
   `/ws`. In the interactive CLI, run these commands in order. Check both public
   hostnames after adding `api`; check HTTPS again after restoring the root:

   ```text
   status
   routes @=127.0.0.1:8080 api=127.0.0.1:8080
   routes
   routes @=127.0.0.1:8080
   quit
   ```

4. In terminal B, delete the remote identity and check local cleanup. Then stop
   terminal A with Ctrl-C:

   ```sh
   ./bin/otgo remove --data-dir "$OTGO_TEST_DIR" --profile live-check
   ./bin/otgo profiles --data-dir "$OTGO_TEST_DIR" --json
   ```

Stopping the target server tests failed upstream connections for new visitors.
A bridge reconnect requires loss of the relay transport or a relay drain.

## Timeout rules

Put flags after the command. Negative durations are rejected.

| Flag | Default | Meaning |
| --- | --- | --- |
| Provisioning `--timeout` | `2m` | Bounds the full provisioning operation; `0` disables this CLI deadline |
| `connect --timeout` | `0` | Runs until Ctrl-C; a positive value bounds the full lifetime, including reconnects |
| `--request-timeout` | `0` | Selects the API's finite default of `15s`; a positive value overrides it |

At the package API, `Client.Connect(ctx, ...)` uses `ctx` only for startup. Set
`ConnectOptions.Lifetime` to make application cancellation stop the running
connection. The CLI passes its command context as both startup and lifetime, so
its positive `connect --timeout` still bounds the full command.

`TransportOptions.IdleTimeout` has no CLI flag. Zero disables it. A positive
value resets a channel after no application bytes move in either direction for
that duration. Choose a value longer than valid quiet periods and test streaming
or slow endpoints. `MaxInboundBytes` is separate: a large upload to a slow target
can overflow the per-channel buffer and reset even while bytes are arriving.

## Check security boundaries locally

1. Confirm a relay-selected route cannot override ClientHello SNI, including a
   client that sends no SNI.
2. Confirm expired certificates fail visitor handshakes and `Connect` waits for
   server renewal before returning.
3. Confirm plain HTTP accepts only exact loopback hosts and HTTPS downgrade
   or cross-origin redirects never reach the redirected transport.
4. Confirm identity JSON, `fmt`, and `slog` output omit test secret values. Direct
   `Token` and `PrivateKey` field access must still be treated as secret.
5. Confirm file removal preserves unrelated files, unmarked directories, and
   unsafe markers. Run Unix mode assertions only on non-Windows platforms.

Certificate recovery regressions also hold issuance indefinitely, remove the
profile, and check that all workers stop without recreating credentials. Repeated
failed responses test the shared CSR retry cooldown, eventual retry, and reset
after successful renewal. These run in the normal suite and under `-race`.

## Interactive stdin shutdown

`quit` stops scanning immediately without requiring EOF. On cancellation, the CLI
leaves inherited `os.Stdin` to process exit because closing it may not interrupt
a blocked native read. Tunnel/client cleanup still finishes before exit.

Other supplied closable readers are closed and joined; they must interrupt a
pending read. Regression tests use an open pipe and a child process whose native
stdin writer stays open:

```sh
go test -race ./cmd/otgo -run 'TestReadCommands|TestNativeStdin' -count=3
```
