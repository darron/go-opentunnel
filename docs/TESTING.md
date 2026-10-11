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

3. Run the focused audit regressions:

   ```sh
   go test -race -count=1 -run 'Test(AggregateInbound|ConcurrentInbound|RelayMetadata|RelayEventRoutes|TLSHandshakeDiagnostic|CertificateRefreshAppliesChainOnlyChange|ConnectAndListenRecoverFailedRemoteCertificateInBackground|IdleDetection|Heartbeat|Pong|RejectedOpen|ReaderControl|Live)' .
   go test -race -count=1 -run 'Test(ProxyAdmissionLimit|TLSStreamRevocation|Token|MachineTokenRegistry|HandlerRejectsTokenStore|LegacyTokenRegistry)' ./internal/authproxy
   go test -count=1 -run 'Test(Version|AuthToken)' ./cmd/otgo
   ```

   These cover transport budgets and queues, diagnostic redaction, certificate
   recovery/installation, token boundaries, admission and actual TLS revocation.
   The full suite in steps 1–2 also checks earlier lifecycle, storage and protocol
   regressions. The [audit](SECURITY_AUDIT.md) explains which broken-code mutations
   these tests detect.

4. Run five-second parser fuzz smoke tests:

   ```sh
   make fuzz
   ```

5. Run the longer parser and authentication-boundary checks, using a patched
   supported Go toolchain:

   ```sh
   make fuzz-sustained
   go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
   ```

   Sustained fuzzing runs four protocol/routing targets plus the anonymous auth
   boundary for 45 seconds each, with two workers. Override `FUZZ_TIME` and
   `FUZZ_PROCS` for a longer bounded run. The auth property is zero backend
   requests without issued credentials; it does not replace OAuth provider,
   successful-login, TLS, or machine-token lifecycle tests.

Local fixtures use a fake API/relay with real WebSockets, TLS handshakes, and
generated test certificates. They cover request encoding, redaction,
cancellation, storage, route ownership, SNI-to-route isolation, certificate
renewal, framing, forwarding, and CLI dispatch. Hosted API, certificate issuance,
and relay interoperability have a separate dated [live test record](LIVE_TESTING.md).
Each entry identifies what was tested; it does not cover later changes.
Recorded local results are in [VERIFICATION.md](VERIFICATION.md). Read the
[security model](SECURITY.md) and [current audit](SECURITY_AUDIT.md)
for trust boundaries and tested limits. Earlier review decisions are in the
[archive](archive/README.md).

CI repeats the full suite on Go 1.25 for Linux and macOS. A separate current-Go
job runs the suite and `govulncheck`; a bounded eight-minute fuzz job saves any
new crash input for 14 days. These jobs do not create public tunnels.

## Check Go API documentation

Read the package overview and public contracts locally:

```sh
go doc .
go doc Client.Listen
go doc Client.Connect
go doc -all .
go test -count=1 -run '^Example' .
```

The route and memory-storage examples have expected output and run in the test
suite without network access. The Connect and Listen examples compile with the
suite but do not run automatically: they create public tunnels and have no
`Output` comment. Their Ctrl-C shutdown contexts are for an application process.

Maintain the package overview in `doc.go` and public contracts beside their
declarations. Explain defaults, absent results, concurrency and ownership where
they affect callers. Use Go doc links such as `[Client.Listen]` in source comments.
Do not commit generated HTML or add a documentation runtime dependency.

The [public API page](https://pkg.go.dev/github.com/darron/go-opentunnel) shows
published module versions, not untagged main changes. After publishing a release,
verify the new version and examples on that page. If it is missing, request it
through pkg.go.dev or fetch its version metadata from Go's module proxy; see
[pkg.go.dev's indexing instructions](https://pkg.go.dev/about#adding-a-package).

## Focused auth regressions

Auth regressions and the Homebrew updater:

```sh
go test -race ./internal/authproxy ./cmd/otgo
go test -count=1 ./internal/authproxy -run 'TestBothAuthModes|TestGitHubCallbackFailures|TestRejectedPasswordForms|TestGateLoginBounds|TestGateLoginLimiterAndConcurrency|TestGitHubSetup|TestPrivateRead|TestProxyBrowserFetchMetadata|TestProxyResponsePreservesSameOriginForms'
go test -count=1 ./cmd/otgo -run 'TestEmptyAuthProfile|TestFreshAuthInit|TestProxyTimeouts'
go test -race ./internal/authproxy -run 'TestRevocationAbortsTLS|TestRuntimeFormatting|TestSlowLoginBody|TestDeniedRequestBodies|TestAuthenticatedUpload'
python3 -m unittest discover -s scripts -p 'test_update_homebrew.py'
```

## Repeat the password proxy checks

An opt-in hosted auth test creates isolated profiles, exercises the password/token
gate, streaming/revocation/restart/multiple backends, then removes local credentials
and verifies remote deletion with API 404:

```sh
make build
python3 scripts/auth_smoke.py
```

The fixture becomes public only through the authenticated proxy. The test uses
normal public HTTPS trust and never prints passwords/token values. Failed cleanup
retains its private temporary directory and reports its location. GitHub owner
approval and browser/app integration are separate checks.

## Repeat GitHub browser checks

Use a dedicated profile and private storage overrides from [AUTH_PROXY.md](AUTH_PROXY.md).
Start an instrumented loopback backend such as the `scripts/auth-smoke` fixture.
Provision with `auth init`, then run `auth github --allow-user YOUR_LOGIN`, complete
the owner registration/identity approvals and start `proxy` with the same paths.

1. Visit the HTTPS root signed out; expect the GitHub login page. Anonymous MCP,
   assets and discovery must be denied without incrementing the backend counter.
2. Sign in; verify the root body and logout. Sign in again, restart the proxy and
   verify the old browser session no longer grants access.
3. Stop the profile; repeat `auth github` with the existing client ID, secret via
   stdin and an allowlist excluding your account. Restart and attempt login;
   expect denial and no backend body. Restore the original allowlist while stopped.
4. Exercise CLI token creation/revocation while running; check stripped gate
   credentials and no-store response headers. The password smoke automates the
   corresponding machine-client checks.
5. Stop owned processes, `auth reset`, `remove` the temporary identity and verify
   remote deletion. Delete the temporary GitHub App separately in its settings;
   local reset does not delete it.

Do not commit private configuration, tokens, callback URLs containing codes or
screenshots containing credentials. Dated observations and browser limitations
are in [LIVE_TESTING.md](LIVE_TESTING.md).

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
   make build build-example
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
| Provisioning and password setup `--timeout` | `5m` | Bounds the full provisioning operation; `0` disables this CLI deadline |
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

## TLS listener regression tests

```sh
go test -race -run '^TestListener' . -count=10
```

These tests carry real TLS through the protocol fixture and exercise direct
`http.Server.Serve`, handshake state, Secure cookies/origin construction, relay
peer metadata despite forged HTTP forwarding headers, wrong SNI, streamed HTTP,
WebSocket upgrades, admission/buffer bounds, stalled handshakes, idle cleanup,
renewal, pending recovery, reconnect, route conflicts with forwarding, terminal
errors, concurrent Accept, removal/client shutdown, and deadline-worker joins.
`otgo listen --route @` serves the public API's transport diagnostics. The webapp
example defaults to direct listening; `--forward` keeps the forwarding example.

Auth lifecycle race regressions:

```sh
go test -race ./internal/authproxy -run 'Test(GitHubSetupCancellation|LeaseCompletionWaitsForTransportAbort|CompletedLeaseCannotAbortReusedConnection|RevocationAbortsTLSWithoutCloseNotify)' -count=3
```

These cover cancellation before/during conversion and after persistence, callback
joining beyond graceful HTTP shutdown, and request completion during a paused
revocation close. The provider is an HTTP fixture; real GitHub evidence is in
[LIVE_TESTING.md](LIVE_TESTING.md).

## PROXY headers and certificate diagnostics

Run the local regressions without creating a public tunnel:

```sh
go test -race -count=5 -run 'TestProxy|TestTunnelProxy|TestRouteOptions|TestCLIProxyProtocol|TestCertificate.*(Failure|Cooldown|Retains)' .
go test -count=1 -run 'TestConnectProxyProtocolFlags|TestInteractiveProxyProtocol' ./cmd/otgo
go test -run '^$' -fuzz '^FuzzProxyPeer$' -fuzztime=5s .
```

`TestCLIProxyProtocolForwarding` builds and runs the CLI as an external process
against a local API/relay fixture. Real visitor TLS and a TCP backend verify
header-before-payload order, copied options in JSON status, live option clearing,
existing-stream continuity and clean quit. Other fixtures check every upstream
PROXY vector, malformed peers, mixed plain/proxy routes, route mismatch before
backend dial, partial writes and header deadlines. Certificate fixtures cover
Create, Ensure, Resume, Connect and background recovery, including errors.As,
retry cooldowns and secret-safe formatting, JSON and slog.

For a separate public-service check, run explicitly:

```sh
go run ./scripts/proxy-smoke
```

This creates **one temporary public tunnel**, tests plain/v1/v2 forwarding to a
loopback backend, deletes the tunnel and requires authenticated API 404 afterward.
It uses memory storage and prints only safe diagnostics. A provisioning failure
stops forwarding checks; cleanup still runs. It does not change saved profiles.
Read the dated [live results](LIVE_TESTING.md) before repeating it.

## Preview the auth pages

Render synthetic pages without a tunnel, real credentials or a GitHub App:

```sh
preview_dir=$(mktemp -d)
OTGO_UI_PREVIEW_DIR="$preview_dir" go test ./internal/authproxy -run '^TestVisualPreview$' -count=1
python3 scripts/ui-preview/serve.py "$preview_dir"
```

Open `http://127.0.0.1:58941/github-login`. Other fixture paths are
`/password-login`, `/setup`, `/manifest`, `/complete`, `/complete-long` and
`/logout`. The server binds loopback and applies the rendered pages’ CSP headers;
fixture cookies are discarded. This is a visual/copy-button preview, not a
working login or setup server. Do not submit its GitHub App creation form.

Check phone widths, keyboard focus, long commands and copy/paste. The completion
page must remain usable after stopping the preview server with Ctrl-C: its logo,
styles and clipboard script are embedded in the HTML. A denied or unavailable
clipboard selects the command for manual copying.
