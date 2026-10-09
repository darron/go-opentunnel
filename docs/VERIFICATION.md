# Local verification record

Verified on 2026-10-09, on macOS arm64 with Go 1.27.2 and
golangci-lint 2.14.0. Compatibility baseline:
OpenTunnel commit `22156aa6ab209515186c3ca4f111901b7cedc284`.

## Acceptance checks

| Command | Result |
| --- | --- |
| `make check` | Tests, vet, lint, and CLI/example builds passed |
| `go test -race -count=1 ./...` | Both tested packages passed; example built |
| `go test -race -run 'TestLifecycle\|TestTunnelStalledChannel\|TestTunnelRoutesReconnect' -count=10 .` | All repeated stress regressions passed |
| `golangci-lint run ./...` | 0 issues, across library, tests, CLI, and example |
| `golangci-lint fmt --diff` | No formatting differences |
| `GOTOOLCHAIN=go1.25.0 go test ./...` | Declared minimum Go version passed |
| `GOOS=linux GOARCH=amd64 go build -o bin/otgo-linux-amd64 ./cmd/otgo` | Passed |
| `GOOS=windows GOARCH=amd64 go build -o bin/otgo-windows-amd64.exe ./cmd/otgo` | Passed |
| `./bin/otgo help` | All diagnostic commands available |

The Linux/Windows results are compile checks, not runtime tests on those systems.
The example's local-only server returned the expected root response and all
three `/stream` chunks. Ctrl-C ended the process successfully.

## Parser fuzz smoke

Each command used `go test -run '^$' -fuzz '<name>' -fuzztime=5s .`.
All completed without failure. Execution counts include the local fuzz cache
and may differ on subsequent runs.

| Parser | Executions |
| --- | ---: |
| `FuzzDecodeFrame` | 499,333 |
| `FuzzDecodeControl` | 591,655 |
| `FuzzRouteForSNI` | 196,736 |

## Coverage of meaningful behaviors

The tests use real WebSocket connections, real TLS handshakes, and generated
test certificates against a local fake API and relay. They cover:

- Upstream shared vectors; strict HTTP statuses, authentication, ID escaping,
  response bounds, cancellation, delayed bodies, and redacted error messages.
- Local key/CSR generation, exact and wildcard certificate SANs, mismatched
  keys, validity periods, provisioning interruptions, resume, and failed-issuance
  recovery using the original key.
- Memory/file storage, upstream file layout, permissions, corruption,
  cancellation, copy isolation, traversal, symlinks, and pending transitions.
- Root/named routes, concurrent large transfers, TLS ciphertext at the relay,
  HTTP streaming, application WebSocket upgrade, half-close, rejected upstreams,
  bad TLS, duplicate IDs, limits, unknown controls, heartbeat, drain, reconnect,
  route updates, renewal, and deletion.
- Cancellation before attachment, reset of a blocked upstream, stalled-channel
  isolation, renewal racing deletion, final route names racing teardown,
  bounded outbound queue cancellation, concurrent snapshots/close, and lossy
  event buffering.
- CLI help, flag validation, cancellation, JSON null/results, credential
  redaction, remote inspection, terminal sanitization, and interactive-reader
  shutdown.

An independent integrated code review found lifecycle issues that were fixed
with regression tests. Follow-up review found no remaining important code blocker.
This is a development review, not an independent security audit.

## Public artifact checks and remaining gap

Source, docs, and the initial design commit were checked for private filesystem
paths and common credential patterns. The only committed private-key-shaped
fixture is explicitly invalid text containing `KEY`; functional test keys and
certificates are generated during tests. Build artifacts and local profile
directories are ignored. The project includes an MIT license, and copied
upstream vectors retain their upstream MIT notice and commit provenance.

The initial local acceptance was followed on 2026-10-09 by a deliberate live
exercise of the deployed API, certificate issuance, relay, CLI, and embedding
example. [LIVE_TESTING.md](LIVE_TESTING.md) records those results, the CLI stdin
bug found and fixed, and cleanup of both temporary tunnels. The complete local
check and race suite were rerun after the fix. Confidence is high in the covered
local and live behaviors; long-term renewal, production server drain, and runtime
behavior on other operating systems remain outside this short live exercise.
