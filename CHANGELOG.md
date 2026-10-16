# Changelog

## Unreleased

## v0.13.0 — Custom CA trust and upstream compatibility — 2026-10-16

- Add `ClientOptions.CACertFile` and `NewHTTPClientWithCACert` for private or
  self-hosted API/relay certificates. Add PEM trust without replacing existing
  roots, disabling certificate verification, or changing visitor/backend TLS.
- Add `--ca-cert` to otgo commands and `OPENTUNNEL_CA_CERT`. Auth setup saves an absolute
  `ca_cert` path; proxy startup reuses it. Flags override the environment, then
  saved configuration. Profile and resume commands retain the selected CA path.
- Reject unreadable, empty, malformed and oversized bundles before connecting.
  Clone caller-owned HTTP/TLS configuration instead of mutating it.
- Test the Go WebSocket client against the exact OpenTunnel v0.5.2 server codec,
  pinned by commit and SHA-256, including fragmented messages, interleaved pings,
  binary channel IDs, payload boundaries and close handshakes. Repeat it in CI.
- Add TLS integration and CLI/config regression coverage. No Go runtime
  dependency or wire-protocol change is required for upstream v0.5.2.

[Compare v0.12.0 to v0.13.0](https://github.com/darron/go-opentunnel/compare/v0.12.0...v0.13.0)

## v0.12.0 — Identical release binaries through Homebrew — 2026-10-14

- Install the published GitHub binary archives through Homebrew, selecting
  macOS/Linux and arm64/amd64 automatically. Remove the Go build dependency and
  source-based `--HEAD` installation; development builds remain available with
  `make build`.
- Update the tap only after release binaries and checksums have been published.
  Verify all four archives against their individual and combined SHA-256 files,
  validate the candidate formula, and compare the installed executable with the
  release executable byte for byte before publishing the tap change.
- Preserve manual retry/backfill, numeric downgrade protection and isolated tap
  publishing. Add binary-formula migration and invalid-asset regression coverage.
- Check upstream's new ACME failure wording against existing certificate
  diagnostics. The upstream authorization cleanup/recovery fix is server-only;
  no service protocol or client runtime change is required.

[Compare v0.11.0 to v0.12.0](https://github.com/darron/go-opentunnel/compare/v0.11.0...v0.12.0)

## v0.11.0 — Long polling through authenticated proxies — 2026-10-13

- Remove the auth proxy's 15-second backend response-header deadline so long
  polls and slow responses can wait for headers without a proxy-generated `502`.
  Apply the behavior to every authenticated backend request.
- Preserve client cancellation, credential revocation/expiry and proxy shutdown
  for pending requests, along with existing request and connection limits.
- Add regression coverage for delayed response headers and pending-poll
  cancellation on client disconnect, browser logout and handler shutdown.

[Compare v0.10.0 to v0.11.0](https://github.com/darron/go-opentunnel/compare/v0.10.0...v0.11.0)

## v0.10.0 — Setup feedback and resilient API requests — 2026-10-13

- Show major steps during `otgo auth init`, with a terminal spinner, plain
  redirected progress and clean JSON output.
- Open the default browser for guided GitHub setup, retain the printed URL as a
  fallback, and add `--no-browser` for manual/headless use.
- Identify API and relay traffic as `opentunnel-go/<version>`, as requested by
  upstream, so it can be distinguished from the official CLI.
- Follow upstream transient API retry rules with bounded backoff and a total
  deadline. Retry safe certificate operations without replaying an uncertain
  tunnel creation; preserve HTTP status and redact remote error bodies.
- Use still-valid saved certificates after transient API checks, including rate
  limits and API timeouts. Refuse fallback after authentication, redirect-policy,
  TLS verification or malformed-response failures. Add pinned retry vectors and
  CLI/API regression tests.
- Attach CLI-only macOS and Linux binaries for amd64 and arm64, individual
  SHA-256 files and `SHA256SUMS` to published stable GitHub releases. Add verified
  builds, native smoke checks and safe retry/backfill support; keep Homebrew's
  existing source-build update flow.

[Compare v0.9.0 to v0.10.0](https://github.com/darron/go-opentunnel/compare/v0.9.0...v0.10.0)

## v0.9.0 — Metrics and connection diagnostics — 2026-10-12

- Raise the minimum Go version to 1.26 and update compatibility checks in CI.
- Add concurrent client, connection and control API statistics, independent of
  dropped lifecycle events, with an optional official Prometheus collector.
  Align shared metric names and labels with upstream under `opentunnel_client_`.
- Add `--metrics-listen` to `proxy`, `connect` and `listen`. Scrape a separate
  loopback listener with fixed labels that omit identities and credentials.
  Save `metrics_listen` in a proxy's config to reuse its address on startup;
  explicit flags override it, including an empty value to disable metrics.
- Count authentication outcomes, backend responses and observed certificate
  failures. Add safe certificate failure classes alongside existing error codes.
- Release inactive half-closed channels after 60 seconds by default. Ongoing
  traffic renews the timeout; `--half-close-timeout` and the library option
  allow longer quiet periods.
- Explain how to resume stored pending provisioning after a CLI deadline.
  Keep the hosted service protocol and existing Go APIs compatible.

[Compare v0.8.0 to v0.9.0](https://github.com/darron/go-opentunnel/compare/v0.8.0...v0.9.0)

## v0.8.0 — Dark auth pages and profile inventory — 2026-10-11

- Redesign password, GitHub, setup and logout pages with a dark theme, an original
  otgo SVG mark and a clear GitHub sign-in button. Artwork, styles and the
  completion page’s clipboard script are embedded; no remote assets are loaded.
- Show the saved profile, HTTPS URL and a copyable startup command after GitHub
  setup. Preserve custom storage/API flags and quote command arguments safely.
- Expand `otgo profiles` into a local inventory of profiles, public URLs, saved
  backends, login modes and proxy launch commands. Include pending and incomplete
  state without suggesting unsafe launches. `--json` now returns objects; use
  `--names --json` for an array of names.
- Keep the public Go API and OpenTunnel service protocol compatible. Add no
  runtime Go dependency; include artwork attribution and verification records.

[Compare v0.7.0 to v0.8.0](https://github.com/darron/go-opentunnel/compare/v0.7.0...v0.8.0)

## v0.7.0 — Security hardening and stronger verification — 2026-10-11

- Bind machine tokens to their saved tunnel/API/backend boundary. Unbound legacy
  tokens are denied; `otgo auth token reset` supports explicit reset and reissue.
- Limit aggregate inbound payload to 64 MiB per relay session, configurable with
  `TransportOptions.MaxInboundTotalBytes`, alongside the existing per-channel cap.
- Bound untrusted relay diagnostics, reject literal tunnel-token reflection, and
  keep visitor-controlled TLS errors out of close-event diagnostics.
  Prioritize heartbeats and rejection resets; check relay idle expiry independently.
- Reuse a valid local certificate while failed remote issuance recovers in the
  background, and install certificate-chain changes even when the leaf is unchanged.
- Preserve backend cookie syntax while stripping gate cookies, and preserve
  visitor connection ID zero in JSON lifecycle events.
- Add mutation-proven admission, version, token-binding and TLS regressions,
  anonymous-gate fuzzing, current-Go vulnerability checks and bounded sustained
  fuzzing in CI. Simplify the README and guides, documenting migration and
  verification evidence. No runtime dependency or OpenTunnel wire-format change.

[Compare v0.6.0 to v0.7.0](https://github.com/darron/go-opentunnel/compare/v0.6.0...v0.7.0)

## v0.6.0 — PROXY protocol and certificate diagnostics — 2026-10-11

- Add opt-in PROXY protocol v1/v2 forwarding per route, compatible with upstream
  OpenTunnel v0.5.0. v2 includes the authority TLV. Existing routes stay unchanged.
- Add `ConnectOptions.RouteOptions`, copied status options and atomic
  `Connection.SetRoutesWithOptions` updates. The CLI gains repeatable
  `connect --proxy-protocol route=v1|v2` flags and an interactive option command.
- Return typed certificate issuance failures with safe provider classifications
  and HTTP status, while retaining bounded raw reasons for deliberate inspection.
  Existing sentinel checks and recovery cooldowns remain supported.
- Allow five minutes by default for CLI provisioning and password setup, including
  DNS validation and certificate issuance. Explicit timeout overrides still apply.
- Add `otgo version` and `otgo --version` to show the binary version, full Git SHA
  and build state (`clean`, `dirty` or `unknown`) using Go's standard library.
- Add upstream byte vectors, real CLI/relay/TLS forwarding tests, route-isolation,
  bounded-write and diagnostic-redaction regressions. No dependency was added.

[Compare v0.5.0 to v0.6.0](https://github.com/darron/go-opentunnel/compare/v0.5.0...v0.6.0)

## v0.5.0 — Go API documentation and simpler guides — 2026-10-10

- Expand Go API documentation with a package overview, public field and method
  contracts, runnable local examples, and a pkg.go.dev link in the README.
- Simplify the README and auth setup instructions. Add a documentation index,
  put the protected proxy quick start before validation, and archive earlier
  reviews with updated links.
- Update the advertised client version. Public APIs, runtime behavior and
  dependencies otherwise remain unchanged from v0.4.0.

[Compare v0.4.0 to v0.5.0](https://github.com/darron/go-opentunnel/compare/v0.4.0...v0.5.0)

## v0.4.0 — Authenticated application proxy — 2026-10-10

- Add `otgo proxy` to protect every path and method of an existing HTTP backend
  with password or allowlisted GitHub login. Backend code does not need to change.
- Add guided GitHub App creation under `/__otgo/github/setup`, browser-bound
  one-use setup, OAuth state/PKCE and numeric account allowlists. GitHub mode has
  no password fallback and requests no repository permissions.
- Add persistent XDG auth profiles for multiple backends and concurrent proxies,
  hostname inspection while running, and expiring/revocable machine tokens.
  Compatible HTTP MCP clients can supply tokens; unauthenticated clients are
  denied. This does not implement MCP OAuth discovery/negotiation.
- Harden credential storage and formatting, password work limits, browser
  Origin/CSRF/fetch-metadata checks, protected-response caching, backend cookie
  handling and streaming revocation. New supplied passwords require 12–1024 bytes.
- Preserve same-origin form submissions and redirect successful password login
  to `/`. Bind setup cancellation to its save boundary and join callbacks before
  returning; serialize revocation closes with request completion.
- Reset machine tokens on every password initialization, normalize default-profile
  locks and tolerate safe atomic registry replacement without false revocation.
- Add Homebrew installation and release-triggered tap updates, with manual retry
  support and no scheduled polling. The default local build produces only the CLI.
- Keep the public Go API compatible with v0.3.0, add no external dependency and
  update the advertised client version. Clarify local keys, wildcard certificates
  and the hosted operator's HTTPS trust boundary.
- Add security regressions and document real password/GitHub testing, full
  CLI/embedding-app retests, and [Claude/Amp/Oracle review dispositions](docs/AUTH_SECURITY_REVIEW.md).

[Compare v0.3.0 to v0.4.0](https://github.com/darron/go-opentunnel/compare/v0.3.0...v0.4.0)

## v0.3.0 — Direct TLS listeners — 2026-10-10

- Add `Client.Listen` and `Listener` for serving HTTP handlers directly over
  OpenTunnel. Accepted connections retain the TLS handshake and relay-provided
  peer address; `Client.Connect` remains available for TCP forwarding.
- Share provisioning, certificate renewal, reconnects, route ownership, and
  bounded connection admission between listening and forwarding.
- Add `otgo listen`. Use direct listening by default in the webapp example,
  with `--forward` available to exercise the existing forwarding API.
- Preserve queued HTTP and WebSocket output on ordinary application close.
  Join package-owned workers, including write-deadline watchers, on shutdown.
- Fix profile removal reporting cancellation as a terminal listener error;
  removed listeners return `net.ErrClosed` with no terminal error.
- Add listener and shutdown regression tests, embedding examples, and
  [listener guidance](docs/LISTENER.md). Record local, hosted CI, and
  [public-service validation](docs/LIVE_TESTING.md#tls-listener-retest-2026-10-10).
- Update the advertised client version to match this release.
- Address findings from an [Amp/Oracle security and correctness review](docs/archive/AMP_REVIEW_V0.3.0.md).

[Compare v0.2.0 to v0.3.0](https://github.com/darron/go-opentunnel/compare/v0.2.0...v0.3.0)

## v0.2.0 — Security and correctness hardening — 2026-10-09

- Enforce TLS SNI route isolation and same-origin API/bridge redirects.
- Redact credentials in diagnostic output, constrain file-storage permissions
  and deletion, and sanitize remote error metadata.
- Improve certificate renewal and recovery, including failed or expired
  certificates, shared retry cooldowns, and removal during issuance.
- Separate startup context from connection lifetime. Fix blocked channel writes,
  deadline updates, cancellation cleanup, and recovery of deletion credentials
  after interrupted provisioning.
- Bound fragmented inbound allocation and add optional idle timeouts. Keep
  interactive CLI tunnels running after invalid route input.
- Add security and concurrency regressions, Linux/macOS CI, and documented live
  retests. Address the [initial review](docs/archive/HARDENING.md) and
  [Amp/Oracle findings](docs/archive/AMP_REVIEW.md).

[Compare v0.1.0 to v0.2.0](https://github.com/darron/go-opentunnel/compare/v0.1.0...v0.2.0)

## v0.1.0 — Initial release — 2026-10-09

- Introduce the native Go OpenTunnel client: provisioning, saved profiles,
  resumable certificate issuance, remote inspection, and deletion.
- Forward locally terminated TLS traffic to TCP targets, with route updates,
  reconnects, status, and events.
- Include the `otgo` diagnostic CLI, an embeddable webapp example, tests, and
  security and live-testing documentation.
- Use the MIT license and one dependency outside the standard library:
  `github.com/coder/websocket`.

[Initial release](https://github.com/darron/go-opentunnel/releases/tag/v0.1.0)
