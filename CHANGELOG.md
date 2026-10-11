# Changelog

## Unreleased

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
