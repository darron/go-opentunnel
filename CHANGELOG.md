# Changelog

## Unreleased

- Trigger Homebrew validation/updates on published stable releases, with manual
  retry support. Remove scheduled polling. The source hook uses a tap-only
  `HOMEBREW_TAP_TOKEN` with Actions write permission.

- Fix browser password login, logout and GitHub setup form submissions: preserve
  same-origin Origin headers while retaining strict Origin/CSRF checks. Successful
  password login redirects to `/`.


- Add `otgo proxy` to protect every route of a fixed HTTP backend with password
  or allowlisted GitHub login, without modifying the backend.
- Add named XDG auth profiles, concurrent proxies for different backends,
  persistent settings and expiring/revocable machine tokens, including HTTP MCP
  clients that can send configured tokens.
- Add guided GitHub App registration, OAuth state/PKCE protection and numeric
  account allowlists. Keep auth code private to the CLI.
- Harden auth storage, credential formatting, slow login bodies and stream
  revocation; refuse platforms without the required storage protections.
- Build only the CLI by default; add Homebrew installation and automated stable
  release updates to `darron/homebrew-tap`.
- Clarify local keys and operator-held wildcard certificates in the security doc.

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
- Address findings from an [Amp/Oracle security and correctness review](docs/AMP_REVIEW_V0.3.0.md).

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
  retests. Address the [initial review](docs/HARDENING.md) and
  [Amp/Oracle findings](docs/AMP_REVIEW.md).

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
