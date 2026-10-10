# Authenticated HTTP proxy for otgo

Status: design direction approved on 2026-10-10. The XDG storage layout below
clarifies persistence. No proxy or authentication commands described here are
implemented yet.

## Purpose and boundary

Expose an existing HTTP application through OpenTunnel without changing that
application. Every upstream path and method requires authentication. Password
login comes first; GitHub OAuth is the second browser login mechanism. The first
application to validate is Plannotator Inbox on loopback.

Add a private authentication and HTTP proxy subsystem to `otgo`, built on
`Client.Listen`. Keep the public Go package and OpenTunnel protocol unchanged.
Each proxy serves one profile, its root tunnel hostname, and one fixed upstream
origin. Existing diagnostic and raw forwarding commands retain their behavior;
only the new proxy command offers this protection.

The backend and local account are trusted. Approved visitors can use the entire
proxied application, including its administration and agent APIs. This is an
authentication boundary, not application-specific roles or a sandbox. The hosted
DNS/certificate operator boundary remains as documented in [SECURITY.md](SECURITY.md).
The upstream must not have a separate publicly accessible ingress.

## Profiles, XDG paths, and restart behavior

A profile is a local nickname for a saved tunnel and its proxy configuration,
such as `inbox` or `mayfly`. It is not a visitor account or a security boundary.
The existing package accepts lowercase DNS-label names, with `default` selected
when no name is supplied. Different profiles normally represent different apps
and tunnel hostnames.

Use the same name to select these persistent locations:

| Contents | XDG location | Default for profile `inbox` |
| --- | --- | --- |
| Upstream URL, browser auth mode, password verifier, GitHub client credentials and approved account IDs, bound tunnel ID/hostname | `$XDG_CONFIG_HOME/otgo/<profile>/auth.json` | `~/.config/otgo/inbox/auth.json` |
| Machine-token IDs, hashes, and expiry times | `$XDG_DATA_HOME/otgo/<profile>/tokens.json` | `~/.local/share/otgo/inbox/tokens.json` |
| Existing OpenTunnel identity, API token, local TLS key, certificate/chain, and provisioning recovery records | `$XDG_DATA_HOME/opentunnel/<profile>/` | `~/.local/share/opentunnel/inbox/` |

The OpenTunnel location and its file format stay compatible with existing
profiles. The new auth configuration is private even though it lives under the
configuration directory: create application/profile directories with `0700`
and credential files with `0600` on Unix. Do not change permissions on shared
XDG base directories. Validate existing application/profile directories and
files before use, and refuse unsafe credentials rather than silently importing
them. Honor absolute XDG overrides; ignore relative XDG values and use their
specified defaults. See the [XDG specification](https://specifications.freedesktop.org/basedir/latest/).

The proxy reuses its saved upstream, password verifier or GitHub registration,
allowlist, machine-token registry, and OpenTunnel hostname on subsequent starts.
It does not create a new GitHub App or tunnel merely because the process restarted.
Bind auth configuration to the saved tunnel ID, hostname, and API origin; reject
a mismatch instead of silently associating it with another identity. A missing
bound tunnel is a setup error, not permission to create a replacement publicly.
Setup may explicitly provision and bind a new identity.

Browser sessions, pending OAuth states, and temporary setup state stay in memory.
Visitors sign in again after a restart, using the same password or GitHub account.
GitHub user access tokens are discarded after identity verification. Nothing
security-critical is stored in `$XDG_CACHE_HOME`; deleting cache must not change
the password, create an unprotected proxy, or lose the tunnel identity. No disk
session cache or state directory is needed for the initial implementation.

Retain the existing `--data-dir` override for OpenTunnel storage. Add
`--auth-config` for an explicit auth configuration file and `--token-file` for
an explicit token registry file; show the resolved paths through a local paths
command without printing file contents. An overridden tunnel directory must
still match the auth configuration's bound identity.

Normal stop retains all persistent files and the remote registration. Existing
`otgo remove` remains a tunnel operation; it does not erase separate proxy auth
files or delete a GitHub App. Proxy startup then fails on the missing bound
tunnel. Provide an explicit local auth-reset command for the known auth/token
files only, and report the GitHub App management URL for owner-controlled remote
cleanup. Never recursively delete unrelated files or remove a GitHub App as a
side effect of stopping a proxy.

## Authentication before forwarding

Every request passes through one gate before any backend request, routing,
redirect, stream, or WebSocket upgrade. New upstream endpoints automatically
inherit the gate; no backend route inventory or MCP detection is required.

- With a valid browser session, forward the request after browser Origin checks.
- With an explicitly configured, valid machine token, forward the request.
- Without credentials, return `401`. A browser page navigation may receive the
  local login page with that status, but is never redirected to the backend.
- Invalid or ambiguous credentials are rejected; do not silently fall back from
  an invalid supplied machine token to a valid cookie.
- Protect `HEAD`, `OPTIONS`, API requests, streams, and upgrade requests too.
  Do not exempt health checks, static files, CORS preflights, or discovery paths.

Only the proxy's own narrowly defined login, callback, and login-asset endpoints
are reachable without an established session. They never forward to the backend.
Reserve `/__otgo/` for these handlers and return `404` for unknown paths in that
namespace. Never use a client-supplied path as an authentication bypass rule.
Validate the public Host against the locally verified TLS SNI and profile
hostname; derive callback origins from the profile, not forwarding headers.

Support HTTP request/response streaming and authenticated WebSocket upgrades.
Reject `CONNECT` and unsupported upgrades. This command does not expose arbitrary
TCP protocols or stdio programs. Reject malformed HTTP and conflicting framing
rather than building a raw fallback around the gate.

## Passwords and browser sessions

Provide a setup command that creates a protected per-profile auth configuration
and either generates a strong password or reads one from a supplied file/stdin.
Do not accept passwords as command-line arguments. Display a generated password
only as the explicit result of that setup operation, never in status or events.

Store a random salt and a versioned PBKDF2-HMAC-SHA-256 verifier with at least
600,000 iterations, using Go's standard library. Bound password lengths, login
bodies, hash concurrency, and login attempt rates. A global bound is necessary
because relay-supplied source addresses are not independently authenticated.
Use constant-time verifier comparison and generic failure messages. See
[OWASP password storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

Use opaque, cryptographically random session IDs and a bounded in-memory session
store. Default sessions expire after eight hours; restarting the proxy invalidates
them. Set a unique `__Host-` session cookie with `Secure`, `HttpOnly`, `Path=/`,
no Domain attribute, and `SameSite=Lax`. Apply CSRF protection to password login
and logout, and require an exact public Origin for browser state-changing
upstream requests. Do not interpret a sibling tunnel as a trusted browser origin.

Check sessions on every request. Logout invalidates the session. End authenticated
streams and WebSocket connections when their credentials expire or are revoked;
shutdown must close hijacked connections too. Bound session, OAuth-state, and
active-stream bookkeeping and join their workers during shutdown.

Auth directories are private to the account; configuration files use restrictive
permissions and atomic replacement. Serialize configuration/token mutations
across local processes so a concurrent write cannot undo a token revocation.
Reject symlinks and unsafe file modes on Unix. Windows requires an appropriate
account ACL. Configuration does not appear in JSON status, struct formatting,
logs, errors, or committed examples.

## Machine clients and HTTP MCP

Recommended initial compatibility: optional opaque bearer tokens, generated by
`otgo` for a single proxy profile, with explicit expiry. They are separate from
passwords, browser cookies, tunnel API tokens, and GitHub access tokens. Store
only their hashes and public IDs. Default lifetime is one hour; cap it at
24 hours. Token creation, listing, and revocation are local operations.

Keep the token registry separate from the main auth configuration. Reload its
small, bounded contents before authorization and during active-stream checks;
missing, malformed, or unreadable registry data denies machine access. Atomic
updates allow revocation to affect new requests immediately and active streams
within a bounded polling interval of at most one second. Never expose a public
token-minting endpoint in this first design.

Give machine tokens a reserved `otgo_` prefix. Accept them through
`Authorization: Bearer <otgo-token>` or a dedicated `X-Otgo-Token` header for
clients whose backend also needs its own Authorization header. Only a bearer
value with that reserved prefix is a gate credential; unrelated backend
Authorization values still require a valid gate cookie or `X-Otgo-Token`.
Reject duplicate/ambiguous gate credentials. Consume gate credentials before
proxying; never send them to the upstream. A token grants the same
whole-application access as a browser session, not a particular MCP tool or path.

HTTP MCP POSTs and event streams use the same gate as other HTTP requests. MCP
session identifiers are not authentication credentials. A client supporting
custom headers can supply an `otgo` token. A client unable to authenticate receives
`401` and never reaches the upstream. Unknown protocols carried inside HTTP do
not bypass the gate.

This is not automatic MCP OAuth interoperability. MCP-native browser authorization
also requires resource metadata, authorization-server discovery, client
registration, PKCE, and access tokens bound to the resource. GitHub browser login
alone does not provide those services. Do not advertise OAuth discovery that the
proxy has not implemented, or accept a GitHub token as an `otgo` token. Full MCP
OAuth is a separate scope decision; the proposed initial implementation uses
manual machine tokens. See the [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).

## GitHub login and setup

The second mechanism uses the GitHub authorization-code flow with single-use,
expiring, browser-bound state and PKCE S256. Exchange the code over verified
HTTPS, retrieve the authenticated user, check the allowlist, then issue the same
local session type as password login. Discard GitHub access/refresh tokens after
identity verification; do not give them to browsers or backends. Limit external
responses, set timeouts, and sanitize provider errors.

Resolve configured usernames to numeric GitHub account IDs during setup and
persist those IDs. Username changes do not transfer access to a different account.
Require a nonempty allowlist before accepting public traffic. Select one browser
login mode per proxy; enabling password fallback alongside GitHub would be an
explicit later policy, not an automatic fallback on OAuth failure.

Support manually configured OAuth App client credentials, including an existing
registration with an exact callback for this profile. For the easiest guided
setup, register a GitHub App through GitHub's supported manifest flow instead.
GitHub Apps also support OAuth user login. The wizard provisions/reuses the tunnel
identity without forwarding to the upstream, prepares the exact callback and
minimal registration, opens a local setup page, and lets the owner approve app
creation on GitHub. Validate single-use state on the setup callback, exchange the
manifest code, and save the returned client credentials privately. Do not retain
or print the unused app signing key or webhook secret. Disable webhooks and
request no repository write permissions.

The wizard automates form/configuration work, not the owner's GitHub sign-in and
Create App click. Local setup handlers expire, enforce loopback Host/Origin rules,
and close when finished. Cancellation or a failed save reports the created app's
public management URL for cleanup without printing credentials. Never enable an
unprotected proxy during setup. A headless/manual credential path remains
available.

Sources: [GitHub App manifest flow](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest),
[manifest conversion API](https://docs.github.com/en/rest/apps/apps#create-a-github-app-from-a-manifest),
and [GitHub App OAuth user login](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app).

## Proxy behavior and compatibility

Use `net/http` and `httputil.ReverseProxy`. Select a fixed upstream from startup
configuration; visitor URLs and headers cannot select another target. Do not
follow upstream redirects server-side. Loopback is the normal upstream; verified
HTTPS is available for remote upstreams. Strip visitor-supplied forwarding and
identity headers before setting any proxy-owned metadata. Never use those headers
as evidence of HTTPS or visitor identity.

Remove gate cookies and credentials before forwarding and prevent the upstream
from setting reserved gate-cookie names. Preserve unrelated application cookies
and Authorization headers. Set backend Host to the configured upstream authority.
After validating browser Origin at the public edge, adapt same-origin requests
to that fixed upstream origin when necessary, without accepting a foreign Origin.
Translate redirects that refer to the configured upstream back to the public
origin; preserve intentionally external redirects. Do not rewrite arbitrary
HTML/JavaScript or weaken upstream TLS verification.

A backend with hard-coded localhost URLs, unusual cookie/domain requirements, or
its own incompatible authentication can still need application configuration.
Generic protection can be guaranteed without per-backend endpoint configuration;
universal application compatibility cannot. Compatibility failures remain closed.

## Delivery and verification

1. Implement password setup, sessions, the universal gate, the HTTP proxy, and
   optional machine tokens. Keep provider selection behind a small private seam.
2. Add GitHub identity verification, allowlist setup, and the registration wizard.
3. Exercise the installed Plannotator Inbox through the tunnel: assets, live
   updates, opening threads/attachments, submitting a reply, and reconnection.
   Use a dedicated test thread, not an unsolicited message to another person.

Tests must show zero upstream requests for rejected requests across paths and
methods, including encoded paths, unknown endpoints, spoofed headers, cookies,
MCP POST/GET/DELETE, discovery URLs, and WebSocket upgrades. Test CSRF, session
fixation, expired/revoked credentials, duplicate credentials, secret redaction,
bounded resource use, malicious upstream cookies/redirects, OAuth replay and
provider failures, setup cancellation, and shutdown of streams/hijacked sockets.

Use a generic test backend for uploads, HTTP streaming, WebSockets, redirects,
application cookies, and both supported and unsupported machine-client behavior.
Run the repository's full tests, race checks, vet, build, and golangci-lint.
Repeat CLI and embedded-app regression tests. Record verification and live-test
limits in the repository; use temporary test identities and remove them afterward.
No version bump or release is part of this work.
