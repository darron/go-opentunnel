# Protect a backend with otgo

`otgo proxy` protects every backend path and method, including assets, HTTP MCP,
SSE and WebSockets. No backend route inventory is needed. Authentication belongs
to the CLI; the Go library keeps its existing API.

## Password setup

1. Save the backend and create or reuse its tunnel:

   ```sh
   otgo auth init --profile inbox --upstream http://127.0.0.1:57732
   ```

   Save the generated password in your password manager; it is shown once.
   To supply your own, use `--password-stdin` with one line of 12–1024 bytes.
   The CLI does not echo passwords or accept them in flags.

2. Start the proxy:

   ```sh
   otgo proxy --profile inbox
   ```

3. Open the printed HTTPS URL and sign in.

Browser sessions last eight hours and end on restart. Sign out at
`/__otgo/logout`. A shared password grants whole-backend access without
identifying individual people.

An upstream is an origin without a path prefix, query or embedded credentials.
HTTP requires exact loopback addresses or `localhost`; other origins require
HTTPS. Keep the backend listening on loopback to prevent another public listener
from bypassing the gate. Existing `connect` and `listen` commands expose handlers
directly; use **`proxy`** for authentication.

## Profiles and persistence

A profile is a name for one saved tunnel, backend and auth configuration.
Use a different profile for each backend. They can run concurrently on one
machine; a second proxy for the same profile is refused. Stop that profile's
proxy before setup, replacement or reset. Token commands work while it runs.

| Item | Default path |
| --- | --- |
| Auth configuration | `$XDG_CONFIG_HOME/otgo/PROFILE/auth.json`, otherwise `~/.config/otgo/PROFILE/auth.json` |
| Machine token hashes | `$XDG_DATA_HOME/otgo/PROFILE/tokens.json`, otherwise `~/.local/share/otgo/PROFILE/tokens.json` |
| Tunnel identity/key/certificate | `$XDG_DATA_HOME/opentunnel/PROFILE/`, otherwise `~/.local/share/opentunnel/PROFILE/` |

Relative XDG paths are ignored. `otgo auth paths --profile inbox` reports paths.
Override them with `--data-dir`, `--auth-config` and `--token-file`; use the same
overrides subsequently. Config binds to the stored tunnel ID, hostname and API
origin. Missing/mismatched state fails startup instead of silently provisioning.

Retrieve a hostname while running with `otgo get --profile inbox --json`. The
password cannot be recovered from its saved verifier.

| Task | Command while the profile is stopped |
| --- | --- |
| Change the password or backend | `otgo auth init --profile inbox --replace --upstream http://127.0.0.1:57732` |
| Remove local auth settings, retaining the tunnel and GitHub App | `otgo auth reset --profile inbox` |
| Delete the tunnel | `otgo remove --profile inbox` |

Every `auth init` revokes machine tokens, including leftover tokens when the auth
configuration is missing. Lock files remain to prevent simultaneous lock owners.

Auth storage is supported on macOS, Linux and BSD platforms with the required
file/lock APIs. **Windows authentication setup/startup is refused** until private
ACL validation is implemented; the SDK and other CLI commands remain available.

## GitHub login

First complete password setup to save the backend and tunnel.

1. Stop that profile's proxy and start GitHub setup:

   ```sh
   otgo auth github --profile inbox --allow-user darron
   ```

   Replace `darron` with your GitHub login. Repeat `--allow-user` for other accounts.

2. Open the exact temporary loopback URL printed by the CLI. Follow its buttons
   to GitHub and approve App creation. It requests no repository permissions or
   webhook deliveries. otgo saves the client credentials privately.

3. Start the proxy:

   ```sh
   otgo proxy --profile inbox
   ```

The setup link works once and binds one browser, then redirects to
`/__otgo/github/setup` without the token. All setup routes use that prefix.
Another visitor cannot replace your setup browser; concurrent wizards use
distinct cookies.

Cancelling before credentials begin saving preserves the previous login mode.
Once saving begins, the command waits for it and reports the save result, even
if you interrupt it. No callback continues changing configuration after the
command returns. App creation at GitHub can precede local cancellation; check
your GitHub Apps list and remove an unused App if setup stops before conversion.

The allowlist stores numeric GitHub account IDs, so renames do not transfer access.
GitHub mode replaces password login; provider failures deny access without password
fallback. OAuth uses single-use browser-bound state and PKCE. Provider access tokens
are not persisted or forwarded to the backend. They are discarded after identity
lookup, rather than explicitly revoked at GitHub. Existing machine tokens retain
their lifetime when switching to GitHub login; revoke them separately if access
should change. Returning to password login through `auth init` resets machine
tokens, including when the backend stays the same.

GitHub browser sessions also last eight hours and end on logout or proxy restart.
Removing a GitHub authorization, deleting the App or suspending an account does
not immediately revoke an existing local session: GitHub identity is checked at
login. To revoke all browser access immediately, stop/restart the proxy. Stop it
before changing the allowlist; setup requires the profile lock.

For an existing OAuth/GitHub App, register
`https://HOSTNAME/__otgo/github/callback`, then use `--client-id ID` and
`--client-secret-stdin` with the allowlist. Manage/delete wizard-created Apps using
the printed settings URL. Cancelled/failed registration retains the previous local
mode. If creation succeeds but storage fails, the command prints a cleanup URL.

## Machine clients and MCP

```sh
otgo auth token create --profile inbox --ttl 1h
otgo auth token list --profile inbox
otgo auth token revoke --profile inbox --id TOKEN_ID
```

Creation prints a random whole-backend token once; only its hash is saved. Default
expiry is one hour, maximum 24 hours. Send `Authorization: Bearer TOKEN`. If the
backend needs its own Authorization value, send the gate token in `X-Otgo-Token`.
Gate tokens/cookies and spoofed forwarding/identity headers are stripped upstream.

HTTP MCP clients that can send a configured token can use it. Unauthenticated
clients receive 401, including for MCP discovery. This is not an MCP OAuth
authorization server: automatic negotiation/client registration is not implemented.
Stdio MCP is outside the HTTP proxy.

Credentials are rechecked on each request and every 250 ms during active streams.
Revocation, expiry or unreadable token state cancels streams and aborts their
transports without waiting for TLS close_notify. Completed requests/backend side
effects cannot be undone. Restart invalidates browser sessions and retains
machine tokens, hostname, password verifier/GitHub credentials and backend settings.

## HTTP behavior and trust

### Browser requests

Host/TLS SNI must match the public hostname. Browser writes/WebSockets require
the public Origin. For cookie-authenticated requests, browser fetch metadata
rejects foreign scripts, images, frames and API calls, while permitting top-level
GET navigation. Clients without that metadata still require the exact Origin for
writes and WebSockets; use explicit machine tokens for non-browser clients.
Login/logout forms use CSRF tokens, bounded bodies and short
read deadlines; password hashing has a global rate limit and two concurrent slots.
Sessions use Secure, HttpOnly, SameSite=Lax host cookies.

### Response caching

Authenticated backend responses override public caching directives with
`Cache-Control: private, no-store`, `Pragma: no-cache` and an expired `Expires`
value. Common CDN override headers are removed. This prevents compliant HTTP
caches from storing protected responses. It cannot erase content already seen
or prevent an allowed backend from saving content in browser application storage.

### Resource limits

Login resource limits protect the process, but do not guarantee availability
under attack. Password verification allows a burst of ten attempts, refills one
per second and uses two hashing slots. Malformed/oversized form encoding, invalid CSRF and busy hashing slots do not
spend that budget; an attacker with valid CSRF can still compete for it. GitHub
allows 256 pending logins with ten-minute expiry; a flood can fill those slots
and temporarily deny new logins. Pending states are not evicted to admit newer
ones. Tunnel connections also have a finite capacity; connection floods can deny
service before authentication. Slow login bodies are bounded and idle HTTP
keep-alive connections close after 30 seconds. Active authenticated streams do
not inherit a server-wide read/write timeout.

### Backend compatibility

Backend Host/Origin/Referer are adapted to its fixed origin, and redirects to that
origin are translated back. `/__otgo/` and `__Host-otgo-` cookie names are reserved.
Responses use `Referrer-Policy: same-origin` so ordinary same-origin forms keep
their Origin while external sites receive no referrer. An HTML meta policy,
sandboxed iframe or other backend behavior that produces `Origin: null` still
fails closed; this proxy does not rewrite arbitrary HTML.
Apps with hard-coded absolute URLs, another required origin or reserved names may
need their own proxy settings. Trust the backend’s code: its same-origin scripts
and service workers can act as the authenticated visitor and store already
received content. The gate does not sandbox an authorized application. Allowed users can exercise all backend functionality.
Read the [security model](SECURITY.md) for OpenTunnel's operator/certificate trust
boundary and the [v0.4.0 auth review](AUTH_SECURITY_REVIEW.md) for findings and fixes.
