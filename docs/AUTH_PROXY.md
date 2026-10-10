# Protect a backend with otgo

`otgo proxy` protects every backend path and method, including assets, HTTP MCP,
SSE and WebSockets. No backend route inventory is needed. Authentication belongs
to the CLI; the Go library keeps its existing API.

## Password setup

```sh
otgo auth init --profile inbox --upstream http://127.0.0.1:57732
otgo proxy --profile inbox
```

Setup provisions or reuses an OpenTunnel identity and prints a generated password
once. Save it in your password manager. Alternatively, use `--password-stdin` to
supply one line through stdin; the CLI does not echo it or accept it in a flag.
Open the printed HTTPS URL and sign in. Browser sessions last eight hours and
end on restart. Sign out at `/__otgo/logout`. A shared password grants whole-backend
access, without identifying individual people.

An upstream is an origin without a path prefix, query or embedded credentials.
HTTP requires exact loopback addresses or `localhost`; other origins require
HTTPS. Keep the backend listening on loopback to prevent another public listener
from bypassing the gate. Existing `connect` and `listen` commands expose handlers
directly; use **`proxy`** for authentication.

## Profiles and persistence

A profile names one saved tunnel and auth configuration. Different profiles can
run concurrently against different backends. An OS lock refuses two proxies for
one profile. Setup, replacement and reset require that profile to be stopped;
token commands work while its proxy runs.

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
password cannot be recovered from its verifier. To replace it or the backend,
stop the proxy and run `auth init --replace` with the new settings. Replacement
revokes machine tokens. `auth reset` removes known local auth files, retaining
the tunnel and GitHub App. `otgo remove` separately deletes the tunnel. Lock files
are retained to prevent simultaneous lock owners.

Auth storage is supported on macOS, Linux and BSD platforms with the required
file/lock APIs. **Windows authentication setup/startup is refused** until private
ACL validation is implemented; the SDK and other CLI commands remain available.

## GitHub login

Stop the proxy, then run:

```sh
otgo auth github --profile inbox --allow-user darron
otgo proxy --profile inbox
```

Open the temporary loopback URL and follow its buttons to GitHub. GitHub asks
you to approve App creation. otgo converts the registration code and privately
saves client credentials. It requests no repository permissions or webhook
deliveries. Owner approval remains a GitHub step. Repeat `--allow-user` as needed.

The allowlist stores numeric GitHub account IDs, so renames do not transfer access.
GitHub mode replaces password login; provider failures deny access without password
fallback. OAuth uses single-use browser-bound state and PKCE. Provider access tokens
are not persisted or forwarded to the backend.

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

Host/TLS SNI must match the public hostname. Browser writes/WebSockets require
the public Origin. Login/logout forms use CSRF tokens, bounded bodies and short
read deadlines; password hashing has a global rate limit and two concurrent slots.
Sessions use Secure, HttpOnly, SameSite=Lax host cookies.

Backend Host/Origin/Referer are adapted to its fixed origin, and redirects to that
origin are translated back. `/__otgo/` and `__Host-otgo-` cookie names are reserved.
Apps with hard-coded absolute URLs, another required origin or reserved names may
need their own proxy settings. Allowed users can exercise all backend functionality.
OpenTunnel's operator/certificate trust boundary still applies; see
[SECURITY.md](SECURITY.md) and [AUTH_PROXY_REVIEW.md](AUTH_PROXY_REVIEW.md).
