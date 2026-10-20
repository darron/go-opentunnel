# Security model

For setup, use the [auth guide](AUTH_PROXY.md). The
[current audit](SECURITY_AUDIT.md) records tested fixes and remaining limits.
`otgo proxy` protects every backend path/method;
ordinary `connect` and `listen` do not add login protection.

## Build toolchain

Release binaries and CI pin **Go 1.27.3**, which includes the `crypto/x509`
mitigation for [CVE-2026-111943](https://github.com/golang/go/issues/82345).
Upgrade otgo to v0.14.3 or newer. Library users must rebuild their own applications
with Go 1.27.3 or another patched, supported release; upgrading the module alone
does not patch the application's standard library. The `toolchain` directive
selects Go 1.27.3 for this checkout when automatic toolchain selection is enabled.

Use a patched, supported Go release for production builds. The module's Go 1.26
minimum is a source-compatibility contract; it does not mean that old toolchains
have current HTTP/TLS security fixes. Go supports a major release until two newer
major releases exist; see its [release policy](https://go.dev/doc/devel/release#policy).
Rebuild embedded applications as well as the CLI when updating Go. CI runs
`govulncheck` and the full suite on the pinned security-patched toolchain.

## CLI authentication

Auth secrets require account-owned 0700 directories, regular 0600 files, bounded
strict JSON, no-follow opens, atomic replacement and OS file locks. Password
verifiers use PBKDF2-HMAC-SHA256 with 600,000 iterations and random salts. Generated
passwords/tokens use cryptographic randomness. New supplied passwords require
12–1024 bytes. Private reads validate the opened descriptor, so atomic registry
replacement does not falsely revoke unrelated tokens. Token hashes are reloaded on each
authentication; expiry/revocation aborts active streams. Browser sessions live in
memory and end on restart. Login uses CSRF, rate/concurrency limits and bounded
body reads. Protected responses use `private, no-store` and override upstream
public caching policies; application storage and content already received by an
authorized visitor remain outside HTTP cache controls.

Machine-token registries are bound to the tunnel ID, hostname, API origin and
backend. Reusing one `--token-file` for a different boundary denies its tokens.
Legacy unbound registries fail closed; reset and reissue them as described in the
[auth guide](AUTH_PROXY.md#machine-clients-and-mcp). Switching password login to
GitHub with the same tunnel/backend retains bound machine tokens.

GitHub identity is checked at login, not on each request. Provider-side revocation
does not immediately end an eight-hour local browser session; logout or proxy
restart does. Bounded password work and GitHub pending-state storage can still
be crowded out by a login flood. These availability limits do not grant access
to the backend. Connection floods can still exhaust the outer transport limit;
idle HTTP connections close after 30 seconds. The operator guide specifies lifetimes and MCP compatibility limits.

GitHub requests carry a per-profile Ed25519-signed identity assertion. The
[backend verification guide](AUTH_PROXY.md#signed-backend-identity) explains
key pinning and exact request checks. Header stripping includes identity trailers;
password and machine-token requests carry no GitHub identity. A signature covers
identity and request routing fields, not the body. It can be replayed for the same
fields for up to 30 seconds, including after logout. Keep the backend hop on
loopback or HTTPS, and verify before trusting identity. The signing key is
separate from the tunnel TLS key; same-account compromise can steal either.

`auth verify` and `identity.InspectRequest` are diagnostics: they can report an
expired assertion's signed identity and timestamps. They do not authorize access.
Use `identity.VerifyRequest` in the backend; it always rejects expired assertions.

The setup wizard uses a one-use loopback capability and a browser-bound cookie;
all its routes use `/__otgo/github/setup`. Cookie-authenticated foreign
subresources are rejected using browser fetch metadata; normal top-level GET
navigation remains available. Backend responses use `Referrer-Policy: same-origin`.
HTML meta policies or sandboxing can still produce a refused null Origin. Treat
backend JavaScript and service workers as trusted application code: authentication
does not prevent them from acting as the visitor or retaining received content.

Windows auth storage is refused until private ACL validation is available; SDK
and other CLI commands remain available. Same-account compromise can read/replace
secrets despite file modes. Auth does not remove the hosted operator from the
HTTPS trust boundary: hostname impersonation could capture passwords, sessions
or bearer tokens. Use those credentials only for this backend.

Use loopback route targets and protect stored credentials. Ordinary relay
operation keeps application traffic encrypted, but the hosted domain operator
remains inside the HTTPS trust boundary.

## Who can see the traffic?

| Observer | What is visible |
| --- | --- |
| Normally operating relay | Encrypted TLS records and traffic metadata; no HTTP paths, queries, headers, cookies, bodies, or application WebSocket contents |
| Domain/certificate operator acting maliciously, or after compromise | Could actively impersonate the tunnel hostname using a different trusted certificate and its private key, exposing traffic from visitors who connect to that endpoint |
| Embedding process and local target | Decrypted application traffic, including anything written to their logs |
| Observer on the target's network path | Plaintext application bytes after local TLS termination; loopback keeps this path on the local host |

The visitor's TLS connection passes through the relay and terminates in the
embedding Go process. The outer HTTPS/WebSocket bridge is a separate authenticated
connection. Decrypting that outer connection does not decrypt visitor TLS.

## Local keys and visitor TLS

The client generates an ECDSA P-256 private key locally. It sends a signed
certificate signing request (CSR) containing the public key and requested
hostnames to the API; it never sends the private key. The certificate authority
issues a certificate binding those hostnames to that public key. The client
checks that the returned certificate matches its private key before using it.

For a genuine visitor connection to the embedding process, TLS protects the
application traffic from the relay. The public certificate and CSR do not let
the relay decrypt that traffic. The local private key authenticates the TLS
endpoint; ephemeral key exchange establishes the traffic keys. A different
certificate and private key cannot decrypt previously recorded genuine sessions.

## Domain and certificate authority

The hosted provider controls tunnel DNS and ACME DNS-01 validation for tunnel
hostnames under `opentunnel.xyz`. That authority could obtain a trusted certificate
using its own private key and direct future visitor connections to an endpoint
it controls. It could then decrypt those connections and proxy requests to your
app over a separate TLS connection. This attack does not require your local
private key or decrypt the original end-to-end sessions. It is a consequence of
DNS/certificate authority, not evidence that the hosted service intercepts traffic.

The client's certificate/key check cannot prevent a different valid certificate
from being presented to visitors. Excluding the provider from this trust boundary
requires independently verified key pinning or application encryption with
independently authenticated keys. Ordinary browser HTTPS to a provider-owned
hostname does not provide that independence.

### Wildcards and Certificate Transparency

The client requests a certificate for its own hostname, such as
`demo.opentunnel.xyz`, and `*.demo.opentunnel.xyz` for named routes. Those names
share its locally generated key. A separate operator-held certificate for
`*.opentunnel.xyz` would cover `demo.opentunnel.xyz`, but not
`api.demo.opentunnel.xyz`: a wildcard matches only one DNS label. See
[RFC 9525's wildcard rules](https://www.rfc-editor.org/rfc/rfc9525.html#section-7.1).

An operator that holds a valid covering certificate and its private key could
reuse them for impersonation without issuing another certificate.
[Certificate Transparency](https://certificate.transparency.dev/howctworks/)
logs certificate issuance, not each connection that uses a certificate.
Monitoring can make new issuance visible, but cannot reveal every use of an
existing certificate or prove who holds its private key. Using a wildcard
therefore does not remove the operator from the HTTPS trust boundary.

## Metadata and endpoints

The service can observe source addresses, tunnel and route names, SNI and other
ClientHello metadata, timing, connection counts, and encrypted byte volumes.
The [inspected upstream source](DESIGN.md#compatibility-baseline) logs routing
metadata and emits byte/duration analytics. OpenTunnel does not provide anonymity.

Route targets define where plaintext travels. `127.0.0.1:port` stays on the local
host; a LAN or Internet target exposes application bytes on that network path.
Endpoint processes, logs, and compromised endpoints can expose plaintext too.

The relay proposes a route for each channel, but the client verifies it against
the visitor's TLS ClientHello. SNI must select the same route name. Missing
SNI, a mismatched route, or an unrelated hostname is rejected before plaintext
reaches a target. Expired and not-yet-valid certificates are also rejected at
the visitor handshake.

## Local metrics

`--metrics-listen` starts a separate, opt-in loopback listener. It has no login:
other local processes can scrape it. It does not add a public authentication
exception. Labels contain fixed categories, never tunnel identities, usernames,
request paths, credentials or raw provider reasons. Activity and timing remain
visible. Keep the port local, or provide access controls if you forward it.
See [observability](OBSERVABILITY.md).

## API transport

Use HTTPS for any non-local API. Plain HTTP is accepted only for exact
`localhost` or a literal loopback IP. Names that merely resolve to loopback do
not qualify. Redirects must remain at the initial origin: scheme, case-insensitive hostname,
and effective port. Cross-origin redirects, subdomains, port changes, and HTTPS
downgrades are rejected before another request, including after a caller hook
changes the URL. A supplied `http.Client` is cloned. Its transport, cookie jar,
and redirect hook remain trusted code with access to credentials.

## Credential and TLS safeguards

- Generate private keys locally; never send them to the API.
- Keep tokens and private keys out of logs, shared files, and struct formatting.
  `Identity` and `PendingIdentity` omit those fields from JSON and redact them
  through `fmt` and `slog`. Their exported fields still contain the secrets;
  explicit field access, reflection, or a custom serializer can expose them.
- Unknown API error tags and attachment codes become generic diagnostics rather
  than retaining arbitrary server text. Recognized protocol errors remain typed.
- Relay session/peer metadata is bounded and becomes `unknown` if it contains
  control characters or the known tunnel credential. Event route lists are
  bounded too. These checks make diagnostics safer; they do not verify peer identity.
- Visitor TLS handshake errors use fixed diagnostics or trusted local error
  classifications. Raw TLS errors can include attacker-controlled ALPN and are
  not copied into connection-close events.
- A `ProvisioningError` contains secret recovery credentials when persistence
  and remote cleanup both fail. Handle it with `errors.As`, persist its pending
  record securely, or use its ID/token with `API.Remove`. Ordinary error rendering
  does not print the record.
- Restrict storage to the account running the app. New Unix roots and profiles
  use `0700`; credential files written by the file store use `0600`. Existing
  roots are left unchanged if group/others cannot write them, while
  group/other-writable roots are rejected. Profiles secured by a write are
  `0700`, so a read/traverse-only `0755` parent does not expose their credentials.
  A load does not repair imported file modes; audit existing storage first. A
  profile name is not a security boundary.
- Use normal HTTPS certificate verification for the API and bridge. The client
  has no flag to disable it.
- Visitor TLS requires TLS 1.2 or newer. ECDSA keys restrict TLS 1.2 to
  forward-secret ECDHE suites; TLS 1.3 uses ephemeral key exchange.

Use `NewFileStorage` for an application-owned protected directory, or
`NewXDGStorage` for the compatible default. On Windows, Unix mode bits do not
provide this protection; configure an appropriate ACL for the application
account.

`Storage.Remove` requires a regular completion or pending marker and removes
only known credential filenames. It preserves unmarked directories and unrelated
contents. The file store still uses path-based check-then-use operations, leaving
a same-user race, and replaces credential files individually, leaving a crash
consistency window. Do not treat it as protection from another process running as
the same account.

Local tests check ciphertext at the relay, SNI route isolation,
certificate/key/SAN validation, API redirect policy, credential redaction, and
storage deletion boundaries. Those tests establish local behavior; they are not
an independent audit of the hosted service. See the dated [live record](LIVE_TESTING.md)
for public-service checks and the [archive](archive/README.md) for earlier reviews.

## Direct TLS listener

`Client.Listen` returns handshaken `*tls.Conn` connections for HTTP embedding.
Actual TLS/SNI validation stays in the package. `Request.TLS` is the real
handshake state; this does not authenticate a visitor with a client certificate.
`RemoteAddr` is the relay-provided peer string. The relay can forge it, so it is
not a separate proof of visitor identity. The package never uses HTTP forwarding
headers to infer TLS or peer state. See [the listener contracts](LISTENER.md).

## Private API and relay CAs

[Custom CA trust](CUSTOM_CA.md) adds operator-selected certificates only to the
control API and relay HTTP transport. It preserves certificate/hostname checks
and redirect restrictions. Visitor TLS, backend trust and GitHub trust stay
separate. An added CA is trusted to issue certificates for client connections;
it does not change the domain operator impersonation boundary above.
