# Security model

For the CLI gate, see [AUTH_PROXY.md](AUTH_PROXY.md) and the
[auth review](AUTH_PROXY_REVIEW.md). `otgo proxy` protects every backend path/method;
ordinary `connect` and `listen` do not add login protection.

Auth secrets require account-owned 0700 directories, regular 0600 files, bounded
strict JSON, no-follow opens, atomic replacement and OS file locks. Password
verifiers use PBKDF2-HMAC-SHA256 with 600,000 iterations and random salts. Generated
passwords/tokens use cryptographic randomness. Token hashes are reloaded on each
authentication; expiry/revocation aborts active streams. Browser sessions live in
memory and end on restart. Login uses CSRF, rate/concurrency limits and bounded
body reads. The operator guide specifies lifetimes and MCP compatibility limits.

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
an independent audit or current live revalidation of the hosted service. See the
[hardening guide](HARDENING.md), [Amp review](AMP_REVIEW.md), and the dated
[live record](LIVE_TESTING.md).

## Direct TLS listener

`Client.Listen` returns handshaken `*tls.Conn` connections for HTTP embedding.
Actual TLS/SNI validation stays in the package. `Request.TLS` is the real
handshake state; this does not authenticate a visitor with a client certificate.
`RemoteAddr` is the relay-provided peer string. The relay can forge it, so it is
not a separate proof of visitor identity. The package never uses HTTP forwarding
headers to infer TLS or peer state. See [the listener contracts](LISTENER.md).
