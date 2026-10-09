# Security model

Use loopback route targets and protect stored credentials. Ordinary relay
operation keeps application traffic encrypted, but the hosted domain operator
remains inside the HTTPS trust boundary.

## Who can see the traffic?

| Observer | What is visible |
| --- | --- |
| Normally operating relay | Encrypted TLS records and traffic metadata; no HTTP paths, queries, headers, cookies, bodies, or application WebSocket contents |
| Domain/certificate operator acting maliciously, or after compromise | Could obtain another trusted certificate and impersonate the tunnel hostname to visitors |
| Embedding process and local target | Decrypted application traffic, including anything written to their logs |
| Observer on the target's network path | Plaintext application bytes after local TLS termination; loopback keeps this path on the local host |

The visitor's TLS connection passes through the relay and terminates in the
embedding Go process. The outer HTTPS/WebSocket bridge is a separate authenticated
connection. Decrypting that outer connection does not decrypt visitor TLS.

## Domain and certificate authority

The hosted provider controls tunnel DNS and ACME DNS-01 authorization for
`*.opentunnel.xyz`. That authority could issue a certificate using a different
private key, terminate future visitor connections, and proxy them to your app.
This is a consequence of DNS/certificate authority, not evidence that the hosted
service intercepts traffic.

The client checks that its issued certificate matches its local private key.
That check cannot prevent a different certificate from being presented to
visitors. Excluding the provider from this trust boundary requires independently
verified key pinning or application encryption with independently authenticated
keys. Ordinary browser HTTPS to a provider-owned hostname does not provide that
independence.

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
[hardening guide](HARDENING.md) and the dated [live record](LIVE_TESTING.md).
