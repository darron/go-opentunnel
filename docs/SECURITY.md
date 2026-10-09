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

## Credential and TLS safeguards

- Generate private keys locally; never send them to the API.
- Keep tokens and private keys out of logs, shared files, and struct formatting.
  `Identity` and `PendingIdentity` omit those fields from JSON.
- Restrict storage to the account running the app. Unix directories use `0700`
  and credential files use `0600`. A profile name is not a security boundary.
- Use normal HTTPS certificate verification for the API and bridge. The client
  has no flag to disable it.
- Visitor TLS requires TLS 1.2 or newer. ECDSA keys restrict TLS 1.2 to
  forward-secret ECDHE suites; TLS 1.3 uses ephemeral key exchange.

Use `NewFileStorage` for an application-owned protected directory, or
`NewXDGStorage` for the compatible default. Local tests check ciphertext at the
relay, certificate/key/SAN validation, and credential redaction. Those tests
establish the implemented boundaries; they are not an independent security audit
of the hosted service.
