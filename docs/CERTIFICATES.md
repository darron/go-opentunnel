# Diagnose certificate issuance failures

These additions are on `main`; they are not included in v0.5.0 binaries.

A failed certificate request now returns `*CertificateIssuanceError`. Existing
`errors.Is(err, opentunnel.ErrCertificateIssuance)` checks continue to work.

The CLI prints a safe classification and the HTTP status when the provider
includes one, for example:

```text
opentunnel: certificate issuance failed: rate_limited (HTTP 429)
```

This is a classification of the remote reason, not an independent diagnosis.
It distinguishes a reported rate limit from the previous generic failure; it
does not identify the provider's quota, retry time or deployed server version.
No new retry policy is added. Failed renewal still observes the existing recovery
cooldown; interrupted provisioning retains pending credentials for `otgo resume`
or cleanup with `otgo remove`.

## Inspect in Go

```go
var failure *opentunnel.CertificateIssuanceError
if errors.As(err, &failure) {
    // Safe for routine logs; both fields contain normalized values.
    log.Printf("certificate failure: code=%s status=%d", failure.Code, failure.StatusCode)
    // failure.Reason holds up to 4096 bytes of raw remote text.
    // Inspect it privately and redact it before sharing.
}
```

Raw reasons are untrusted and may contain sensitive values or terminal controls.
Normal fmt output (including `%+v` and `%#v`), JSON and slog omit that text.
Deliberate access to `Reason` bypasses this protection. Low-level
`Client.API().Certificate` also returns the raw remote certificate state.

## Classifications

| Code | Recognized provider indication |
| --- | --- |
| `rate_limited` | ACME `rateLimited`, rate-limit wording, or HTTP 429 |
| `dns_error` | ACME `dns` or DNS error/failure/problem wording |
| `authorization_failed` | ACME `unauthorized` / `rejectedIdentifier`, or authorization-failed wording |
| `timeout` | Timeout wording, HTTP 408 or 504 |
| `bad_csr`, `bad_nonce`, `caa_error` | Corresponding ACME problem type |
| `account_error`, `account_action_required` | Missing account or required account action |
| `challenge_failed`, `connection_error`, `tls_error` | Corresponding ACME validation failure |
| `malformed_request`, `server_error`, `unsupported_identifier` | Corresponding ACME problem type |
| `unknown` | Reason does not match a known classification |

`StatusCode` is zero when no recognized `HTTP NNN` status is present. An unknown
failure still retains its bounded reason for deliberate inspection through
`errors.As`. Avoid repeated fresh tunnel creation to diagnose a failure: check
one existing pending request and its provider reason first.
