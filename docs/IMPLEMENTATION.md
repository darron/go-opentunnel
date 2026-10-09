# Implementation

The public package is an OpenTunnel client; `cmd/otgo` is a consumer of the same
API exposed to embedding applications. The module is
`github.com/darron/go-opentunnel`, requires Go 1.25 or newer, and is MIT licensed.
Its sole external module is `github.com/coder/websocket v1.8.15`.

## Components

- `api.go` implements the HTTP lifecycle endpoints with finite request deadlines,
  bounded responses, escaped endpoint IDs, typed errors, and response-body ownership.
- `protocol.go` validates routes and control messages and encodes the four-byte,
  big-endian connection ID used in binary bridge frames. Shared upstream vectors
  and their license/provenance are under `testdata/vectors/`.
- `certificate.go` generates P-256 keys and CSRs locally and verifies returned
  certificates against the key, validity period, exact hostname, and wildcard SAN.
- `storage.go` implements concurrent memory storage and the upstream-compatible
  file layout. File writes use private temporary files and atomic replacement,
  with metadata last. Profile and credential symlinks are rejected. The file
  format does not provide a cross-process transaction or lock.
- `client.go` serializes lifecycle mutations per profile, persists pending state
  before certificate submission, resumes provisioning, and owns cancellation of
  its operations and connections. A confirmed remote deletion uses a bounded
  cleanup context to remove local credentials even if its caller cancels.
- `connection.go` owns reconnects, route snapshots, status, bounded events, and
  certificate refresh. Name changes trigger a new attachment; target changes
  apply to newly opened channels. Empty replacement routes suspend attachment.
- `session.go` owns bridge attachment, framing, heartbeats, channel dispatch,
  and a bounded write queue. `channel.go` terminates visitor TLS locally and
  forwards bidirectional streams, including half-close, to the selected target.
  Per-channel cancellation closes blocked upstream sockets independently.

## Ownership and resource bounds

The connection context lasts for the entire bridge lifetime. `Connection.Close`
cancels and joins its workers; `Client.Close` cancels and joins the operations and
connections it owns. Low-level calls through `Client.API()` retain their own
context ownership. Custom storage must honor cancellation.

Default limits are 256 channels, 8 MiB of pending inbound bytes per channel,
256 queued events, a 32-message outbound queue, and 32 KiB outbound chunks.
The aggregate inbound budget can therefore reach approximately 2 GiB before
TLS, socket, and other overhead; lower `MaxConnections` and `MaxInboundBytes`
for smaller applications. A slow event consumer loses events, counted by
`Status().DroppedEvents`. A channel exceeding its inbound budget is reset.
Sustained outbound pressure can delay other channels because the upstream
protocol has no per-channel flow-control mechanism.

## Review findings addressed

The integrated review and regression tests identified and addressed these cases:

- Resetting or overflowing a channel must cancel its upstream socket; aborting
  only the virtual TLS connection can leave an upstream write blocked.
- Confirmed remote deletion must finish local cleanup after caller cancellation.
- Renewal and deletion must share a profile lock so a late renewal cannot
  recreate deleted credentials.
- Retrying failed certificate issuance must reuse the stored private key.
- Certificate validation must require the wildcard SAN itself, rather than
  accepting one sample subdomain certificate.
- API deadlines must remain active until the response body is consumed.
- Route changes during session publication must retain the final route names.

See [TESTING.md](TESTING.md) for reproducible commands and the live exercise,
[VERIFICATION.md](VERIFICATION.md) for the recorded local results, and
[SECURITY.md](SECURITY.md) for the encryption and trust boundaries.
