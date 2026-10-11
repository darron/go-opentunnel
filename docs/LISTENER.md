# Embed HTTP directly over tunnel TLS

[`Client.Listen`](../listener.go) implements [issue #1](https://github.com/darron/go-opentunnel/issues/1).
Use it when your application needs the real TLS handshake in `http.Request.TLS`
and the relay's visitor peer in `RemoteAddr`, without a loopback HTTP adapter.
`Client.Connect` remains available for forwarding to existing TCP targets.

```go
listener, err := client.Listen(startupCtx, opentunnel.ListenOptions{
    Profile: "phone",
    Routes: []string{"@", "api"},
    Lifetime: appCtx,
})
if err != nil {
    return err
}
defer listener.Close()
server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
return server.Serve(listener)
```

Use `Serve`, not `ServeTLS`: the package has already completed TLS and owns
certificate selection. `Accept` returns an actual `*tls.Conn`, not a wrapper.
The package verifies the handshake SNI against the relay route and rejects
expired or not-yet-valid certificates. It requires TLS 1.2 or newer and negotiates
HTTP/1.1. It does not authenticate visitors with client certificates.

## Lifetime and errors

- `startupCtx` bounds provisioning and initial attachment only. Cancellation
  after `Listen` returns leaves the listener running.
- `Lifetime` owns the running tunnel. When omitted, the client owns it.
- `Accept` waits across transient reconnects. Existing sockets are aborted when
  their bridge session ends; reconnect makes new sockets available.
- Invalid visitor handshakes are rejected inside the package; they do not end
  `Accept` or the listener.
- `Close`, client shutdown, and removal unblock `Accept` with `net.ErrClosed`.
  Lifetime cancellation returns its context error. A fatal attachment returns
  `*AttachError`; use `errors.As` to inspect it.
- Terminal `Accept` and `Close` wait for package workers, including handshake,
  refresh, bridge, idle, and write-deadline workers. `Done` and `Err` expose the
  same lifecycle as `Connection`. Application handlers belong to the application.
- `Close` aborts accepted sockets, including hijacked WebSocket sockets. This
  also applies when `http.Server.Shutdown` closes the listener: it does not
  provide a graceful drain of active requests. Coordinate any application-level
  draining before closing it.
- Closing retains local credentials and the remote tunnel. `Client.Remove`
  deletes them. Pending issuance recovery follows the same rules as `Connect`.

## Routes and limits

`Routes` is a list of SNI names: `@` for the root hostname, or lowercase DNS
labels for subdomains. Duplicate names and an empty initial list are invalid.
`SetRoutes` changes names and reattaches asynchronously, closing existing sockets.
An empty update pauses attachment. One client may own disjoint listener and
forwarding routes for the same profile; overlap returns `ErrRouteInUse`.
Separate clients/processes must coordinate their claims themselves.

`Status().Routes` maps names to empty strings because there are no backend
addresses. `Addr()` reports the root hostname with network `opentunnel`.
`Identity`, `Events`, `Status`, `Done`, and `Err` are available on the listener.
Events remain bounded and lossy.

`TransportOptions.MaxConnections` includes handshaking, queued, and accepted
sockets. The accept queue has the same fixed capacity; stale entries are discarded
on reconnect. Each channel retains the `MaxInboundBytes` bound, and the session
shares the `MaxInboundTotalBytes` budget (64 MiB by default). A slow
handshake or application cannot block delivery to healthy channels. A full inbound
buffer resets that channel; there is no protocol-level per-channel flow control.
Optional `IdleTimeout` counts TLS records consumed or written by the application
for listeners; forwarding connections count application bytes. Set HTTP server
header/body deadlines as appropriate. Every accepted socket must be closed by its
owner to release its admission slot. Ordinary application close uses protocol
`end` so the relay can drain already-written bytes before half-closing its visitor
socket. Local admission is released immediately; completion of the relay's other
half remains relay-owned. Failures/forced shutdown abort channels or the session.

## Peer trust

`Request.TLS` describes the actual locally terminated handshake. `RemoteAddr`
preserves ordinary `open.peer` address/port strings supplied by the relay.
Oversized values, control characters or reflected tunnel credentials become
`unknown`; session/event metadata is bounded too. It is not independently verified against
an end-to-end visitor identity. A compromised or malicious relay can forge it;
IP-based quotas and access rules inherit that trust. The package does not consult
`Forwarded`, `X-Forwarded-For`, or `X-Forwarded-Proto`. Applications must not let
those visitor-controlled headers override this metadata without their own trusted
proxy policy. See [SECURITY.md](SECURITY.md) for the certificate/DNS operator boundary.

## Try it

```sh
make build
./bin/otgo listen --profile listener-demo --route @ --route api
```

The diagnostic handler returns `tls`, `sni`, `peer`, and an HTTPS `origin` built
from SNI. Ctrl-C retains the profile. Delete it after testing:

```sh
./bin/otgo remove --profile listener-demo
```

`go run ./examples/webapp` serves handlers directly through `Listen`, including
`/request` metadata, `/stream`, and `/ws`. `--forward` exercises `Connect` through
loopback; `--local-only` runs just the local HTTP target.
