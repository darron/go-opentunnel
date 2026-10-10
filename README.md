# go-opentunnel

Embed an [OpenTunnel](https://opentunnel.xyz) client in your Go application. Serve
your HTTP handler directly over public HTTPS, or forward to an existing TCP server.
Visitor TLS terminates in your process.

```sh
go get github.com/darron/go-opentunnel
```

Requires Go 1.25 or newer. The sole dependency outside the standard library is
`github.com/coder/websocket`. Licensed under [MIT](LICENSE).

See [CHANGELOG.md](CHANGELOG.md) for release highlights.

## Embed the client

Use `Client.Listen` to give `http.Server` the actual visitor TLS connection:

```go
listener, err := client.Listen(ctx, opentunnel.ListenOptions{
    Profile: "demo",
    Routes: []string{"@"},
    Lifetime: ctx,
})
if err != nil {
    return err
}
defer listener.Close()
server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
return server.Serve(listener)
```

`Request.TLS` contains the real handshake. `RemoteAddr` comes from relay metadata;
HTTP forwarding headers do not override it. Closing aborts accepted sockets and
joins package workers. Read the [listener contracts](docs/LISTENER.md) for peer
trust, admission limits, terminal errors, and HTTP shutdown behavior.

Use `Client.Connect` for an existing TCP server. This function connects
`127.0.0.1:8080`. Pass your
application's shutdown context. The `demo` profile persists across restarts.

```go
package example

import (
    "context"

    opentunnel "github.com/darron/go-opentunnel"
)

func serveTunnel(ctx context.Context) error {
    store, err := opentunnel.NewXDGStorage()
    if err != nil {
        return err
    }
    client, err := opentunnel.NewClient(opentunnel.ClientOptions{Storage: store})
    if err != nil {
        return err
    }
    defer client.Close()

    connection, err := client.Connect(ctx, opentunnel.ConnectOptions{
        Profile:  "demo",
        Routes:   opentunnel.Routes{"@": "127.0.0.1:8080"},
        Lifetime: ctx,
    })
    if err != nil {
        return err
    }
    defer connection.Close()
    <-connection.Done()
    return connection.Err()
}
```

The [webapp example](examples/webapp/main.go) includes an HTTP server, event
handling, signal cancellation, streaming responses, and a WebSocket echo endpoint.
Run it with `go run ./examples/webapp`; it serves directly through `Listen`.
Use `--forward` for the loopback forwarding path or `--local-only` for local HTTP.

Use these contracts when embedding:

- **Lifetime:** the `Connect` and `Listen` contexts bound startup only. Set
  `ConnectOptions.Lifetime` or `ListenOptions.Lifetime` when application shutdown should stop the running
  tunnel. Otherwise call `Connection.Close`; `Client.Close` stops every
  connection owned by that client.
- **Routes:** one client may run disjoint route names for the same profile.
  Overlapping names return `ErrRouteInUse`, including conflicting `SetRoutes`
  updates.
- **Storage:** `NewFileStorage(root)` uses your directory; `NewXDGStorage()` uses
  the upstream-compatible data directory. Memory storage lasts only for the
  process. Coordinate same-profile provisioning across clients or processes.
- **Provisioning:** cancellation after a known creation preserves pending
  credentials. If persistence and compensating deletion both fail, handle
  `*opentunnel.ProvisioningError` and securely recover or delete its `Pending`
  identity. Concurrent removal interrupts issuance with `ErrProfileChanged`.
- **Events:** delivery is bounded and lossy. Use `Status()` for current state
  and `Status().DroppedEvents` to detect missed events.
- **Traffic:** buffers are bounded. The relay protocol has no per-channel flow
  control, so sustained outbound backpressure can delay other channels. Optional
  `TransportOptions.IdleTimeout` is disabled by default.
- **Credentials:** JSON, `fmt`, and `slog` representations of `Identity` and
  `PendingIdentity` redact tokens and private keys. Their exported fields still
  contain live secrets. Other API response types may also carry credentials;
  keep them private and read the [security model](docs/SECURITY.md).
- **API transport:** use HTTPS except for exact `localhost` or literal loopback
  addresses. Redirects must keep the same scheme, hostname, and effective port.

See the [API mapping](docs/DESIGN.md#public-package-and-api) for lifecycle,
connection, storage, and remote-inspection operations.

## Exercise the package with otgo

`otgo` is a diagnostic CLI built from the public package.

1. Build it and start a loopback test server in one terminal:

   ```sh
   make build
   ./bin/webapp --local-only --addr 127.0.0.1:8080
   ```

2. In another terminal, create a dedicated profile and connect it:

   ```sh
   ./bin/otgo create --profile demo
   ./bin/otgo connect --profile demo --route @=127.0.0.1:8080 --interactive
   ```

3. Visit the printed HTTPS URL. Enter `status` or `quit` in the CLI. After
   disconnecting, delete the test tunnel:

   ```sh
   ./bin/otgo inspect --profile demo --json
   ./bin/otgo remove --profile demo
   ```

Put flags **after the command**. Repeat `--route name=host:port` for each route.
Common flags are `--api`, `--data-dir`, `--profile`, `--json`, and
`--request-timeout`. The CLI omits tokens and private keys from output.

Provisioning defaults to a two-minute timeout. `connect --timeout 0` runs until
Ctrl-C; a positive timeout limits its entire lifetime. See
[testing instructions](docs/TESTING.md) for all timeout rules, interactive route
changes, and a live test using isolated storage.

## Validation

```sh
make check
make race
make fuzz
```

Local tests cover the API, storage, protocol, TLS listening/forwarding, concurrency,
and CLI. The **2026-10-10** listener retest also verified real HTTP TLS/peer
metadata, HTTPS/WSS normal close, and shutdown against the public service.
The **2026-10-09** public-service records cover provisioning, HTTPS/WSS,
streaming, large and concurrent transfers, route changes, embedding, shutdown,
and deletion. The final CLI and embedded-app retest ran after the hardening
changes; the earlier run also exercised a forced bridge reconnect.

Read the [local results](docs/VERIFICATION.md) and
[live results and limits](docs/LIVE_TESTING.md) for the evidence. See the
[hardening guide](docs/HARDENING.md), [v0.2.0 Amp review](docs/AMP_REVIEW.md), and
[v0.3.0 listener review](docs/AMP_REVIEW_V0.3.0.md) for current behavior, review
dispositions, and remaining limits.
