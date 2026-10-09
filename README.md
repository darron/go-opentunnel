# go-opentunnel

Embed an [OpenTunnel](https://opentunnel.xyz) client in your Go application. Run
an HTTP server on loopback, then use the package to expose it over public HTTPS.
Visitor TLS terminates in your process.

```sh
go get github.com/darron/go-opentunnel
```

Requires Go 1.25 or newer. The sole dependency outside the standard library is
`github.com/coder/websocket`. Licensed under [MIT](LICENSE).

## Embed the client

This function connects an existing server at `127.0.0.1:8080`. Pass your
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
        Profile: "demo",
        Routes:  opentunnel.Routes{"@": "127.0.0.1:8080"},
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
Run it with `go run ./examples/webapp`; it creates and owns its tunnel connection.

Use these contracts when embedding:

- **Lifetime:** `Connect` returns after its first successful attachment. Its
  context controls provisioning, reconnects, and shutdown. `Client.Close` joins
  all work it owns; `Connection.Close` joins one connection's workers.
- **Storage:** `NewFileStorage(root)` uses your directory; `NewXDGStorage()` uses
  the upstream-compatible data directory. Memory storage lasts only for the
  process. Coordinate same-profile provisioning across clients or processes.
- **Events:** delivery is bounded and lossy. Use `Status()` for current state
  and `Status().DroppedEvents` to detect missed events.
- **Traffic:** buffers are bounded. The relay protocol has no per-channel flow
  control, so sustained outbound backpressure can delay other channels.
- **Credentials:** identity JSON omits tokens and private keys. Keep the stored
  files private. Read the [security model](docs/SECURITY.md) before exposing an app.

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

Local tests cover the API, storage, protocol, TLS forwarding, concurrency, and CLI.
The public service was also exercised on **2026-10-09**: provisioning, HTTPS/WSS,
streaming, large and concurrent transfers, route changes, reconnection, embedding,
shutdown, and deletion passed.

Read the [local results](docs/VERIFICATION.md) and
[live results and limits](docs/LIVE_TESTING.md) for the evidence.
