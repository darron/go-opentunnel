# go-opentunnel

`go-opentunnel` is an embeddable Go client for [OpenTunnel](https://opentunnel.xyz). It provisions tunnel identities, stores credentials, connects the multiplexed relay bridge, terminates visitor TLS in your process, and forwards the resulting local connections to named `host:port` routes.

The only runtime dependency outside the Go standard library is `github.com/coder/websocket`. Go 1.25 or newer is required.

## Library

```go
store, err := opentunnel.NewXDGStorage()
if err != nil { log.Fatal(err) }
client, err := opentunnel.NewClient(opentunnel.ClientOptions{Storage: store})
if err != nil { log.Fatal(err) }
defer client.Close()

ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
defer cancel()
connection, err := client.Connect(ctx, opentunnel.ConnectOptions{
    Profile: "demo",
    Routes:  opentunnel.Routes{"@": "127.0.0.1:8080"},
})
if err != nil { log.Fatal(err) }
defer connection.Close()
<-connection.Done()
```

`Connect` uses its context for the whole connection lifetime, including reconnects. Cancel it to stop the bridge. `Client.Close` stops connections created by that client; `Connection.Close` stops one bridge. `Create`, `Resume`, and `Ensure` return snapshots whose credential fields are deliberately excluded from JSON. `Client.API().Get` supports diagnostic remote inspection when you already hold a stored identity.

The SDK maps OpenTunnel operations directly to Go methods: `Profiles`, `List`, `Get`, `Pending`, `Create`, `Resume`, `Ensure`, `Remove`, and `Connect` are methods on `Client`; `Connection` provides `Identity`, `Events`, `Status`, `SetRoutes`, `Done`, `Err`, and `Close`. [The design document](docs/DESIGN.md#public-package-and-api) records the full upstream-to-Go mapping.

Storage is explicit: `NewFileStorage(root)` uses the directory you supply, while `NewXDGStorage()` uses the upstream-compatible XDG data location. Memory storage is process-only. File storage is safe within the implementation’s operations, but provisioning the same profile concurrently from separate processes is not a transaction.

Bridge traffic and event delivery are bounded. The event channel is lossy under a slow consumer; inspect `Status().DroppedEvents` and use `Status()` as the authoritative state snapshot. The relay protocol has no per-channel flow control, so sustained backpressure on a shared bridge can delay unrelated channels. Keep route targets responsive and consume events without blocking application shutdown.

## CLI

Build the diagnostic CLI with `make build`; it is deliberately only a consumer of the public package.

```sh
./bin/otgo create --profile demo
./bin/otgo connect --profile demo --route @=127.0.0.1:8080 --interactive
# in interactive mode: status; routes @=127.0.0.1:8080 api=127.0.0.1:8081; quit
./bin/otgo inspect --profile demo --json
./bin/otgo remove --profile demo
```

Flags appear after the command. All commands accept `--api`, `--data-dir`, `--profile`, `--json`, and `--request-timeout`; zero request timeout selects the library default and positive values override it. Provisioning commands also accept `--timeout` (default two minutes). `connect --timeout 0` is the default and leaves the connection running until Ctrl-C; a nonzero value limits the whole connection lifetime. Negative durations are rejected. Repeat `--route name=host:port` for each route. The CLI never prints tokens or private keys.

## Local example and live exercise

For a CLI exercise, run `go run ./examples/webapp --local-only --addr 127.0.0.1:8080` to start a loopback HTTP and WebSocket echo target. In another terminal, connect it with `./bin/otgo connect --profile live-check --route @=127.0.0.1:8080 --interactive`. Visit the printed HTTPS URL, use `/stream` for a streaming response, and connect a WebSocket client to `/ws`. Add a named route with the `routes` interactive command, then run `./bin/otgo remove --profile live-check`.

The example also demonstrates embedding: omit `--local-only` and it starts the loopback server and owns a `Client.Connect` session itself, using `--profile`, `--api`, and `--data-dir` when supplied. Stopping its local HTTP server only causes `upstream_connect_failed` for new visitor connections; it does not test relay reconnection. A bridge reconnect requires a relay transport loss or server drain.

This sequence is a live service test, separate from the local test suite. See [docs/TESTING.md](docs/TESTING.md) for what each check establishes and [docs/SECURITY.md](docs/SECURITY.md) for the TLS and trust model.
