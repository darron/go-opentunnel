# Testing and verification

Run the local suite and build checks with:

```sh
make check
make race
make fuzz
./bin/otgo help
```

The local tests use fake API/relay components. They establish request encoding, credential redaction, cancellation, storage behavior, route validation, bridge framing, TLS forwarding, and CLI command dispatch without creating a public tunnel. They do not demonstrate interoperability with the deployed API, certificate authority, or relay.

`make lint` checks formatting and runs `golangci-lint` across `./...`, including tests, the CLI, and the embedding example. The version-2 configuration enables the standard linters plus additional security, context, resource, and error checks. It has no excluded package or file patterns. Two security analyzer rules are disabled with reasons in `.golangci.yml`: runtime-selected TCP destinations are the SDK's purpose (`G704`), and profile file paths are validated by the storage implementation (`G304`). Local source suppressions explain missing-value storage results, owner-executable directory permissions, and non-cryptographic retry jitter. These are reviewed exceptions, not claims that static analysis proves security.

The lifecycle regressions can be repeated independently:

```sh
go test -race -run 'TestLifecycle|TestTunnelStalledChannel|TestTunnelRoutesReconnect' -count=10 .
```

See [VERIFICATION.md](VERIFICATION.md) for local results and
[LIVE_TESTING.md](LIVE_TESTING.md) for the completed public-service exercise.

For a deliberate live exercise, start the loopback target in one terminal:

```sh
go run ./examples/webapp --local-only --addr 127.0.0.1:8080
```

Then use a dedicated profile in another terminal:

```sh
./bin/otgo create --profile live-check
./bin/otgo connect --profile live-check --route @=127.0.0.1:8080 --interactive
```

Visit the printed HTTPS address. Check the normal response, `/stream`, and a WebSocket connection to `/ws`. In interactive mode run `status`, then `routes @=127.0.0.1:8080 api=127.0.0.1:8080`, and verify the named public hostname. Stopping the local server tests a failed local upstream for new visitors, not bridge reconnection. Test a reconnect only by inducing a relay transport loss or observing a relay drain. Finish with `./bin/otgo remove --profile live-check`.

`connect` retains its context for the entire bridge. By default `--timeout 0` means Ctrl-C or the calling context controls shutdown. A positive `connect --timeout` bounds the full connection lifetime; it is not merely a startup deadline. Provisioning defaults to two minutes and accepts its own `--timeout` override. A zero `--request-timeout` selects the API client's finite default; positive values override it.

Interactive `quit` stops scanning without requiring stdin EOF. The CLI treats
inherited `os.Stdin` as process-owned: cancellation does not wait for a native
stdin read that the OS may not interrupt. Tunnel/client cleanup still completes
before process exit. Other supplied closable readers are closed and joined;
they must support interruption of a pending read. Regression tests use both an
open pipe and a child process with its native stdin writer held open.
