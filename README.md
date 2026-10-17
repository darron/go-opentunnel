# go-opentunnel

<img src="internal/authproxy/ui/mark.svg" alt="otgo: an animal peeking out of a tunnel" width="80" height="80">

[![Go Reference](https://pkg.go.dev/badge/github.com/darron/go-opentunnel.svg)](https://pkg.go.dev/github.com/darron/go-opentunnel)

Expose a local application over public HTTPS with [OpenTunnel](https://opentunnel.xyz).
Use `otgo` to require password or GitHub login, or embed the client in your Go app.
Visitor TLS terminates in your process. Read the [security model](docs/SECURITY.md)
for the relay and domain operator's trust boundaries.

## Install

For the CLI:

```sh
brew install darron/tap/otgo
otgo version
```

Or download a macOS or Linux binary from
[GitHub releases](https://github.com/darron/go-opentunnel/releases).
[Verify the SHA-256 checksum](docs/RELEASES.md#verify-and-install) before installing.

`otgo version` (or `otgo --version`) shows the version, full Git SHA and whether
the source was clean or dirty when built. Missing build metadata is `unknown`.

For the Go library:

```sh
go get github.com/darron/go-opentunnel
```

Source compatibility starts at Go 1.26. Build production binaries with the latest
patched release of a [supported Go version](https://go.dev/doc/devel/release#policy).
The core client uses `github.com/coder/websocket`. The optional metrics adapter
and otgo use the official Prometheus Go client. The optional identity verifier
uses golang-jwt; otgo also uses a QR encoder and terminal detection. These do not
add dependencies to the core client import. Licensed under [MIT](LICENSE).
See the [changelog](CHANGELOG.md) for release highlights and the
[Homebrew guide](docs/HOMEBREW.md) for binary installation and updates.

For private API/relay certificates, use `ClientOptions.CACertFile` or
`--ca-cert` after an otgo command. See [custom CA trust](docs/CUSTOM_CA.md).

## Protect a local application with otgo

1. Save a backend under a named profile:

   ```sh
   otgo auth init --profile inbox --upstream http://127.0.0.1:57732
   ```

   Setup creates or reuses a tunnel and shows a generated password once. Save it
   in your password manager. Use `--password-stdin` to supply your own password.

2. Start the protected proxy:

   ```sh
   otgo proxy --profile inbox
   ```

3. Open the printed HTTPS URL or scan the terminal QR code on your phone, then sign in.

The QR code appears in interactive terminals. Use `--qr=never` to hide it or
`--qr=always` to force it; `--json` always keeps output machine-readable.

Every backend path requires authentication, including assets, HTTP MCP, SSE and
WebSockets. **Use `proxy` for protection:** the diagnostic `connect` and `listen`
commands expose services directly without a login gate.

A profile saves the hostname, backend and auth settings in XDG directories.
Restarting reuses those settings and requires a fresh browser login. Use different
profiles for different backends; they can run concurrently on one machine.
List saved profiles, clickable HTTPS URLs, backends and launch commands:

```sh
otgo profiles
```

This is a local inventory, so it works while proxies are running or stopped.
`otgo profiles --json` produces structured output; `--names` prints only names.
Profiles without a matching auth setup have no proxy launch command.

### GitHub login

Stop the profile's proxy, then switch its login mode:

```sh
otgo auth github --profile inbox --allow-user darron
otgo proxy --profile inbox
```

Setup tries to open your default browser; the printed link is a fallback. Use
`--no-browser` to open it yourself. The completion page shows
your profile and a copyable proxy command. It requests no repository
permissions. Repeat `--allow-user` to approve more accounts. GitHub login replaces
password login. Existing OAuth/GitHub Apps are also supported.

The backend receives the verified username and numeric ID in `X-GitHub-User` and
`X-GitHub-ID`, plus a signed `X-Otgo-Identity` assertion. Export the profile's public
key with `otgo auth public-key --profile inbox` and use the optional
[`identity` package](https://pkg.go.dev/github.com/darron/go-opentunnel/identity)
to verify requests. See [signed backend identity](docs/AUTH_PROXY.md#signed-backend-identity)
for the trust boundary and an example. Password and machine-token requests do not
carry GitHub identity.

### Machine clients and MCP

Create a short-lived token while the proxy runs:

```sh
otgo auth token create --profile inbox --ttl 1h
```

Send it as `Authorization: Bearer TOKEN`, or use `X-Otgo-Token` when the backend
needs its own Authorization header. Tokens grant access to the whole backend.
Clients that cannot supply a session cookie or token are denied. otgo does not
implement an MCP OAuth authorization server or automatic client registration.

Upgrading to v0.7.0 requires resetting and reissuing existing machine tokens;
see the [migration instructions](docs/AUTH_PROXY.md#machine-clients-and-mcp).

The [auth guide](docs/AUTH_PROXY.md) covers token revocation, password replacement,
GitHub setup, saved file paths and HTTP compatibility.

`connect` supports per-route PROXY headers for a TCP
backend that understands them. See the
[PROXY v1/v2 options](docs/FORWARDING.md). [Certificate diagnostics](docs/CERTIFICATES.md)
explain typed failures and safe CLI summaries.

## Embed the client

Use `Client.Listen` to serve an HTTP handler over the visitor's TLS connection:

```go
package example

import (
    "context"
    "net/http"
    "time"

    opentunnel "github.com/darron/go-opentunnel"
)

func serveTunnel(ctx context.Context, handler http.Handler) error {
    store, err := opentunnel.NewXDGStorage()
    if err != nil {
        return err
    }
    client, err := opentunnel.NewClient(opentunnel.ClientOptions{Storage: store})
    if err != nil {
        return err
    }
    defer client.Close()

    listener, err := client.Listen(ctx, opentunnel.ListenOptions{
        Profile:  "demo",
        Routes:   []string{"@"},
        Lifetime: ctx,
    })
    if err != nil {
        return err
    }
    defer listener.Close()

    server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
    return server.Serve(listener)
}
```

`Request.TLS` contains the real handshake. `RemoteAddr` comes from relay metadata;
HTTP forwarding headers do not override it. The library exposes your handler
directly; add application authentication when it is needed.

For an existing TCP server, use `Client.Connect` with a route such as
`opentunnel.Routes{"@": "127.0.0.1:8080"}`. Both APIs use the caller's context for
startup. Set `Lifetime` to stop the running tunnel on application shutdown, or
close it explicitly. `Client.Close` stops its owned connections and joins workers.

The [webapp example](examples/webapp/main.go) demonstrates HTTP, streaming,
WebSockets and shutdown. Run `go run ./examples/webapp`; use `--forward` for TCP
forwarding or `--local-only` for a loopback test server.

Read the [listener guide](docs/LISTENER.md) for shutdown and peer trust, and the
[Go API documentation](https://pkg.go.dev/github.com/darron/go-opentunnel) for
types, methods and examples. The [package reference](docs/DESIGN.md#public-package-and-api)
explains routes, storage, provisioning recovery and resource limits.
`Identity` and `PendingIdentity` redact
credentials in standard formatting and JSON; their exported fields still contain
live secrets.

## Monitor a running proxy

Available in v0.9.0 and later.

Start a separate local metrics listener:

```sh
otgo proxy --profile inbox --metrics-listen 127.0.0.1:9091
```

Scrape `http://127.0.0.1:9091/metrics`. Choose a different port for each instance.
Metrics are disabled by default and omit tunnel identities and credentials.
Save `metrics_listen` in the proxy's auth config to reuse its port on startup;
an explicit flag overrides it, including an empty value to disable metrics.
Embedded applications can read `Client.Stats()` or register the optional
[Prometheus adapter](docs/OBSERVABILITY.md) with their own registry.

## Build and validate

`make build` builds only `bin/otgo`. `make build-example` builds the example.

```sh
make check
make race
make fuzz
```

`make check` runs tests, vet, formatting, full golangci-lint and the CLI build.
See [testing instructions](docs/TESTING.md) for local and public-service checks.

Browse the [documentation index](docs/README.md) for guides, security reviews and
dated validation records. The [v0.7.0 audit](docs/SECURITY_AUDIT.md) records
security fixes, test-quality checks and remaining limits.
