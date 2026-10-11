# Forward to a PROXY-aware backend

These additions are on `main`; they are not included in v0.5.0 binaries.

Use PROXY protocol when your TCP backend needs the visitor address. The backend
must understand the selected version. A normal HTTP server expects an HTTP
request immediately and will reject a PROXY preamble.

This feature matches [OpenTunnel v0.5.0](https://github.com/anomalyco/opentunnel/blob/v0.5.0/docs/protocol.md#proxy-protocol).
It adds a local TCP header; the hosted API and bridge messages stay the same.
It does not add authentication. Use [the auth proxy](AUTH_PROXY.md) to require
login before exposing an ordinary HTTP application.

## CLI

Enable it separately for each route:

```sh
otgo connect --profile tcp-demo \
  --route @=127.0.0.1:4000 --proxy-protocol @=v1 \
  --route api=127.0.0.1:4001 --proxy-protocol api=v2
```

Routes without `--proxy-protocol` forward application bytes unchanged. Unknown
versions, duplicate options and options for an absent route are rejected.
The flags apply to `connect`; `proxy` and `listen` do not emit PROXY headers.

Add `--interactive` to change a running connection:

```text
proxy-protocol @=v2 api=v1
status
proxy-protocol
```

The first command replaces all forwarding options for the current routes. The
last clears them. Changes affect new visitor connections. Existing streams keep
running and never receive another preamble. A `routes` command replaces targets
and clears forwarding options. These diagnostic connection settings are supplied
on each start, rather than saved in an auth profile.

## Go

Keep the existing `Routes` map and supply options alongside it:

```go
connection, err := client.Connect(ctx, opentunnel.ConnectOptions{
    Profile: "tcp-demo",
    Routes: opentunnel.Routes{
        "@":   "127.0.0.1:4000",
        "api": "127.0.0.1:4001",
    },
    RouteOptions: map[string]opentunnel.RouteOptions{
        "api": {ProxyProtocol: opentunnel.ProxyProtocolV2},
    },
    Lifetime: ctx,
})
```

`Connection.SetRoutesWithOptions` replaces both maps atomically for new channels.
`Connection.SetRoutes` clears options. Status returns copies of both maps.
As with Routes, do not modify an input map concurrently with the call copying it.

## What the backend receives

The client verifies the visitor TLS route, connects to the backend and writes
one header before forwarding any application bytes. Header delivery uses
`TransportOptions.WriteTimeout` (10 seconds by default) and stops on cancellation.

| Field | Value |
| --- | --- |
| Source | Relay-provided visitor address and port; a bare IP uses port 0 |
| Destination | `0.0.0.0:443` or `[::]:443`, according to the source family |
| v1 | Text `PROXY TCP4` / `TCP6`; invalid peers use `PROXY UNKNOWN` |
| v2 | Binary address block and `PP2_TYPE_AUTHORITY` TLV with relay SNI |
| Invalid v2 peer | `LOCAL` / `UNSPEC`, with authority when available |

IPv4-mapped IPv6 becomes IPv4. Invalid peers, hostnames and zone identifiers are
not resolved. The v2 authority is omitted when empty or longer than 255 bytes.
The destination is unspecified because the client does not know which public
relay address the visitor reached.

Peer metadata comes from the relay. It is useful for logging, but is not a
verified user identity. Accept PROXY headers only on a backend listener restricted
to your trusted local forwarder; otherwise a direct client can forge them.
