# Outbound proxies

otgo and the Go package can reach the OpenTunnel API and bridge through an
outbound proxy. Both use the same settings, including bridge reconnects.

```sh
ALL_PROXY=http://proxy.example:3128 otgo proxy --profile inbox
```

## Environment settings

| Setting | Applies to |
| --- | --- |
| `HTTPS_PROXY` | HTTPS API calls and the WSS bridge |
| `HTTP_PROXY` | HTTP API calls and the WS bridge; HTTP API bases are restricted to loopback |
| `ALL_PROXY` | Fallback when the request's scheme-specific setting is empty |
| `NO_PROXY` | Destinations that should connect directly |

Lowercase spellings also work. A nonempty uppercase value wins over its lowercase
spelling. A scheme-specific setting wins over `ALL_PROXY`; an invalid selected
setting fails with `ErrInvalid` rather than falling back or silently going direct.
Unused settings do not fail a bypassed request. As in Go's standard HTTP client,
`HTTP_PROXY` is refused in CGI environments (`REQUEST_METHOD` is set).

`NO_PROXY` supports comma-separated domains, IP addresses, CIDR ranges, optional
ports and `*`. `example.com` matches that domain and its subdomains;
`.example.com` matches only subdomains. Localhost and literal loopback IPs always
connect directly. Matching uses Go's maintained `x/net/httpproxy` package,
including internationalized domain names.

Proxy URLs support `http`, `https`, `socks5` and `socks5h`; bare `host:port`
uses HTTP. Go's standard transport handles CONNECT, TLS and proxy authentication.
Both SOCKS spellings resolve the destination through the proxy.
Credentials may be supplied as URL user information, with reserved characters
percent-encoded. HTTP proxy credentials travel to the proxy in cleartext; use an
HTTPS proxy when that connection needs encryption. API and bridge TLS still
verify the destination certificate and hostname. [Custom CA bundles](CUSTOM_CA.md)
also apply to an HTTPS proxy's certificate.

Settings are captured when the default transport is created. Restart otgo, or
construct a new Go client, after changing them. They are not saved in profiles.
These settings govern the OpenTunnel API and bridge; they do not configure
backend connections, GitHub authentication or your browser.

## Explicit Go transport

A supplied `ClientOptions.HTTPClient.Transport` remains a trusted override.
Its `Proxy` function takes precedence over these environment rules. A nil
`Proxy` function on that transport connects directly. For example:

```go
proxyURL, err := url.Parse("http://proxy.example:3128")
if err != nil {
    return err
}
transport := http.DefaultTransport.(*http.Transport).Clone()
transport.Proxy = http.ProxyURL(proxyURL)
defer transport.CloseIdleConnections()
client, err := opentunnel.NewClient(opentunnel.ClientOptions{
    HTTPClient: &http.Client{Transport: transport},
})
if err != nil {
    return err
}
defer client.Close()
```

This explicit `http.ProxyURL` setting does not apply `NO_PROXY`. Supply your own
selector if you need a custom bypass policy. The package does not mutate or
close caller-owned transports; a CA-file option owns its documented clone.
`NewAPI` follows the same rules. `NewHTTPClientWithCACert` captures the environment
when it constructs its default transport.

## Diagnostics and trust

Built-in proxy errors identify invalid environment settings, CONNECT status
codes, authentication requirements (`407`) and policy refusal (`403`). They omit
proxy URLs, credentials, response bodies and arbitrary response text. Underlying
network, context and TLS errors remain available through `errors.Is`/`errors.As`.
Explicit custom transports and hooks remain trusted code responsible for their
own diagnostic content.

Invalid configuration and CONNECT `403`/`407` failures stop startup or a running
bridge rather than reconnecting indefinitely. Network failures and temporary
proxy statuses retain bounded API retries and bridge backoff. A failure before
the origin request is sent can be retried; an ambiguous create/delete failure
after sending the request is not replayed.

A proxy sees destination names, connection timing and volume. Ordinary CONNECT
and SOCKS forwarding carry encrypted API/bridge TLS. A proxy whose CA you trust
can intercept that TLS and access API credentials and bridge traffic. Visitor TLS
remains a separate encrypted layer inside the bridge. This is
separate from [visitor authentication and the domain operator's trust boundary](SECURITY.md).
