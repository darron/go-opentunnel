# Custom CA trust

Use a private CA when a self-hosted control API or relay has a certificate that
Go's normal trust store does not recognize. The hosted service normally needs
no extra configuration.

## otgo

Pass a PEM file after the command:

```sh
otgo connect --api https://tunnel.example.com --ca-cert /etc/company/ca.pem \
  --route @=127.0.0.1:8080
```

Or set `OPENTUNNEL_CA_CERT=/etc/company/ca.pem`. The precedence is:

1. `--ca-cert`, including `--ca-cert=""` to use normal trust.
2. A nonempty `OPENTUNNEL_CA_CERT`.
3. The saved auth profile's `ca_cert`, for `proxy` and `auth github`.
4. Normal Go trust settings.

`auth init` saves the selected path as an absolute `ca_cert` field in
`auth.json`. Successful `auth github` setup retains it, or saves an override
alongside the GitHub credentials. Failed/cancelled setup preserves the previous
configuration. A `proxy` override applies only to that run; `proxy` reads the
saved path on startup. You can also add `"ca_cert": "/etc/company/ca.pem"` to an existing
profile. The file's contents are not copied into the profile. Keep that path
available and restart the proxy after changing its bundle.

`otgo profiles` and provisioning resume hints include the effective CA option
in their copyable commands. Profile inventory reads local state; it does not
check that the CA file exists or that an endpoint is online. Ordinary commands
such as `connect` do not read an auth profile; pass the flag or environment
variable for them.

## Go package

```go
client, err := opentunnel.NewClient(opentunnel.ClientOptions{
    API:        "https://tunnel.example.com",
    CACertFile: "/etc/company/ca.pem",
})
if err != nil {
    return err
}
defer client.Close()
```

For direct API calls, pass the client returned by
`opentunnel.NewHTTPClientWithCACert(path)` to `opentunnel.NewAPI`. The helper has
no standalone timeout; `NewAPI` applies its usual operation deadline. Call
`CloseIdleConnections` on a standalone HTTP client when it is no longer needed.
The library does not read `OPENTUNNEL_CA_CERT`, so embedding it does not silently
adopt CLI-specific environment settings.

With `ClientOptions.HTTPClient`, the CA option clones the client, its
`*http.Transport`, TLS configuration and explicit root pool. Other transport
settings, cookie jar and redirect hook are retained. An opaque custom
RoundTripper, custom `DialTLS`/`DialTLSContext`, or `InsecureSkipVerify` is
rejected with `ErrInvalid` when a CA file is supplied: a custom TLS dialer
would bypass the transport's CA settings. Without `CACertFile`, existing
custom-client behavior is unchanged. Custom HTTP transports and hooks remain trusted application code.

## Boundaries and errors

The bundle adds certificates to Go's system roots, or to an explicit root pool
already configured on the supplied HTTP client. It must contain only valid
`CERTIFICATE` PEM blocks and whitespace, with a maximum size of 1 MiB. Missing,
unreadable, empty or malformed files fail construction/startup with `ErrInvalid`
before any service request. Certificate errors remain non-retryable; there is
no fallback to insecure TLS.

This trust applies to control API HTTPS and relay WSS. It does not change:

- Certificate-chain or hostname verification, API redirect restrictions, or
  the browser's trust store.
- Visitor certificates, locally generated private keys, backend HTTPS trust,
  or GitHub OAuth/API trust.
- The [domain operator's ability to impersonate a hostname](SECURITY.md#domain-and-certificate-authority).

The file is trusted operator configuration. Adding a CA authorizes it to sign
certificates for these client connections. Minimal containers still need a
normal system CA store for public endpoints; this feature does not bundle a
second public root store. Go also has platform-specific native trust and
`SSL_CERT_FILE`/`SSL_CERT_DIR` behavior; an explicit CA file avoids depending on
those environment variables for the additional trust.
