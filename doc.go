// Package opentunnel exposes local applications over OpenTunnel HTTPS.
// It terminates visitor TLS in your process and either serves an HTTP handler
// through a net.Listener or forwards decrypted bytes to a TCP backend.
//
// # Start a tunnel
//
// Create a [Client] with [NewClient]. Zero [ClientOptions] use the hosted
// [DefaultAPI] and persistent [NewXDGStorage]. Choose [NewMemoryStorage] for
// temporary identities or [NewFileStorage] for an application-owned directory.
// A profile names one stored tunnel; an empty profile selects "default".
//
// Use [Client.Listen] for direct HTTP serving. Pass its [Listener] to
// [net/http.Server.Serve], not ServeTLS: accepted connections have already
// completed TLS, and http.Request.TLS contains the actual handshake. Use
// [Client.Connect] to forward traffic to existing host:port targets instead.
// In both APIs, route "@" selects the root hostname; a lowercase DNS label
// selects that subdomain. The method examples show both paths. Set
// [ConnectOptions].RouteOptions to emit [ProxyProtocolV1] or [ProxyProtocolV2]
// headers to a backend that supports them. [Connection.SetRoutesWithOptions]
// replaces targets and options together; SetRoutes clears forwarding options.
//
// # Lifetime and shutdown
//
// The context passed to Connect or Listen bounds provisioning and initial
// attachment only. Cancelling it after a successful return does not stop the
// tunnel. Set Lifetime in [ConnectOptions] or [ListenOptions] to an application's
// shutdown context, or close the returned connection explicitly.
// [Client.Close] stops all operations and connections owned by that client.
//
// [Connection.Close] and [Listener.Close] retain stored credentials and the
// remote tunnel. Use [Client.Remove] to delete them. Closing joins package
// workers and aborts active visitor sockets; it does not join application
// handlers or gracefully drain HTTP requests. Applications own that work.
//
// # State, routes and concurrency
//
// Clients, connections and listeners support concurrent method calls. Construct
// them through NewClient, Connect and Listen; their zero values are not usable.
// Coordinate provisioning and route claims across separate clients or processes,
// even when they share storage. Within one client, overlapping routes for the
// same profile return [ErrRouteInUse]; disjoint routes may run concurrently.
//
// Connections retry transient bridge failures. Use [Connection.Status] or
// [Listener.Status] for snapshots. Events are bounded and lossy; inspect
// DroppedEvents in [Status] rather than assuming every transition was delivered.
// Set OnEvent in [ConnectOptions] or [ListenOptions] to observe startup and running
// events synchronously; callbacks must return promptly and must not close their
// owners. Set OnRouteConflict to [RouteConflictFail] for a fatal route conflict;
// the default retries. [Connection.URLs] and [Listener.URLs] return configured URLs.
// [PublicURL] builds a URL without connecting; [IsValidRouteName] validates names.
// Wait for Done before reading the final Err. Resource bounds and timeout
// defaults are documented in [TransportOptions].
//
// # Outbound proxies
//
// Default transports capture HTTP_PROXY, HTTPS_PROXY and NO_PROXY at construction,
// with ALL_PROXY as a fallback when a scheme-specific proxy is unset. Lowercase
// spellings also work. API calls and bridge connections share that policy.
// An explicit [ClientOptions].HTTPClient transport remains a trusted override.
// See the [outbound proxy guide] for bypass rules, credentials and diagnostics.
//
// # Statistics
//
// [Client.Stats], [Connection.Stats] and [API.Stats] expose concurrent operation
// snapshots without consuming events or starting a server. Client totals retain
// stopped connections. The optional metrics subpackage adapts these snapshots
// to the official Prometheus Go client; register its collector with an
// application-owned registry and protect the administrative HTTP endpoint.
//
// # Credentials and provisioning errors
//
// [Identity] and [PendingIdentity] contain live tokens and private keys. Their
// JSON, fmt and slog representations redact credentials; direct field access
// does not. Custom [Storage] implementations must persist secret fields
// explicitly, protect them at rest and honor context cancellation.
// Low-level API responses, including [CreateTunnelResponse], are not redacted.
//
// [Client.Get], [Client.Pending] and [Client.Resume] return (nil, nil) when no
// matching local identity exists. Use [Client.EnsureWithOptions] to observe
// provisioning or certificate checks while reusing an identity. Interrupted provisioning may leave a pending
// identity that Resume can finish or Remove can delete. If both persistence and
// remote cleanup fail, use errors.As to inspect [ProvisioningError] and securely
// recover or delete its Pending identity. Use errors.Is for package sentinel
// errors and errors.As for [APIError], [AttachError] and [CertificateIssuanceError].
// Certificate failures have safe classifications and HTTP status. Their bounded
// raw Reason is untrusted and omitted from fmt, JSON and slog output.
//
// # Authentication and trust
//
// The library does not authenticate visitors. Add authentication to your handler
// or use the otgo CLI's proxy command for password/GitHub login and machine
// tokens. The CLI's ordinary connect and listen commands also expose services
// directly. Relay-provided peer metadata is not an independently verified
// visitor address and should not be treated as an end-to-end identity.
//
// Set [ClientOptions].CACertFile to add PEM certificates to the API and relay
// trust roots. For low-level [NewAPI] use, [NewHTTPClientWithCACert] builds an
// HTTP client with the same behavior. Certificate and hostname verification stay
// enabled. The library does not read OPENTUNNEL_CA_CERT; that variable belongs
// to otgo. This setting does not affect visitor TLS or backend connections.
//
// The local private key never leaves the client. A normally operating relay
// carries encrypted visitor TLS, but the hosted domain/certificate operator
// remains inside the HTTPS trust boundary and could impersonate the hostname
// with another trusted certificate. See the [security model] and [auth guide].
//
// [security model]: https://github.com/darron/go-opentunnel/blob/main/docs/SECURITY.md
// [outbound proxy guide]: https://github.com/darron/go-opentunnel/blob/main/docs/OUTBOUND_PROXY.md
// [auth guide]: https://github.com/darron/go-opentunnel/blob/main/docs/AUTH_PROXY.md
package opentunnel
