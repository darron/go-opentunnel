# Security model

OpenTunnel carries the visitor's TLS connection through the relay to this Go process. The relay's outer HTTPS/WebSocket connection is independently authenticated; the visitor's application TLS is terminated here using the tunnel certificate and private key. A normally operating relay can route encrypted records without seeing HTTP paths, headers, cookies, request bodies, or application WebSocket messages.

The relay can still observe tunnel and route names, source addresses, SNI and other ClientHello metadata, timestamps, connection counts, and encrypted traffic volumes. It is not an anonymity system. After local TLS termination, forwarding to a plaintext target exposes application traffic on that target's network path. The included example binds only loopback for that reason.

The hosted provider controls the tunnel hostname's DNS and ACME DNS authorization. A malicious or compromised operator with that authority could obtain a separately trusted certificate and impersonate a tunnel hostname to visitors. Validating the certificate returned to this client proves that it matches this client’s private key; it cannot prevent a different certificate from being presented elsewhere. Use an application layer with independently authenticated keys if that authority must be excluded.

Do not log, serialize, or share an `Identity` token or private key. Their JSON fields are omitted by design. Keep file storage readable only by the account that runs the tunnel. Use `NewFileStorage` when an application owns a specific protected directory; `NewXDGStorage` follows the compatible default location. A profile name is not a security boundary.

The client relies on normal HTTPS certificate verification for API and bridge connections and does not provide a switch to disable it. Visitor TLS requires modern protocol versions and forward-secret authenticated encryption as provided by Go’s TLS stack. Route targets identify a trust boundary: `127.0.0.1:port` reaches only the local host, while a LAN or Internet target allows plaintext application bytes to leave the process.
