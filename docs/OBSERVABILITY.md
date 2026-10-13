# Monitor otgo and embedded clients

Available in v0.9.0 and later.

Metrics are optional. They describe this Go process, not the hosted relay's
ACME jobs, database, DNS provider or other tunnels.

## Run otgo with metrics

Choose a separate loopback port for each running instance:

```sh
otgo proxy --profile inbox --metrics-listen 127.0.0.1:9091
otgo proxy --profile another-app --metrics-listen 127.0.0.1:9092
```

Scrape `http://127.0.0.1:9091/metrics`. The same flag works with `connect` and
`listen`. Without the flag or a saved `metrics_listen` value, otgo starts no
metrics server. `localhost` binds
IPv4 loopback; literal IPv4 and IPv6 loopback addresses are accepted. Port `0`
chooses an available port; otgo prints the actual URL. Wildcard and non-loopback
addresses are rejected. A port already in use fails before tunnel startup.

For a saved proxy, find its config with `otgo auth paths --profile inbox` and add
`"metrics_listen": "127.0.0.1:9091"` as a top-level field in the existing
`auth.json`. The next `otgo proxy --profile inbox` uses that address automatically.
Use a different saved port for each profile. An omitted or empty value disables
metrics. An explicit `--metrics-listen` overrides the saved value for that run;
`--metrics-listen=""` disables it without changing the file. Config values get
the same loopback-only validation; an invalid saved address fails config loading.
`connect` and `listen` use the flag directly.

The listener is local and separate from the public tunnel. It has no password
or GitHub login: local processes can read it. Do not forward its port through
another proxy or tunnel unless you provide your own access controls.
The public authentication gate does not gain a metrics route.
The listener rejects unrelated Host headers and foreign browser origins; normal
Prometheus scrapes need no Origin header.

An example Prometheus scrape job:

```yaml
scrape_configs:
  - job_name: otgo
    static_configs:
      - targets: ['127.0.0.1:9091', '127.0.0.1:9092']
```

For Prometheus on another machine or in a container, arrange a protected route
to loopback yourself. Do not bind the admin listener to the internet.

## Embed in a Go application

Use `client.Stats()` for a concurrent snapshot without starting a server.
`connection.Stats()` covers one connection and its reconnects. `client.API().Stats()`
covers control API calls, including calls made directly through that API.
Client totals survive connection shutdown; counters reset when a new client is
created. Snapshots contain no credentials or tunnel identity.

The optional adapter uses the official Prometheus Go client. Register it with
your application's registry:

```go
registry := prometheus.NewRegistry()
registry.MustRegister(metrics.NewCollector(client))
handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
// Mount handler on an administrative server you control.
```

Imports:

```go
"github.com/darron/go-opentunnel/metrics"
"github.com/prometheus/client_golang/prometheus"
"github.com/prometheus/client_golang/prometheus/promhttp"
```

The core `opentunnel` package does not import Prometheus. The adapter starts no
server and registers nothing globally. Register one source per registry: a
client already includes its connections, so registering both would double-count
work and conflict on metric descriptors.

## Read the numbers

- Control API counters count one completed logical operation, even when it retries.
  Total duration includes retries, backoff, response-body reading and validation.
  Only the final failure counts as an error; successful retries do not.
- Bridge attempts and attachments distinguish relay connection attempts from
  successful attachment. An attach failure is separate from a later disconnect.
- Visitor counters cover admission and closure. Active visitors include TLS
  handshakes and queued listener connections.
- Byte counters measure data-frame payload received from valid relay frames
  and successfully sent outgoing payload, including TLS headers and handshakes.
  Incoming totals include payload
  later rejected for an unknown channel or a full buffer. They exclude WebSocket
  framing and control messages; they are not plaintext HTTP byte counts.
- Buffered bytes measure queued inbound payload. Event drops count missed
  lifecycle notifications. Neither replaces the operation counters.
- Certificate failure counts describe **failed responses observed by this
  client**. Polling the same failed state again increments the count again.
  They cannot reveal the server's individual issuance attempts.
- Proxy metrics describe request gating, terminal browser login outcomes and
  received backend response headers. A response count does not prove a stream
  completed. Go runtime metrics describe the local process.

Snapshots may combine values observed at slightly different instants during
concurrent work. Gauges settle after workers finish. Metrics do not depend on
reading `Events()`, which is a bounded, lossy notification channel.

otgo's labels use fixed categories. Metrics omit profiles, hostnames, addresses,
request paths, usernames, tokens, raw provider errors and private keys. They
still reveal activity and timing to anyone who can scrape the local listener.

Client metric names start with `opentunnel_client_`:

| Measurement | Suffix |
| --- | --- |
| API completions and failures | `api_requests_total`, `api_errors_total` |
| API duration summary | `api_request_duration_seconds` (`_count`, `_sum`; no quantiles) |
| Bridge lifecycle | `bridge_attempts_total`, `bridge_attaches_total{result="ok|error"}`, `reconnects_total` |
| Visitor lifecycle | `visitor_connections_total{outcome="accepted|rejected"}`, `visitor_connections_closed_total` |
| Transport payload | `visitor_bytes_total{direction="in|out"}` |
| Current resource use | `bridges_attached`, `visitor_connections_open`, `inbound_buffered_bytes` |
| Lost notifications | `dropped_events_total` |
| Observed certificate failures | `certificate_failures_total{class="..."}` |

The `|` notation above lists allowed values, not a literal label value.
For example, `rate(opentunnel_client_visitor_bytes_total{direction="in"}[5m])` gives incoming
relay payload bytes per second over five minutes. Scrape targets distinguish CLI
instances; otgo does not attach profile labels.

Shared family names and labels follow [upstream observability](https://github.com/anomalyco/opentunnel/blob/4b066b2ed40a4e0c325e60c68061599f2151d897/crates/opentunnel-server/src/metrics.rs).
The `opentunnel_client_` prefix distinguishes client scope from server scope.
Client bytes update as relay frames arrive or are successfully sent; upstream
records its visitor-byte totals when connections finish. Client attach results
use `ok` and `error`, and visitor admission outcomes use `accepted` and `rejected`.
These do not claim the server's more detailed outcomes. API and proxy statistics
are client additions. Server ACME attempts, database queries and cluster routing
are outside this client's view.

The CLI authentication gate adds these families:

| Family | Fixed labels and meaning |
| --- | --- |
| `opentunnel_proxy_requests_total` | `outcome`: `admitted`, `auth_denied`, `origin_denied`, `protocol_denied`, `public_denied`, `unavailable`, `owned`; one routing decision per request |
| `opentunnel_proxy_backend_responses_total` | `class`: `1xx`, `2xx`, `3xx`, `4xx`, `5xx`, `other`; received response headers, including WebSocket `101` |
| `opentunnel_proxy_backend_errors_total` | Reverse proxy errors handled by its error handler |
| `opentunnel_proxy_logins_total` | `mode`: `password`, `github`; `outcome`: `success`, `failure`; terminal password POST or GitHub callback outcomes |

`owned` means the gate handled its reserved routes locally. Machine-token
admission contributes to request outcomes, not browser login counts. Anonymous
requests and login pages can increase counters without any backend request.
The local registry also includes the official Go runtime collector, including
its Go version information; it omits the process collector. These gate counters
are CLI additions, not upstream server families.

## Half-closed connections

A peer can finish sending while it continues receiving. otgo preserves that
behavior, then closes a half-closed channel after **60 seconds of inactivity**.
Traffic in the remaining direction renews the inactivity period; the timeout is
not a fixed deadline for a slow response.

Override it on `proxy`, `connect` or `listen`:

```sh
otgo proxy --profile inbox --half-close-timeout 2m
```

Embedded applications use `TransportOptions.HalfCloseTimeout`. Zero selects
60 seconds; negative values are invalid. Fully open quiet connections are not
subject to this timeout. The separate `IdleTimeout` remains disabled by default.

`Connect` observes the decrypted stream's half-close. `Listen` observes explicit
relay end messages and local raw half-closes. It cannot infer an encrypted TLS
`close_notify` before the application reads it: accepted connections remain
ordinary `*tls.Conn` values. Applications must still close connections they own.
