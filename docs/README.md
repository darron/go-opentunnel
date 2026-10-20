# Documentation

Start with one of these guides. The [project README](../README.md) has install
commands and the shortest working examples.

## Use otgo

| Task | Guide |
| --- | --- |
| Protect an app with password or GitHub login | [Auth proxy](AUTH_PROXY.md) |
| Use the otgo mark or check icon attribution | [Artwork](BRAND.md) |
| Set up saved profiles or run multiple backends | [Profiles and persistence](AUTH_PROXY.md#profiles-and-persistence) |
| Verify the GitHub user at your backend | [Signed identity](AUTH_PROXY.md#signed-backend-identity) |
| Give a machine client or MCP endpoint access | [Machine clients and MCP](AUTH_PROXY.md#machine-clients-and-mcp) |
| Install or update the CLI; maintain release automation | [Homebrew](HOMEBREW.md) |
| Download verified binaries or publish a release | [Release binaries](RELEASES.md) |
| Scrape local metrics or read client statistics | [Observability](OBSERVABILITY.md) |
| Understand who can see traffic and where authentication ends | [Security model](SECURITY.md) |

## Embed or develop the Go client

| Task | Guide |
| --- | --- |
| Forward to a TCP backend with PROXY v1/v2 headers | [Forwarding](FORWARDING.md) |
| Connect to an API/relay using a private CA | [Custom CA trust](CUSTOM_CA.md) |
| Diagnose certificate issuance failures | [Certificates](CERTIFICATES.md) |
| Serve HTTP directly through the tunnel | [TLS listener](LISTENER.md) |
| Browse exported types, methods and Go examples | [Go API documentation](https://pkg.go.dev/github.com/darron/go-opentunnel) |
| Find API, protocol and storage contracts | [Package reference](DESIGN.md) |
| Navigate source files and resource limits | [Implementation](IMPLEMENTATION.md) |
| Run local tests or repeat a public-service check | [Testing](TESTING.md) |

## Review the evidence

| Record | Scope |
| --- | --- |
| [Security and test audit](SECURITY_AUDIT.md) | v0.7.0 hardening, meaningful test checks and compatibility evidence |
| [Auth security review](AUTH_SECURITY_REVIEW.md) | v0.4.0 password/GitHub findings, fixes and remaining limits |
| [Verification](VERIFICATION.md) | Dated local checks, CI, release and Homebrew results |
| [Upstream compatibility](UPSTREAM_COMPATIBILITY.md) | Adopted changes, existing protections and server-only changes |
| [Live testing](LIVE_TESTING.md) | Dated public-service and browser observations |
| [Historical reviews](archive/README.md) | Earlier findings and their dispositions |

Validation records describe the revisions tested. They do not certify later code
changes or the hosted operator's deployed source.
