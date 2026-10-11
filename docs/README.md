# Documentation

Start with the guide for your task. The [project README](../README.md) has the
installation commands and quick starts.

## Use otgo

| Task | Guide |
| --- | --- |
| Protect an app with password or GitHub login | [Auth proxy](AUTH_PROXY.md) |
| Set up saved profiles or run multiple backends | [Profiles and persistence](AUTH_PROXY.md#profiles-and-persistence) |
| Give a machine client or MCP endpoint access | [Machine clients and MCP](AUTH_PROXY.md#machine-clients-and-mcp) |
| Install or update the CLI; maintain release automation | [Homebrew](HOMEBREW.md) |
| Understand who can see traffic and where authentication ends | [Security model](SECURITY.md) |

## Embed or develop the Go client

| Task | Guide |
| --- | --- |
| Serve HTTP directly through the tunnel | [TLS listener](LISTENER.md) |
| Find API, protocol and storage contracts | [Package reference](DESIGN.md) |
| Navigate source files and resource limits | [Implementation](IMPLEMENTATION.md) |
| Run local tests or repeat a public-service check | [Testing](TESTING.md) |

## Review the evidence

| Record | Scope |
| --- | --- |
| [Auth security review](AUTH_SECURITY_REVIEW.md) | v0.4.0 password/GitHub findings, fixes and remaining limits |
| [Verification](VERIFICATION.md) | Dated local checks, CI, release and Homebrew results |
| [Live testing](LIVE_TESTING.md) | Dated public-service and browser observations |
| [Historical reviews](archive/README.md) | Earlier findings and their dispositions |

Validation records describe the revisions tested. They do not certify later code
changes or the hosted operator's deployed source.
