# v0.3.0 Amp security and correctness review

Reviewed on **2026-10-10** with the `amp-review` workflow and an actual Oracle
second opinion. The review covered `v0.2.0` (`5a29926`) through `1463912`, plus
the pending changelog and README link. Its scope was the new listener API,
connection cleanup, CLI, example, regressions, and documentation.

[Review thread](https://ampcode.com/threads/T-01a1275e-77cb-7629-930c-76dba68b61b9).
The [earlier Amp review](AMP_REVIEW.md) covers the v0.2.0 hardening.

**Initial recommendation: hold release.** Oracle identified a removal race,
which Amp reproduced in an isolated copy. Amp also found contradictory design
documentation. Both findings were accepted after independent verification.

**Focused confirmation: PASS.** Amp verified both fixes and found no remaining
concrete release blocker in the reviewed paths. Confidence in those specific
fixes is high. The confirmation covered the working-tree fixes and changelog
before the release commit.

## Findings and fixes

| Finding | Severity | Resolution |
| --- | --- | --- |
| Removing a profile could leave paused listeners with `Err() == context.Canceled` and make `Accept` return that error instead of `net.ErrClosed` | P2, release blocker | Mark each matching connection as explicitly closing before canceling it. Continue joining workers outside the client mutex. |
| Design docs omitted `otgo listen`, described the old example default, and denied the existence of a public tunnel listener | P3 | List the new CLI command, describe the direct-listener default and forwarding option, and update the package scope. |

The removal ordering existed before this release, but violated the new
listener's documented terminal-error contract. The regression
`TestListenerRemovePausedListenersReportsClosed` creates 64 listeners, pauses
their routes, and removes the shared profile. It checks that all workers have
exited, terminal errors are nil, and `Accept` reports `net.ErrClosed`.
Before the fix, **all 64 listeners failed** with `context.Canceled`.
After the fix, the regression passed **ten race repetitions**.

## Verification

After the fixes, the following passed locally:

```sh
go test -race -run '^TestListenerRemovePausedListenersReportsClosed$' . -count=10
make check
go test -race ./... -count=1
GOTOOLCHAIN=go1.25.0 go test ./... -count=1
```

`make check` includes all package and CLI tests, vet, formatting, CLI/example
builds, and golangci-lint 2.14.0, which reported **0 issues**. Amp's initial
review also ran the full race suite, ten listener race repetitions, Go 1.25
tests, vet, formatting, lint, builds, and CLI help. Those checks passed; its
additional removal probe exposed the defect.

Amp independently reran all listener tests with ten race repetitions, a fresh
full race suite, ten Go 1.25 repetitions of the new removal regression, vet,
formatting, lint (**0 issues**), and `git diff --check`. All passed.

Amp did not edit the repository or access credentials or the live service.
Oracle completed the initial second opinion; the focused confirmation uses
that critique without another Oracle call.

The rebuilt CLI and embedded app subsequently repeated the full public-service
workflow with **exit 0** and verified deletion of all three temporary identities.
See [the live record](LIVE_TESTING.md#v030-post-review-retest-2026-10-10) and
[verification details](VERIFICATION.md#v030-review-follow-up-2026-10-10).

## Scope and confidence

The initial review established no additional code blocker or security
vulnerability. It examined actual `*tls.Conn` delivery, SNI authorization,
certificate checks, admission bounds, reconnect cleanup, orderly output close,
deadline workers, and peer trust. These checks provide evidence for the reviewed
paths; they do not establish every input or long-running production behavior.
The hosted operator remains inside the documented certificate/DNS trust
boundary, and relay peer metadata remains relay-trusted. See
[SECURITY.md](SECURITY.md) and [listener contracts](LISTENER.md).
