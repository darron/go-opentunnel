# Auth proxy security and correctness review — 2026-10-10

A fresh-context, read-only reviewer examined the CLI/auth implementation against
its approved requirements and ran independent race tests, vet and diff checks.
This was a development review, not an external audit or an Amp/Oracle review.

The first pass found four important issues and a portability issue. Each was
verified and addressed before final testing:

| Finding | Resolution and regression |
| --- | --- |
| TLS close could wait five seconds for a non-reading peer, delaying revocation/shutdown | Abort the underlying transport outside the lease mutex. A real TLS/net.Pipe regression verifies termination within one second. Completed leases ignore stale watcher snapshots, preserving reused connections. |
| Runtime formatting exposed private credentials | Owning objects redact pointer/value formatting and use shared state pointers so formatting never copies mutexes. Tests cover common fmt verbs with an active credential and password/GitHub secrets. |
| Two incomplete login bodies held both hash slots indefinitely | Parse bounded forms under a two-second read deadline before acquiring hashing slots. Real HTTP connection tests cover URL-encoded, JSON and multipart slow bodies, with normal login remaining available. |
| Windows skipped private ownership/permission checks | Refuse auth storage on Windows and other platforms lacking required protections before creating files. SDK/other CLI features still compile. Private Windows ACL support remains future work. |
| Unix build tag broke Solaris compilation | Narrow flock targets and provide a fail-closed fallback. Solaris auth-package and Windows/Linux CLI compilation passed. |

Follow-up review found two further gaps:

- `ParseForm` ignores non-form bodies. Clearing the deadline could leave net/http
  draining them forever. Unsupported types now retain the deadline and close the
  connection. All untrusted bodies have a deadline, including denied routes,
  bad-Origin login and unknown owned endpoints. Authenticated forwarding clears
  it; a delayed-upload regression verifies legitimate uploads keep working.
- The tap workflow published before testing the candidate. It now installs/tests
  on macOS before pushing. A further token-boundary finding led to tap-owned
  updater code, read-only validation and a fresh write-authorized publishing job.
  Release binaries never run in the publisher. The publisher uses its own token;
  the later release-triggered dispatch uses a tap-only Actions-write secret.

No concrete anonymous-forwarding bypass was found in the universal gate,
Host/SNI/Origin validation, fixed upstream rewrite, credential stripping, OAuth
state/PKCE/numeric allowlist or bound-identity startup. Follow-up fixes were reviewed
and tested. [VERIFICATION.md](../VERIFICATION.md) and [LIVE_TESTING.md](../LIVE_TESTING.md)
record actual local/hosted evidence and limits.

The final release-dispatch review found no further issues. It checked stable
release validation, environment/JSON handling of tags, manual main-only guards,
the tap-only Actions-write credential, immutable tap checkouts and separation of
validation from publishing. Both workflows passed `actionlint`; all five tap
updater tests passed. Live results are recorded in [VERIFICATION.md](../VERIFICATION.md).

A separate [pre-v0.4.0 security review](../AUTH_SECURITY_REVIEW.md) covers both auth
modes, real GitHub registration/login/allowlist denial and subsequent cache and
password-admission fixes. Its known availability and revocation limits supersede
any broader interpretation of the earlier readiness statement above.
