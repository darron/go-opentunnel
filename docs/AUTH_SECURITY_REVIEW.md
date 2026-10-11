# Password and GitHub security review — 2026-10-10

This pre-v0.4.0 review examined the universal HTTP gate, password login, GitHub
registration/OAuth, sessions, machine tokens and upstream credential handling.
A fresh-context read-only reviewer independently inspected the implementation
and reproduced findings. A subsequent genuine `claude -p` review inspected the full auth feature and
identified additional defects. Findings were checked against code and reproduced
before accepting fixes. Claude’s focused confirmation found all original findings resolved or supported
by the dispositions below, with no new security/correctness blocker. The recorded
local/race/password/GitHub/CLI/app checks passed; Linux CI awaits the commit.
Amp and Oracle subsequently found two P2 shutdown/revocation races and no P0/P1
issue. Both were reproduced and fixed. `make check` passed with zero lint issues and a
fresh full race run passed on the final tests (auth: 61.758 seconds). Post-Amp
public password/CLI/app repeats passed, including API 404 cleanup. Amp’s focused confirmation and Oracle agreed both original P2 findings are
resolved, with no new material correctness/security finding and no commit blocker.
Its release caveat referred to pending exact-commit CI and the public repeats,
which were still running when the confirmation prompt was sent; both drivers
subsequently completed successfully. Exact-commit CI remains pending.

## Findings and disposition

| Finding | Disposition |
| --- | --- |
| Authenticated responses inherited public upstream caching policies | Fixed for both modes: force `private, no-store`, `Pragma: no-cache`, expired `Expires`; remove common CDN overrides and `X-Accel-Expires`. Regression tests failed before the fix and pass afterward. |
| Invalid password forms/CSRF consumed the global verification budget | Fixed: bounded parsing and CSRF validation precede admission. Busy hash slots also do not spend the budget. Regressions demonstrated the failures before correction. The limiter test uses a frozen clock rather than hashing speed. |
| Login floods can deny new logins | Retained bounded limits: ten password attempts with one-per-second refill/two hashing slots; 256 GitHub pending states expiring after ten minutes. Valid-CSRF attackers can compete for password work; GitHub floods can exhaust pending capacity. No oldest-state eviction, which would let floods invalidate legitimate in-progress logins. |
| GitHub provider revocation does not revoke an existing local session immediately | Documented: identity is checked at login. Local sessions last eight hours and end on logout/restart; stop/restart to revoke all browser access. Changing an allowlist requires stopping that profile. |
| Fresh auth setup retained an orphaned machine-token registry | Fixed: every successful initialization resets tokens before saving the new backend. Save failures after reset remain fail-closed. |
| Empty profile used a different lock from its default-profile storage | Fixed: normalize once after CLI flag parsing; reset/setup/proxy share the default lock. |
| Atomic registry rename could falsely revoke retained tokens and their streams | Fixed: no-follow open first, validate the opened descriptor, bounded read. Nonblocking open also rejects FIFOs without waiting for a writer. A deterministic replacement test reproduced the old failure. |
| Another loopback visitor could rebind the setup browser | Fixed: one-use capability, clean redirect, browser binding retained on refresh, distinct cookies across concurrent wizards. All routes use `/__otgo/github/setup`. |
| Browser cookie requests could load foreign subresources without Origin | Added fetch-metadata protection for foreign scripts/images/frames/API requests; allow top-level GET navigation. The sibling-OpenTunnel premise was conditional and does not apply to an up-to-date Public Suffix List, which contains `opentunnel.xyz`. |
| Backend no-referrer response policy broke normal form POSTs | Fixed response header to `same-origin`. Arbitrary HTML meta policies/sandboxing can still produce null Origins and are explicitly refused; no HTML rewriting or null-Origin exception. |
| Weak supplied passwords and ambiguous backend Set-Cookie values | Require 12–1024 bytes for new verifiers; drop nameless and case-insensitive reserved gate cookies. Previously saved verifiers remain readable. |
| Cancelled GitHub setup could save credentials during graceful shutdown | Fixed: bind request contexts to wizard cancellation, serialize cancellation with the save boundary, and join accepted callbacks before releasing profile locks. Cancellation before saving retains the previous config; an already-started save reports its actual result. Regressions failed before the fix and without callback joining. |
| Revocation could close a client connection after its handler finished | Fixed: serialize handler completion with cancellation and transport abort so net/http cannot reuse the connection before the old close completes. A paused-close regression reproduced the race; completed requests still reject late revocation. |
| Idle connections could retain visitor channels indefinitely | Set HTTP idle timeout to 30 seconds without imposing read/write deadlines on active authenticated streams. |
| Shared handler admission independently starved existing authenticated users | Not established in production: the outer transport already caps 256 visitor channels and advertises HTTP/1.1 only. A direct-handler harness bypassed that limit. Connection-flood availability remains documented; no admission refactor was made. |


No concrete anonymous forwarding, allowlist bypass or upstream credential leak
was found in the reviewed paths. This conclusion applies to the tested revision
and scenarios; it is not a proof that every possible attack has been excluded.

The NGINX-specific header is removed because it can override standard cache
headers. See [NGINX proxy-cache documentation](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_cache_valid). The regression was observed failing
with that header present before it was added to the filter. No live NGINX cache
was used in this exercise.

The domain entry was verified in the [current Public Suffix List](https://publicsuffix.org/list/public_suffix_list.dat).
Fetch checks follow the [W3C Fetch Metadata fields](https://www.w3.org/TR/fetch-metadata/).
These controls supplement the exact-Origin rule; they are not a client identity
mechanism for callers that can choose their own headers.

## Regression coverage

- Both auth modes: nine HTTP methods across eleven paths, including MCP,
  discovery, assets, SSE/WebSocket and encoded/reserved path variations. Spoofed
  identity/forwarding headers grant no access; backend counters remain zero.
- Both auth modes: a deliberately public-cacheable backend is overridden;
  session revocation returns 401 without the protected body.
- GitHub callbacks: missing/duplicate browser binding, duplicate state/code,
  denied numeric identity, provider denial, failed exchange and failed identity
  lookup issue no session or backend request. Responses do not reflect secret
  canaries and retain no-store/no-referrer policies.
- Password admission: repeated bad-CSRF, malformed and oversized submissions
  leave a valid login available. Occupied hashing slots preserve the work budget.
- New Claude-review regressions cover one-use setup capabilities/rebinding,
  per-wizard cookies, empty-profile lock exclusion, stale-token reset including
  save failure, deterministic atomic reads/FIFO rejection, foreign subresource
  denial/top-level navigation, backend form policy/reserved cookies and idle limits.
- Amp regressions cancel a real loopback wizard while provider conversion is
  paused, verify unchanged configuration, and cancel after persistence while
  terminal output is paused beyond the HTTP shutdown interval. The command must
  join that callback and report its committed result. A paused transport close
  must prevent request completion/keep-alive reuse until abort finishes.
- Existing tests cover state/PKCE/replay/expiry, Origin/SNI, private storage,
  credential ambiguity/redaction, logout and stream revocation.

Local OAuth tests substitute provider HTTP. The gate,
callback handlers, sessions and instrumented backend execute real code.

## Live evidence and limits

The owner created a temporary GitHub App through the wizard and approved its
identity grant. Real GitHub OAuth reached `protected-backend` at the public
HTTPS root. Logout returned to login. Reconfiguring the same App to allow only
`octocat` denied the owner's real account: callback did not redirect to the
backend and the root remained behind login. Returning the allowlist to the owner
restored authenticated access.

An isolated GitHub-mode public-service matrix denied anonymous methods/routes,
forged credentials and callbacks without any backend requests. Machine access
stripped gate credentials/spoofed identity and respected revocation. Password
live testing uses `scripts/auth_smoke.py`; dated final results and cleanup are in
[LIVE_TESTING.md](LIVE_TESTING.md), with local checks in [VERIFICATION.md](VERIFICATION.md).

Chrome intermittently displayed `ERR_BLOCKED_BY_CLIENT`, including after a
successful registration conversion and authenticated backend request. Its
extension UI also interrupted automation. The owner subsequently saw the real
backend and native UI inspection confirmed it. No certificate validation or
browser security protection was disabled; the responsible extension was not
established. Provider failure status/body assertions come from automated tests,
not from Chrome's blocked error display.

After the additional Claude fixes, the entire password smoke passed again
(revocation: 0.389 seconds), as did the rebuilt CLI/embedding-app workflow. A new
real GitHub App went through the one-use `/__otgo` setup flow and OAuth; the backend
was visible, logout worked, an excluded identity stayed behind login, restoring
the allowlist permitted a session, and restart invalidated it. Both test-App
deletions were owner-approved and accepted/queued by GitHub.

After the two Amp lifecycle fixes, the final rebuilt password smoke passed again
(SSE/WSS revocation: 0.236 seconds), followed by complete CLI/listener/embedding-app
public-service validation. All temporary identities returned API 404 and all
owned processes stopped. The real GitHub run predates those last lifecycle fixes;
the changed wizard shutdown paths were retested with actual loopback HTTP and
a provider fixture, including conversion cancellation and committed callback
joining. No third real-provider App was created for those narrow corrections.

The test profiles were stopped, local auth credentials removed and remote tunnel
deletion confirmed with API 404. After owner confirmation, GitHub accepted App
deletion and removed it from the Apps list; its UI reported deletion queued.

HTTP cache controls cannot revoke content already received or application-managed
storage. This review does not verify alternate direct backend ingress, an MCP
OAuth negotiation implementation, GitHub account suspension live, extended
certificate renewal, or runtime behavior on every supported OS. Keep the backend
on loopback. The hosted domain/certificate trust boundary remains described in
[SECURITY.md](SECURITY.md).
