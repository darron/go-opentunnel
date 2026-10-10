# Authenticated otgo Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans
> for native implementation, or superpowers:subagent-driven-development if the
> user selects delegation. Complete the tasks below with their test cycles.

**Goal:** Add a reusable password-protected HTTP proxy to otgo, then GitHub
OAuth login and guided registration, protecting every upstream endpoint.

**Architecture:** A private `internal/authproxy` package owns configuration,
credentials, sessions, the request gate, and reverse proxy. The CLI owns
OpenTunnel lifecycle and setup commands. No new public SDK API is needed.

**Tech Stack:** Go 1.25, standard-library HTTP, crypto, JSON, filesystem, and
httputil; the existing coder/websocket dependency supports tests and examples.
Start without a new dependency. Add one only for a demonstrated requirement.

**Spec:** [AUTH_PROXY_DESIGN.md](AUTH_PROXY_DESIGN.md).

## Global constraints

- Work on `main`; preserve unrelated `.vscode/` files and existing user edits.
- No version bump or release. Retain MIT licensing and OpenTunnel compatibility.
- Password browser login first, GitHub OAuth second, manual machine tokens for
  initial MCP compatibility. Full MCP OAuth discovery/server is outside this plan.
- Protect all upstream paths/methods; owned login endpoints never proxy.
- Sessions: eight-hour default, in memory, invalidated on restart. Machine tokens:
  one-hour default, maximum 24 hours, hashes only, `otgo_` prefix.
- Stream revocation polling at most one second; credential expiry bounds streams.
- GitHub state is browser-bound, single-use, expiring, and protected with PKCE S256.
- Bind stored proxy configuration to tunnel ID, hostname, and normalized API origin.
- XDG config/data defaults and explicit override semantics are specified in the
  design. Secrets are never cache entries or routine command output.
- Preserve package, diagnostic CLI, and embedded-app behavior; document tests.

## Review focus

1. A restart or missing tunnel must reuse setup or refuse startup, never create
   an unprotected/new public identity silently. Tasks 1 and 5 cover it.
2. Gate credentials must coexist with backend Authorization and cookies without
   leaking gate secrets or accepting duplicates. Tasks 3 and 4 cover it.
3. Cross-site requests from sibling tunnel domains must remain denied after
   backend Host/Origin adaptation. Tasks 3 and 4 cover it.
4. Expiry, logout, registry corruption, and shutdown must terminate existing
   streams and hijacked WebSockets, not just future requests. Tasks 2–4 cover it.
5. Successful GitHub app creation followed by failed persistence must report a
   public cleanup URL while retaining no unreviewed credentials. Task 7 covers it.

## Files and interfaces

Create focused files under `internal/authproxy`: `config.go`, `files.go`,
`password.go`, `tokens.go`, `sessions.go`, `gate.go`, `proxy.go`, `github.go`,
and `github_setup.go`, with corresponding `_test.go` files. Add `lock_unix.go`
and `lock_windows.go` for OS-backed file locks on mutable profile files. Keep the following
interfaces consistent between tasks; unexported helpers remain local choices.

- `Paths` has `AuthConfig`, `TokenFile`, and `TunnelRoot` string fields.
- `ResolvePaths(profile, tunnelRoot, authConfig, tokenFile string) (Paths, error)`
  resolves defaults and overrides without creating files or reading secrets.
- `Binding` contains `TunnelID`, `Hostname`, and `APIOrigin` strings.
- `Config` contains `Binding`, upstream URL, selected browser login mode,
  versioned password verifier, GitHub client credentials, and approved numeric
  GitHub IDs. Secret-bearing structs explicitly redact formatting and JSON status.
- `LoadConfig(path string) (Config, error)` and
  `SaveConfig(path string, cfg Config) error` validate protected files.
- `ValidateBinding(cfg Config, binding Binding) error` refuses identity changes.
- `PasswordVerifier` stores algorithm/version, salt, iteration count, and digest.
  `NewPasswordVerifier(password []byte) (PasswordVerifier, error)` and
  `VerifyPassword(verifier PasswordVerifier, password []byte) bool` own hashing.
- `TokenStore` is constructed by `NewTokenStore(path string) *TokenStore`.
  `Create(ttl time.Duration) (secret, id string, err error)`,
  `Revoke(id string) error`, and `Authenticate(secret string) (Principal, error)`
  implement bounded disk-backed token operations.
- `Principal` has public ID/auth mechanism and expiry, with no secret fields.
- `Sessions` is created by `NewSessions(limit int) *Sessions`.
  `Create(principal Principal, ttl time.Duration) (string, error)`,
  `Authenticate(secret string) (Principal, error)`, and `Revoke(secret string)`
  implement in-memory sessions. `Close()` invalidates sessions and stops workers.
- `BrowserAuthenticator` has `Register(mux *http.ServeMux)` for owned login
  handlers. Implement password and GitHub variants sharing the session service.
- `Options` includes Config, TokenStore, Sessions, and BrowserAuthenticator.
  `NewHandler(opts Options) (*Handler, error)` constructs the gated reverse proxy;
  `Handler` implements `http.Handler` and `Close() error` for all owned streams.
- GitHub helpers accept an injected `*http.Client` and fixed endpoint options in
  tests; production uses only the official HTTPS endpoints. No public insecure flag.

## Task 1: Persistent profile configuration and paths

**Files:** Create `config.go`, `files.go` and tests; modify `storage.go` and
`storage_test.go` only to correct relative XDG_DATA_HOME handling.

- [ ] Write `TestResolvePathsXDGAndOverrides`, covering unset/empty/absolute and
  relative XDG values, explicit paths, malformed profile names, and two profiles.
  Assert the exact defaults from the design and no filesystem creation.
- [ ] Write `TestConfigProtectedRoundTrip`, `TestConfigRejectsUnsafeFiles`,
  `TestConfigAtomicWriteFailure`, and `TestConfigBindingMismatch`. Assert restart
  reuse, secret redaction, symlink/mode rejection, bounded JSON parsing, previous
  file retention after a failed replacement, and wrong ID/hostname/API denial.
- [ ] Add interprocess mutation tests: competing config/token updates must
  serialize, release locks after process failure, and never resurrect a revoked
  token. Use Unix flock and the Windows LockFileEx API through standard-library
  OS facilities; bounded lock acquisition failures return an error.
- [ ] Extend the SDK XDG tests to assert relative overrides use the home fallback.
- [ ] Run focused tests, confirm the new tests fail for the missing behavior, then
  implement the interfaces above. Use 0700 application directories and 0600 files;
  refuse unsafe existing locations. Keep shared XDG base permissions unchanged.
- [ ] Run `go test ./internal/authproxy -run 'TestResolvePaths|TestConfig'` and
  `go test . -run TestXDG`; commit the tested configuration/storage changes.

## Task 2: Passwords, sessions, and machine credentials

**Files:** Create `password.go`, `sessions.go`, `tokens.go` and their tests.

- [ ] Write password tests asserting random salts, correct/wrong verification,
  PBKDF2-HMAC-SHA256 at least 600000 iterations, version/size rejection, and no
  plaintext persistence. Cap input at 1024 bytes; generated passwords use
  32 cryptographically random bytes encoded without padding.
- [ ] Write `TestSessionsExpiryRevocationAndCapacity` and
  `TestSessionsRestartInvalidates`. Assert expiry, logout, random IDs, bounded
  capacity (1024 sessions), and fresh process state. Provide a private fake-clock
  constructor for deterministic tests without sleeps.
- [ ] Write token tests for one-hour default, invalid/over-24-hour TTL, profile
  separation, expiry, revocation, duplicate IDs, hash-only persistence, prefix
  validation, corruption/missing registry failure, concurrent atomic updates,
  and formatting redaction. Cap registry size at 64 KiB and 256 token entries.
- [ ] Run focused tests to confirm failure, implement the interfaces, then run
  `go test -race ./internal/authproxy -run 'TestPassword|TestSessions|TestToken'`.
  Commit after those pass. Use no JWT or homegrown encryption scheme.

## Task 3: Universal request gate and password login

**Files:** Create `gate.go` and `gate_test.go`; use Tasks 1–2 interfaces.

- [ ] Write `TestGateNeverCallsUpstreamWithoutAuth` with a counting handler.
  Table-test all HTTP methods, unknown/static/health/MCP/discovery paths, encoded
  paths, path cleaning, and upgrade requests. Assert backend count stays zero.
- [ ] Write browser tests for 401 login pages, credential submission, login CSRF,
  session fixation, cookie flags, logout CSRF, expiry, state-changing requests
  without/with foreign Origin, and sibling-domain origins. Exact owned auth
  routes are handled locally; unknown `/__otgo/` paths are 404.
- [ ] Write `TestGateCredentialAmbiguity` covering duplicate cookies/headers,
  invalid prefixed bearer plus valid cookie, both machine-token sources, backend
  bearer plus valid cookie, and backend bearer plus valid X-Otgo-Token.
- [ ] Write Host/SNI and resource-bound tests: malformed public Host, mismatched
  locally verified SNI, spoofed forwarding headers, login bodies over 4 KiB,
  bounded login concurrency (two hashes), and a global attempt limiter. Use a
  token bucket of ten attempts with one refill per second; return 429 on excess.
- [ ] Confirm failures, implement `BrowserAuthenticator` for passwords and the
  gate within Handler, then run `go test -race ./internal/authproxy -run TestGate`.
  Commit once the backend-count and cross-site tests pass.

## Task 4: Reverse proxy, streaming, and connection ownership

**Files:** Create `proxy.go`, `proxy_test.go`, and stream/upgrade tests.

- [ ] Write authenticated round-trip tests for bodies/uploads, query/path
  preservation, backend Authorization, unrelated cookies, redirects, and streams.
  Verify fixed backend selection and no server-side following of redirects.
- [ ] Write `TestProxyRemovesGateCredentials` and
  `TestProxyRejectsReservedResponseCookies`, asserting no gate secret reaches the
  backend or status logs. Test duplicate upstream Set-Cookie and spoofed identity/
  forwarding fields. Translate only redirects to the configured backend origin.
- [ ] Write Origin-adaptation tests: a verified same-origin public request works
  against a loopback backend guard; a sibling/foreign request never arrives.
  Reject CONNECT and upgrades other than WebSocket before contacting the backend.
- [ ] Write streaming tests for valid/missing MCP bearer credentials, SSE flushing,
  WebSocket data, credential expiry, logout, registry revocation/corruption, and
  Handler.Close. Assert stream closure within one second of revocation and join
  all worker/hijacked connections without leaking the admission slot.
- [ ] Confirm failures, implement NewHandler/ServeHTTP/Close with ReverseProxy,
  then run `go test -race ./internal/authproxy`. Commit the proxy after passing.

## Task 5: CLI setup and reusable protected proxy

**Files:** Create `cmd/otgo/auth.go`, `cmd/otgo/proxy.go` and tests; update command
dispatch/help in `commands.go`, README, and DESIGN's CLI boundary description.

- [ ] Add failing command tests for `auth init`, `auth paths`, `auth reset`,
  `auth token create/list/revoke`, and `proxy`. Flags follow the command as today.
  Setup accepts upstream and password input; proxy reads the saved configuration.
  Expose --auth-config/--token-file and existing common flags. No password/token
  command-line value flags, --no-auth, or anonymous upstream exceptions.
- [ ] Test that setup explicitly ensures a tunnel and binds it, whereas proxy
  startup only loads the bound identity and refuses missing/mismatched files.
  Restart retains its upstream, password, token registry, and tunnel hostname.
  `auth paths --json` prints paths only. Reset removes known local files, not
  unrelated files, the remote GitHub App, or the tunnel.
- [ ] Test malformed flags, missing auth, unsafe files, captured output redaction,
  cancellation, listener errors, events, and shutdown with active connections.
- [ ] Confirm failures, implement the CLI. Use Client.Listen with the root route,
  http.Server.Serve, a five-second ReadHeaderTimeout and bounded header size.
  Ensure Handler.Close and listener/server teardown run on every failure path.
- [ ] Run `go test -race ./cmd/otgo ./internal/authproxy` and `make check`; commit.
  This milestone is usable password-protected software before GitHub is added.

## Task 6: GitHub browser login

**Files:** Create `github.go`, `github_test.go`; extend auth CLI configuration.

- [ ] Write fake-provider tests for OAuth begin/callback, PKCE verifier binding,
  state/cookie mismatch, replay, expiry, denial, non-approved account, numeric-ID
  matching after username changes, empty allowlist, slow/oversized provider
  responses, unexpected redirects, and errors containing credential-like text.
- [ ] Implement GitHubBrowserAuthenticator using Sessions and the same gate.
  Pending states expire after ten minutes and are capped at 256 entries. Use
  official HTTPS endpoints, a ten-second request timeout, and 64 KiB response
  bounds. Default redirects are rejected; custom providers exist only in tests.
- [ ] Implement explicit manual credential setup using protected input/files,
  resolve allowlisted usernames to IDs, and require successful protected
  persistence before switching the configured mode. No automatic password fallback.
- [ ] Run focused failing tests before implementation, then
  `go test -race ./internal/authproxy ./cmd/otgo`; commit the provider milestone.

## Task 7: Guided GitHub App registration

**Files:** Create `github_setup.go`, its tests, and CLI wizard integration.

- [ ] Write registration tests for manifest values, exact callback, disabled
  webhooks, no repository write permission, owner approval, state mismatch/replay,
  conversion credentials, port/Host/Origin checks, cancellation, timeout,
  duplicate callback, persistence failure, and no forwarding during setup.
- [ ] Implement `RunGitHubSetup(ctx context.Context, paths Paths, binding Binding,
  approvedUsers []string, out io.Writer) error`. Bind a temporary loopback server,
  open/print its non-secret start URL, POST the manifest through the browser, and
  exchange the returned code. Time out the setup after ten minutes. Never invoke
  GitHub registration as a side effect of proxy restart.
- [ ] Save only needed client credentials and allowlisted IDs; discard returned
  app signing key/webhook secret. On partial success report the public management
  URL, not provider bodies, codes, or secrets. Provide manual setup for headless use.
- [ ] Confirm test failure before implementation; run wizard tests under race
  and `make check`, then commit. Actual browser app creation remains GitHub's
  owner approval step; tests use a fake registration provider.

## Task 8: Full verification and operator documentation

**Files:** Update TESTING, VERIFICATION, LIVE_TESTING, SECURITY, README, and
CHANGELOG with implemented behavior and evidence. Add reusable tests/scripts
under `scripts/` only when they materially simplify repeating the live checks.

- [ ] Run `make check`, `make race`, and the existing fuzz targets. Record exact
  tool versions, test results, and limitations; do not claim checks not performed.
- [ ] Run the diagnostic CLI and embedded webapp regression workflows using
  temporary identities. Exercise streaming, WebSockets, forwarding, direct TLS,
  reconnect, cancellation, and cleanup. Verify remote identities are removed.
- [ ] Exercise the new proxy against a purpose-built generic backend through a
  real tunnel. Verify password login/denial, bearer MCP access/denial, all-method
  gating, uploads, redirects, cookies, streams, and revocation. Stop all test
  processes and remove their profiles and auth files afterward.
- [ ] Validate installed Plannotator Inbox in a browser through the gate: login,
  assets, live updates, attachments, and sending a reply on a dedicated test
  thread. Do not alter the user's existing threads or send unsolicited messages.
  Verify denied requests independently. Report any backend compatibility gap.
- [ ] Validate GitHub login with an owner-approved registration, allowlisted and
  denied accounts where available, and reuse after restart. If an interactive
  step is unavailable, document precisely what remains unverified.
- [ ] Obtain an independent security/correctness review, verify actionable
  findings, add regression tests for fixes, and rerun affected/full checks.
- [ ] Replace design/plan mirrors with concise current operator documentation
  after implementation. Review the staged files for credentials and unrelated
  changes, commit and push main under the user's standing authorization, then
  verify the remote commit and CI. Do not publish a new release.
