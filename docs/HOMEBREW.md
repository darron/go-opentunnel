# Homebrew installation and release updates

```sh
brew install darron/tap/otgo
brew test darron/tap/otgo
otgo version
```

The [personal tap](https://github.com/darron/homebrew-tap) downloads release source
and builds only `./cmd/otgo`. It installs no library source, examples or fixtures.
Go is a build dependency; the CLI includes the packages it needs. `make build`
also builds only the CLI; `make build-example` separately builds the example.

`otgo version` (or `otgo --version`) reports the binary version,
full Git SHA and source state at build time (`clean`, `dirty` or `unknown`).
Checkout builds read Go's recorded VCS metadata. Stable Homebrew builds use the
release tag's verified commit SHA because source archives contain no `.git`.

For other archive builds, supply that metadata explicitly:

```sh
make build BUILD_REVISION=<full-git-sha> BUILD_STATE=clean
```

An archive build without supplied metadata reports `sha=unknown unknown`.
Recorded VCS metadata takes precedence over supplied values.

Stable releases include the auth proxy. Use HEAD for unreleased changes:

```sh
brew install --HEAD darron/tap/otgo
# For updates to an existing HEAD install:
brew upgrade --fetch-HEAD darron/tap/otgo
```

To replace an existing HEAD installation with stable:

```sh
brew uninstall --formula otgo
brew install darron/tap/otgo
```

This replaces the installed CLI; saved XDG tunnel/auth profiles stay outside the
Homebrew installation directory.

## Automation

Publishing a stable release in `go-opentunnel` triggers
`.github/workflows/update-homebrew.yml`. It validates the published release and
uses a narrowly scoped secret to dispatch the tap's `update-otgo.yml` workflow
on main. There is no cron schedule. Drafts and prereleases do not trigger updates.
A tag push by itself is insufficient: publish the GitHub release.

The separate [binary release workflow](RELEASES.md) attaches downloadable CLI
archives and SHA-256 files. It does not change the tap's source-build procedure.

If release creation is later automated using `GITHUB_TOKEN`, that publishing job
must explicitly dispatch this workflow and `release-binaries.yml` with the release
tag. GitHub suppresses
new workflow runs from most events created with that token, including release
publication; `workflow_dispatch` is an exception. See
[GitHub's workflow trigger rules](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow#triggering-a-workflow-from-a-workflow).

The tap downloads the HTTPS source archive and calculates SHA-256. Only
`Formula/otgo.rb` changes; HEAD/build/test logic is preserved. Older versions are
refused and identical updates are no-ops. A macOS runner installs/tests the
candidate before a fresh runner publishes it using the tap's own `GITHUB_TOKEN`.
Both jobs use the same immutable main commit; other refs are skipped.
dbrain's existing workflow and formula remain unchanged.

### One-time release credential

In `darron/go-opentunnel`, add a **repository Actions secret** named
`HOMEBREW_TAP_TOKEN` at Settings → Secrets and variables → Actions.
Use a fine-grained GitHub PAT with:

- Resource owner: `darron`.
- Repository access: only `darron/homebrew-tap`.
- Repository permission: **Actions — Read and write**.
- Metadata read is automatic; no Contents write, Administration, Secrets or
  Workflows permission is needed.

The token triggers a workflow; it does not push formula changes. GitHub documents
Actions write as the permission for
[workflow dispatch](https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event).
Use an expiry and replace the repository secret when renewing it. Never commit
or paste the token into a source file. Missing/expired credentials fail the release
hook visibly; the release remains published and can be retried.

After adding the secret, retry the complete hook for an already-published release:

```sh
gh workflow run update-homebrew.yml --repo darron/go-opentunnel -f tag=v0.11.0
```

To run the tap directly using your local GitHub login:

```sh
gh workflow run update-otgo.yml --repo darron/homebrew-tap -f tag=v0.11.0
```

The commands above require a published `v0.11.0` release. For another release,
replace the tag. Leave the tap workflow's tag empty to select the latest stable
release. Drafts and prereleases are refused. Updates are serialized; non-fast-forward pushes fail instead of
overwriting another change. Rerun after a failure. Actions failures appear in the
tap's Actions tab and do not roll back a release. A successful source dispatch
means the tap workflow started; check that run for its validation/publishing result.

CI tests invalid/injected tags and checksums, formula slots, symlinks, numeric
version ordering, downgrades, idempotence and preservation of other formulae.
