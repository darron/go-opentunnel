# Homebrew installation and release updates

```sh
brew install darron/tap/otgo
brew test darron/tap/otgo
```

The [personal tap](https://github.com/darron/homebrew-tap) downloads release source
and builds only `./cmd/otgo`. It installs no library source, examples or fixtures.
Go is a build dependency; the CLI includes the packages it needs. `make build`
also builds only the CLI; `make build-example` separately builds the example.

Stable starts at v0.3.0. Auth proxy code is on main until the next release:

```sh
brew install --HEAD darron/tap/otgo
# For updates to an existing HEAD install:
brew upgrade --fetch-HEAD darron/tap/otgo
```

## Automation

Publishing a stable release in `go-opentunnel` triggers
`.github/workflows/update-homebrew.yml`. It validates the published release and
uses a narrowly scoped secret to dispatch the tap's `update-otgo.yml` workflow
on main. There is no cron schedule. Drafts and prereleases do not trigger updates.
A tag push by itself is insufficient: publish the GitHub release.

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

After adding the secret, test the complete hook without creating a release:

```sh
gh workflow run update-homebrew.yml --repo darron/go-opentunnel -f tag=v0.3.0
```

To run the tap directly using your local GitHub login:

```sh
gh workflow run update-otgo.yml --repo darron/homebrew-tap -f tag=v0.3.0
```

Leave the tap workflow's tag empty to select the latest stable release. Drafts and prereleases
are refused. Updates are serialized; non-fast-forward pushes fail instead of
overwriting another change. Rerun after a failure. Actions failures appear in the
tap's Actions tab and do not roll back a release. The source dispatch completing means the tap workflow was started; check its
Actions run for the eventual validation/publishing result.

CI tests invalid/injected tags and checksums, formula slots, symlinks, numeric
version ordering, downgrades, idempotence and preservation of other formulae.
