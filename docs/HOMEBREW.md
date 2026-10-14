# Homebrew installation and release updates

```sh
brew install darron/tap/otgo
brew test darron/tap/otgo
otgo version
```

The [personal tap](https://github.com/darron/homebrew-tap) installs the exact
compiled executable attached to the GitHub release. It selects macOS or Linux
and arm64 or amd64, verifies the archive's SHA-256, and installs `otgo`. Go is
not required, and no source compilation takes place. Homebrew cleanup is skipped
for the executable so its bytes match the release download.

`otgo version` reports the version, full release commit SHA and `clean`.
Existing installations upgrade normally:

```sh
brew update
brew upgrade otgo
```

Source-based `--HEAD` installation is no longer offered. To replace an existing
HEAD installation, uninstall the CLI and install stable:

```sh
brew uninstall --formula otgo
brew install darron/tap/otgo
```

Saved XDG tunnel/auth profiles remain outside Homebrew's installation directory.
For development, use `make build` in a checkout; it builds only `./cmd/otgo`.
`make build-example` separately builds the example. Checkout builds use Go's VCS
metadata. For a manual source-archive build, supply the metadata explicitly:

```sh
make build BUILD_REVISION=<full-git-sha> BUILD_STATE=clean
```

Without VCS or supplied metadata, an archive build reports `sha=unknown unknown`.

## Automation

Publishing a stable GitHub release starts `release-binaries.yml`. After its
build, native smoke checks and asset publication succeed, it calls
`update-homebrew.yml`, which dispatches the tap's `update-otgo.yml` workflow.
There is no cron schedule. Drafts and prereleases are skipped; pushing a tag
alone does not publish binaries or update the tap.

The tap downloads all four published archives, their individual SHA-256 files
and `SHA256SUMS`. It verifies every hash before generating `Formula/otgo.rb`.
Missing assets, invalid metadata, corrupt checksums and downgrades fail before
publication. Identical updates leave the formula unchanged.

A macOS runner checks formula syntax/style, audits it, installs it and runs its
tests. It compares the installed executable with the extracted release binary
using `cmp`. A fresh runner then regenerates the formula, verifies its hash
matches the validated candidate, and publishes only `Formula/otgo.rb`. No release
executable runs with publication credentials. Both jobs use the same immutable
tap automation commit; other refs are skipped. dbrain's formula and workflows
are unchanged.

For automation that publishes using `GITHUB_TOKEN`, explicitly dispatch the
binary workflow after release creation:

```sh
gh workflow run release-binaries.yml --repo darron/go-opentunnel --ref main \
  -f tag=v0.12.0 -f update_homebrew=true
```

GitHub suppresses most further events created with that token, including release
publication; `workflow_dispatch` is an exception. See
[GitHub's workflow trigger rules](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow#triggering-a-workflow-from-a-workflow).

### Release credential

The `go-opentunnel` repository Actions secret **`HOMEBREW_TAP_TOKEN`** is a
fine-grained GitHub PAT with:

- Resource owner: `darron`.
- Repository access: only `darron/homebrew-tap`.
- Repository permission: **Actions — Read and write**.
- Automatic Metadata read; no Contents write, Administration, Secrets or
  Workflows permission is needed.

It dispatches the workflow; the tap's own `GITHUB_TOKEN` publishes the formula.
GitHub documents Actions write for
[workflow dispatch](https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event).
Use an expiry and replace the secret when renewing it. Missing/expired credentials
fail visibly; published release assets remain available.

### Retry

Once all release assets are published, retry the tap hook:

```sh
gh workflow run update-homebrew.yml --repo darron/go-opentunnel --ref main \
  -f tag=v0.12.0
```

Or dispatch the tap directly with your local GitHub login:

```sh
gh workflow run update-otgo.yml --repo darron/homebrew-tap --ref main \
  -f tag=v0.12.0
```

Use the desired published tag; leave the tap's tag empty to select the latest
stable release. Updates are serialized, and non-fast-forward pushes fail instead
of overwriting another change. A successful dispatch means the tap workflow
started; check that run's final validation/publication result.

CI checks asset corruption, missing/extra files, formula migration and target
selection, symlinks, version ordering, downgrades, idempotence and preservation of
other formulae. The release guide covers [binary backfills](RELEASES.md#retry-or-backfill-assets).
