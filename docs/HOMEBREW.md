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
# For an existing install:
brew reinstall --HEAD darron/tap/otgo
```

## Automation

The tap's `.github/workflows/update-otgo.yml` checks the latest published stable
release hourly and supports a manual trigger. It validates the tag/release,
downloads the HTTPS source archive and calculates SHA-256. Only `Formula/otgo.rb`
changes; its HEAD/build/test logic is preserved. Older versions are refused and
identical updates are no-ops. Scheduled unchanged releases skip the build.

A macOS runner installs/tests each changed candidate before pushing it to tap
main. Manual runs validate even an unchanged formula. The workflow uses the tap's
own `GITHUB_TOKEN`; no personal token or additional secret is required. Validation
runs with read-only permissions. A separate fresh runner recreates the validated
formula change using tap-owned code and receives write permission only for
publishing. dbrain's existing workflow and formula remain unchanged.

Run a validation/update without publishing another release:

```sh
gh workflow run update-otgo.yml --repo darron/homebrew-tap -f tag=v0.3.0
```

Leave the tag empty to select the latest stable release. Drafts and prereleases
are refused. Updates are serialized; non-fast-forward pushes fail instead of
overwriting another change. Rerun after a failure. Actions failures appear in the
tap's Actions tab and do not roll back a release. GitHub may disable schedules on
inactive public repositories; re-enable the workflow there if needed.

CI tests invalid/injected tags and checksums, formula slots, symlinks, numeric
version ordering, downgrades, idempotence and preservation of other formulae.
