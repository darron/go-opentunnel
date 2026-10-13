# Upstream protocol vectors

The original four JSON files (`control`, `frames`, `names`, `routes`) are copied from [OpenTunnel shared vectors](https://github.com/anomalyco/opentunnel/tree/22156aa6ab209515186c3ca4f111901b7cedc284/spec/vectors).

- Source commit: `22156aa6ab209515186c3ca4f111901b7cedc284`.
- Copy date: 2026-10-09.
- License: upstream MIT; the original notice is in [MIT-LICENSE](MIT-LICENSE).

`proxy.json` is copied from upstream tag v0.5.0, commit
`bb81367416c78834e09bca569267cbbae50781fb`, on 2026-10-10:
[PROXY vectors](https://github.com/anomalyco/opentunnel/blob/bb81367416c78834e09bca569267cbbae50781fb/spec/vectors/proxy.json).
The same upstream MIT notice applies. The original four vector sets were compared
with that tag and their decoded JSON content was unchanged.

`api-retry.json` is copied on 2026-10-13 from commit
`0cad49c74303bfdb2c0495e9c58fd1bdb9d619db`:
[API retry vectors](https://github.com/anomalyco/opentunnel/blob/0cad49c74303bfdb2c0495e9c58fd1bdb9d619db/spec/vectors/api-retry.json).
The same upstream MIT notice applies. Tests verify retry statuses, delay bounds,
limits and fixed Cloudflare messages. Raw-body message vectors are intentionally
not adopted: the Go client redacts untrusted error bodies.
