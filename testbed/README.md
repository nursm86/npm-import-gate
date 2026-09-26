# gate-testbed

A small Express service used as a realistic project for the gate to scan. It depends on real public
packages (`express`, `helmet`) and, in the compromised variant, on the local `@recon` reconstruction
fixtures. Two lockfiles are used in the evaluation:

- **clean**: only `express` and `helmet`. The gate passes.
- **compromised**: adds one or more `@recon/*` fixtures. The gate fails, and in CI the pull request
  goes red.

Install the clean variant with `npm ci` after the local registry is running (see
`../evaluation/publish-reconstructions.sh`). The `.npmrc` routes only the `@recon` scope to the
local registry.
