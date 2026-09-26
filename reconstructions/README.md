# Detector fixtures

Four tiny packages used to test the gate against controlled ground truth, one per technique class.
They are **benign fixtures**, not malware: none contains a payload. The only runtime behaviour any
of them has is one attempted request to `sinkhole.invalid` (a reserved TLD that never resolves) and,
for the control case, writing a marker file. That is enough for the static layer to recognise the
code signature and for the sandbox to record a blocked attempt.

| Package | Class | Real 2026 incident with the same shape | Signature the gate keys on |
|---|---|---|---|
| `@recon/p0-lifecycle` | Install-time (control) | Historical majority; npm v12 blocks it by default | `postinstall` lifecycle script |
| `@recon/p1-import-loader` | Import-time | AsyncAPI, Jul 2026 | outbound request at module scope |
| `@recon/p2-sorted-btree` | Deferred / use-time | indexed-btree, Sep 2026 | outbound request inside a method, in a package that describes itself as pure data-structure code |
| `@recon/p3-optional-helper` | Silent optional dependency | TanStack, May 2026 | optional dependency from a non-registry source + module-scope request on load |

Published to a local Verdaccio registry only (see `../evaluation/publish-reconstructions.sh`), never
to npmjs.com. The testbed's `.npmrc` routes the `@recon` scope to the local registry; every other
dependency still comes from the public registry.
