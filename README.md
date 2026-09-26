# npm-import-gate

A pre-merge CI gate for npm projects, built for the world after npm v12 (8 July 2026) started
blocking lifecycle install scripts by default. Install-time execution used to be the dominant
technique in malicious npm packages. It is now mostly closed, and the attacks that followed run
at import time (AsyncAPI, July 2026) or when a method is called (indexed-btree, September 2026).
This gate looks for those.

Built as the applied project for INFS7008 Systems and Network Security, Western Sydney
University, Spring 2026. Author: Md Nur Islam.

## What it does

```
package-lock.json ──▶ resolve ──▶ static ──▶ dynamic (optional) ──▶ score ──▶ report / exit code
```

1. **resolve**: reads the lockfile (v2/v3), lists every installed package, and checks lockfile
   hygiene: non-registry sources, missing integrity, optional dependencies from odd places,
   declared lifecycle scripts.
2. **static**: parses every JavaScript file of every package into an AST and extracts
   capabilities (process spawn, network, DNS, filesystem writes, credential reads, environment
   enumeration, dynamic code, base64 decoding, known C2 indicators, host fingerprinting,
   obfuscation). Each capability is weighted by **where it sits**: module scope runs the moment
   the package is imported; a method only runs when the application calls it. A capability that
   contradicts the package's own description (a "sorted tree" that spawns processes) weighs more.
3. **dynamic** (`--dynamic`, needs Docker): imports each package inside a container with no
   network, a read-only filesystem, dropped capabilities and Node's permission model, with a
   preload hook that records every attempted spawn, connection, credential read or environment
   dump. Two sensors: the hook records intent; the permission model enforces.
4. **score**: capabilities count once each at their most dangerous occurrence; lockfile findings
   and known combinations (exfiltration, dropper, detached loader, beacon, credential theft) add
   boosts; the score is capped at 100. Fail at 60, warn at 35 by default.
5. **report**: Markdown for humans, JSON for machines, SARIF for GitHub code scanning. Exit code 1
   on fail so the pull request goes red.

## Usage

```bash
npm ci                                   # npm 12: no install scripts run
node src/cli.js scan .                   # Markdown to stdout, static only
node src/cli.js scan . --dynamic         # add the sandbox layer (Docker required)
node src/cli.js scan . --format sarif --out gate.sarif
node src/cli.js scan . --fail 50 --warn 25 --only lodash,express
node src/cli.js rules                    # the rule catalogue as a Markdown table
```

Requires Node 22 or newer. The sandbox uses the `node:24-bookworm-slim` image.

## What it does not claim

- Code that only runs when a specific method is called with a specific argument will not fire in
  the import-time sandbox. The static layer is there for that, and runtime capability enforcement
  (NodeShield, Latch) is the next layer up.
- Provenance attestations prove which pipeline built a package, not that the pipeline was clean.
  This gate scores behaviour regardless of provenance.
- Environment-aware malware can stay dormant in any sandbox.
- Static rules produce false positives on bundlers, native addons and telemetry libraries. The
  evaluation in the report quantifies that.

## Repository layout

```
src/            the gate
test/           node:test unit tests
reconstructions/ benign look-alikes of the three 2026 attack patterns for a local registry
testbed/        a small application the gate is run against in CI
evaluation/     sampling, baselines, metrics
.github/        ci.yml (tests, audit, self-scan) and the pull-request gate workflow
```

## Safety

The evaluation uses real malicious samples from DataDog's public dataset. They are never
extracted on the host outside a scratch directory, never executed outside the no-network
container, and never republished. The reconstructions in `reconstructions/` contain no payload:
they call a sinkholed hostname and write a marker file so that detection can be verified.
