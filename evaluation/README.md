# Evaluation

Produces the numbers behind §4 of the report: detection rate per technique class, false-positive
rate on benign packages, and a comparison against the baselines. Everything writes to
`results/` (git-ignored except `.gitkeep`).

## Quick checks (no dataset needed)

```bash
npm run verify:detection   # static layer catches P0-P3, clears a benign package
npm run verify:sandbox     # dynamic layer sees P1 import-time, misses P2 deferred (Docker)
```

These prove the gate works and produce the reconstruction column of Table 4.

## Full evaluation (needs the DataDog dataset)

The dataset is 33 GB; the sampler fetches only the zips it selects (about 400 MB for 150) through a
blobless partial clone and a sparse checkout. Needs git 2.25+, unzip and about 1 GB of disk.

1. **Sample and extract the malicious set.** `sample-dataset.mjs` clones the index of DataDog's
   public dataset (Apache-2.0), lists the npm zips, takes a seeded sample stratified by month with a
   quota of samples published on or after the npm v12 GA date, fetches only those zips and unzips
   them (password `infected`) into `results/work/malicious/<id>_<category>_<name>@<version>/`.
   Extraction only unzips; nothing is executed.
   ```bash
   node evaluation/sample-dataset.mjs --count 150 --post-ga 60 --min-compromised 15 --seed 42
   ```
   Writes `results/work/malicious/malicious-manifest.json` (name, version, category, date).

2. **Build the benign set.** `fetch-benign.mjs` downloads the latest tarball of a curated,
   category-tagged list of 100 widely used packages into `results/work/benign/`.
   ```bash
   node evaluation/fetch-benign.mjs
   ```

3. **Run the gate over everything.** One CSV row per package, appended as it finishes, so an
   interrupted run leaves usable data (`--resume` continues it). Loose package directories have no
   lockfile, so the only lockfile signal the harness reconstructs is the declared lifecycle script.
   ```bash
   node evaluation/run-evaluation.mjs --out evaluation/results/gate-results-static.csv   # static only, ~7 s
   node evaluation/run-evaluation.mjs --dynamic --out evaluation/results/gate-results.csv # + sandbox, ~10 min
   ```

4. **Baselines.** Install-script blocking alone, GuardDog (`uvx guarddog npm scan <dir>`, local
   scans, threat-rule and any-rule readings, raw JSON kept in `results/work/guarddog/`) and npm
   audit, over the same directories.
   ```bash
   node evaluation/run-baselines.mjs
   ```

5. **Metrics.** Turns a results CSV (and `baselines.csv` if present) into the tables the report
   cites, written to `../04-evidence/results/NUMBERS[-tag].md` and `numbers[-tag].json`.
   ```bash
   node evaluation/metrics.mjs                                    # final: gate-results.csv
   node evaluation/metrics.mjs --csv evaluation/results/gate-results-static.csv --tag static
   ```

6. **Explain the misses and the rule iterations.**
   ```bash
   node evaluation/explain-misses.mjs --csv evaluation/results/gate-results.csv --out ../04-evidence/results/misses.md
   node evaluation/report-ablation.mjs --out ../04-evidence/results/ABLATION-static.md \
     "v0.1::first measured pass::evaluation/results/gate-results-static.csv" \
     "v0.2::rules as shipped::evaluation/results/gate-results-static-v02.csv"
   ```
   Each ablation step is a static run made with one constant in `src/config/constants.js` switched
   off (tiny-package boost 0, tool discount multiplier 1, inferred-tool discount false); the
   per-step CSVs and the constant used are recorded next to the table in `04-evidence/results/`.

Quick checks that do not need the dataset: `node evaluation/verify-detection.mjs` (static layer,
P0–P3 and a benign control) and `node evaluation/verify-sandbox.mjs` (dynamic layer, Docker).

## Safe handling (state this in the report, §3.6)

- Samples are handled only inside `results/work/`, which is git-ignored.
- The static layer parses files; it never executes them.
- The dynamic layer runs each sample only inside the Docker sandbox: no network, read-only root,
  dropped capabilities, Node permission model, CPU/memory/pids limits.
- Nothing is ever re-published. The reconstructions in `../reconstructions/` are benign and contain
  no payload.
- This mirrors the dataset's own warning: "This repository contains actively malicious software ...
  Do not run it on your machine."
