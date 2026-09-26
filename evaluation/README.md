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

1. **Get the malicious set.** Clone DataDog's public dataset (Apache-2.0):
   ```bash
   git clone https://github.com/DataDog/malicious-software-packages-dataset dataset
   ```
   The npm samples live under `dataset/samples/npm/` as encrypted zips (password `infected`) with a
   `manifest.json`. They are real malware: never extract or run them outside the steps below.

2. **Sample and extract.** `sample-dataset.mjs` reads the manifest, takes a stratified sample by
   discovery date, and extracts each selected zip into `results/work/malicious/<name>/` using the
   dataset password. Extraction only unzips the tree; nothing is executed.
   ```bash
   node evaluation/sample-dataset.mjs --dataset ./dataset --count 150
   ```

3. **Build the benign set.** `fetch-benign.mjs` downloads the top-N npm packages by weekly downloads
   at pinned versions into `results/work/benign/`.
   ```bash
   node evaluation/fetch-benign.mjs --count 100
   ```

4. **Run the gate over everything and label from the manifest.**
   ```bash
   node evaluation/run-evaluation.mjs --dynamic   # omit --dynamic for static-only
   ```
   Writes `results/gate-results.csv` (one row per package) and prints the metrics.

5. **Baselines.** `run-baselines.mjs` runs `npm audit`, install-script-blocking-only, and GuardDog
   over the same sets, writing `results/baselines.csv`.
   ```bash
   node evaluation/run-baselines.mjs
   ```

6. **Metrics and tables.** `metrics.mjs` turns the CSVs into the precision/recall/F1 tables and the
   per-technique breakdown used in the report.
   ```bash
   node evaluation/metrics.mjs
   ```

## Safe handling (state this in the report, §3.6)

- Samples are handled only inside `results/work/`, which is git-ignored.
- The static layer parses files; it never executes them.
- The dynamic layer runs each sample only inside the Docker sandbox: no network, read-only root,
  dropped capabilities, Node permission model, CPU/memory/pids limits.
- Nothing is ever re-published. The reconstructions in `../reconstructions/` are benign and contain
  no payload.
- This mirrors the dataset's own warning: "This repository contains actively malicious software ...
  Do not run it on your machine."
