// Runs the gate over every extracted package under results/work/{malicious,benign}, labels each
// from its folder, writes results/gate-results.csv, and prints the metrics. Static by default;
// pass --dynamic to add the sandbox layer (Docker). Each work folder holds one package per
// subdirectory (a package.json plus its files), which is the layout produced by sample-dataset.mjs
// and fetch-benign.mjs.
import { mkdir, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { DEFAULT_THRESHOLDS } from '../src/config/constants.js';
import { analyzePackageDirectory } from '../src/static/analyze-package.js';
import { scorePackage } from '../src/static/scoring.js';
import { verdictFor } from '../src/score/aggregate.js';
import { runDynamicAnalysis } from '../src/dynamic/sandbox.js';
import { classifyResult } from './lib/classify.mjs';
import { evaluate, recallByTechnique, asPercent } from './lib/metrics.mjs';
import { BENIGN_DIR, MALICIOUS_DIR, RESULTS_DIR, parseFlags, toCsv } from './lib/work.mjs';

async function packageDirs(root) {
  try {
    const entries = await readdir(root, { withFileTypes: true });
    return entries.filter((entry) => entry.isDirectory()).map((entry) => path.join(root, entry.name));
  } catch {
    return [];
  }
}

async function scanPackage(dir, { dynamic }) {
  const analysis = await analyzePackageDirectory(dir);
  const scored = scorePackage(analysis.findings, [], analysis.purpose);
  let dynamicOutcome = null;
  if (dynamic) {
    const result = await runDynamicAnalysis({ name: path.basename(dir), dir }, analysis.manifest);
    scored.score = Math.min(100, scored.score + result.scoreDelta);
    scored.patterns.push(...result.patterns);
    dynamicOutcome = result.outcome;
  }
  const verdict = verdictFor(scored.score);
  return {
    result: { patterns: [...new Set(scored.patterns)], findings: analysis.findings, lockfileFindings: [] },
    score: scored.score,
    verdict,
    flagged: verdict !== 'pass',
    dynamicOutcome,
  };
}

async function main() {
  const flags = parseFlags(process.argv.slice(2));
  const dynamic = Boolean(flags.dynamic);
  const failOnly = Boolean(flags['fail-only']);

  const malicious = await packageDirs(MALICIOUS_DIR);
  const benign = await packageDirs(BENIGN_DIR);
  if (malicious.length + benign.length === 0) {
    process.stderr.write(`No packages under ${MALICIOUS_DIR} or ${BENIGN_DIR}.\n`
      + 'Run sample-dataset.mjs and fetch-benign.mjs first (see evaluation/README.md).\n');
    process.exit(1);
  }
  process.stdout.write(`Scanning ${malicious.length} malicious and ${benign.length} benign packages`
    + `${dynamic ? ' with the dynamic layer' : ' (static only)'}...\n`);

  const rows = [];
  for (const [isMalicious, dirs] of [[true, malicious], [false, benign]]) {
    for (const dir of dirs) {
      const scan = await scanPackage(dir, { dynamic });
      const flagged = failOnly ? scan.verdict === 'fail' : scan.flagged;
      rows.push({
        name: path.basename(dir),
        isMalicious,
        flagged,
        score: scan.score,
        verdict: scan.verdict,
        technique: isMalicious ? (flagged ? classifyResult(scan.result) : 'undetected') : 'n/a',
        dynamicOutcome: scan.dynamicOutcome ?? '',
      });
    }
  }

  await mkdir(RESULTS_DIR, { recursive: true });
  await writeFile(path.join(RESULTS_DIR, 'gate-results.csv'), toCsv(rows), 'utf8');

  const overall = evaluate(rows);
  process.stdout.write('\n=== gate (combined) ===\n');
  process.stdout.write(`precision ${asPercent(overall.precision)}  recall ${asPercent(overall.recall)}  `
    + `F1 ${asPercent(overall.f1)}  FP rate ${asPercent(overall.falsePositiveRate)}\n`);
  process.stdout.write(`tp ${overall.tp}  fp ${overall.fp}  tn ${overall.tn}  fn ${overall.fn}\n`);

  process.stdout.write('\n=== detected malicious samples by technique class (gate classification) ===\n');
  for (const bucket of recallByTechnique(rows)) {
    process.stdout.write(`${bucket.technique.padEnd(18)} ${bucket.detected}/${bucket.total} (${asPercent(bucket.recall)})\n`);
  }
  process.stdout.write(`\nThresholds: fail ${DEFAULT_THRESHOLDS.fail}, warn ${DEFAULT_THRESHOLDS.warn}. `
    + `Detection = verdict ${failOnly ? "'fail'" : "'warn' or 'fail'"}.\n`);
  process.stdout.write(`Rows written to ${path.join(RESULTS_DIR, 'gate-results.csv')}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exit(1);
});
