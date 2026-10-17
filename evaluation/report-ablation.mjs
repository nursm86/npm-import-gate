// Builds the cumulative-ablation table (what each rule change bought) from one results CSV per
// step. Each step is "<label>::<change>::<csv>"; the CSVs come from run-evaluation.mjs runs made
// with the relevant constants in src/config/constants.js switched off (see 04-evidence/results/
// ABLATION-static.md for the exact constant per step). Static scores only, so the table does not
// depend on the sandbox.
//
//   node evaluation/report-ablation.mjs --out ../04-evidence/results/ABLATION-static.md \
//     "v0.1::first measured pass::evaluation/results/gate-results-static.csv" \
//     "v0.2::rules as shipped::evaluation/results/gate-results-static-v02.csv"
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { DEFAULT_THRESHOLDS } from '../src/config/constants.js';
import { asPercent, evaluate } from './lib/metrics.mjs';
import { parseCsv, parseFlags, toBool, toNum } from './lib/work.mjs';

const STEP_SEPARATOR = '::';
const TABLE_HEADER = '| Step | Rule change (cumulative) | Precision | Recall | F1 | FP rate | TP | FP |\n|---|---|---|---|---|---|---|---|';

async function datasetRows(csvPath) {
  return parseCsv(await readFile(csvPath, 'utf8'))
    .filter((row) => row.set !== 'reconstruction' && row.score !== '')
    .map((row) => ({ isMalicious: toBool(row.isMalicious), staticScore: toNum(row.staticScore) }));
}

function tableRow(step, change, rows, threshold) {
  const result = evaluate(rows.map((row) => ({ ...row, flagged: row.staticScore >= threshold })));
  return `| ${step} | ${change} | ${asPercent(result.precision)} | ${asPercent(result.recall)} | ${asPercent(result.f1)} | `
    + `${asPercent(result.falsePositiveRate)} | ${result.tp} | ${result.fp} |`;
}

async function main() {
  const argv = process.argv.slice(2);
  const flags = parseFlags(argv);
  const steps = argv.filter((arg) => arg.includes(STEP_SEPARATOR)).map((spec) => {
    const [step, change, csv] = spec.split(STEP_SEPARATOR);
    return { step, change, csv: path.resolve(csv) };
  });
  if (steps.length === 0 || typeof flags.out !== 'string') {
    throw new Error('usage: report-ablation.mjs --out <markdown> "<step>::<change>::<csv>" ...');
  }
  const { warn, fail } = DEFAULT_THRESHOLDS;
  const warnRows = [];
  const failRows = [];
  for (const { step, change, csv } of steps) {
    const rows = await datasetRows(csv);
    warnRows.push(tableRow(step, change, rows, warn));
    failRows.push(tableRow(step, change, rows, fail));
  }
  const out = [
    '# ABLATION-static.md: what each rule change bought (static layer, same sample)', '',
    `Generated ${new Date().toISOString()}. Each step adds one change to the previous row; the last row is the rule set as shipped. `
      + `Static scores only, thresholds warn ≥ ${warn}, fail ≥ ${fail}.`, '',
    `## Flag = warn or fail (score ≥ ${warn})`, '', TABLE_HEADER, ...warnRows, '',
    `## Flag = fail only (score ≥ ${fail})`, '', TABLE_HEADER, ...failRows, '',
  ].join('\n');
  await writeFile(path.resolve(flags.out), `${out}\n`);
  process.stdout.write(`Wrote ${path.resolve(flags.out)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
});
