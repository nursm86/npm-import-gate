// Turns gate-results.csv (and baselines.csv if present) into the numbers the report cites.
// Writes 04-evidence/results/NUMBERS.md (markdown tables, the single source of truth for §4)
// and numbers.json (the same figures for the chart script), and copies the CSVs alongside.
//   node evaluation/metrics.mjs
import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { DEFAULT_THRESHOLDS } from '../src/config/constants.js';
import { asPercent, evaluate, recallByTechnique } from './lib/metrics.mjs';
import { BASELINES_CSV, EVIDENCE_RESULTS_DIR, GATE_RESULTS_CSV, NPM12_GA_DATE, parseCsv, parseFlags, toBool, toNum } from './lib/work.mjs';

const SWEEP_THRESHOLDS = [20, 25, 30, 35, 40, 45, 50, 55, 60, 65, 70, 75, 80, 90];
const pct = (value) => asPercent(Number.isFinite(value) ? value : 0);
const mean = (values) => (values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : 0);
const median = (values) => {
  if (!values.length) return 0;
  const sorted = [...values].sort((left, right) => left - right);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
};

function metricRow(label, rows) {
  const result = evaluate(rows);
  return `| ${label} | ${rows.filter((row) => row.isMalicious).length} | ${rows.filter((row) => !row.isMalicious).length} | `
    + `${pct(result.precision)} | ${pct(result.recall)} | ${pct(result.f1)} | ${pct(result.falsePositiveRate)} | ${result.tp} | ${result.fp} | ${result.fn} | ${result.tn} |`;
}

const METRIC_HEADER = '| Configuration | Malicious | Benign | Precision | Recall | F1 | FP rate | TP | FP | FN | TN |\n|---|---|---|---|---|---|---|---|---|---|---|';

async function main() {
  const flags = parseFlags(process.argv.slice(2));
  const csvPath = typeof flags.csv === 'string' ? path.resolve(flags.csv) : GATE_RESULTS_CSV;
  const tag = typeof flags.tag === 'string' ? `-${flags.tag}` : '';
  const rows = parseCsv(await readFile(csvPath, 'utf8'))
    .filter((row) => row.verdict !== 'error' && row.score !== '')
    .map((row) => ({
      ...row,
      isMalicious: toBool(row.isMalicious),
      postGa: toBool(row.postGa),
      hasInstallScript: toBool(row.hasInstallScript),
      staticScore: toNum(row.staticScore),
      dynamicDelta: toNum(row.dynamicDelta),
      score: toNum(row.score),
      seconds: toNum(row.seconds),
      flagged: toBool(row.flagged),
    }));
  const dataset = rows.filter((row) => row.set !== 'reconstruction');
  const malicious = dataset.filter((row) => row.isMalicious);
  const benign = dataset.filter((row) => !row.isMalicious);
  const reconstructions = rows.filter((row) => row.set === 'reconstruction');
  const dynamicRan = rows.some((row) => row.dynamicOutcome && row.dynamicOutcome !== '');
  const { fail, warn } = DEFAULT_THRESHOLDS;

  const withFlag = (items, predicate) => items.map((row) => ({ ...row, flagged: predicate(row) }));
  const combinedWarn = withFlag(dataset, (row) => row.score >= warn);
  const combinedFail = withFlag(dataset, (row) => row.score >= fail);
  const staticWarn = withFlag(dataset, (row) => row.staticScore >= warn);
  const staticFail = withFlag(dataset, (row) => row.staticScore >= fail);
  const installOnly = withFlag(dataset, (row) => row.hasInstallScript);

  const out = [];
  out.push(`# NUMBERS${tag}.md: evaluation results (single source of truth for §4)`, '');
  out.push(`Generated ${new Date().toISOString()} from \`${path.basename(csvPath)}\`. `
    + `Thresholds: warn ≥ ${warn}, fail ≥ ${fail}. Dynamic layer ${dynamicRan ? 'ran' : 'did not run'}.`, '');
  out.push(`Sample: ${malicious.length} malicious (${malicious.filter((row) => row.postGa).length} published on or after npm v12 GA ${NPM12_GA_DATE}; `
    + `${malicious.filter((row) => row.category === 'compromised_lib').length} compromised libraries, `
    + `${malicious.filter((row) => row.category === 'malicious_intent').length} malicious-intent), ${benign.length} benign, ${reconstructions.length} reconstructions.`, '');

  out.push('## Table 5 source: detection by configuration (dataset sample only)', '', METRIC_HEADER);
  out.push(metricRow('Gate, static only, flag = warn or fail', staticWarn));
  out.push(metricRow('Gate, static only, flag = fail', staticFail));
  if (dynamicRan) {
    out.push(metricRow('Gate, static + dynamic, flag = warn or fail', combinedWarn));
    out.push(metricRow('Gate, static + dynamic, flag = fail', combinedFail));
  }
  out.push(metricRow('Install-script blocking alone (npm v12 default)', installOnly));
  out.push(metricRow('npm audit (advisory-based; flags nothing on fresh malware)', withFlag(dataset, () => false)));
  try {
    const baselines = parseCsv(await readFile(BASELINES_CSV, 'utf8'));
    const guarddog = baselines.filter((row) => row.guarddog !== '');
    if (guarddog.length) {
      out.push(metricRow('GuardDog (static rules)', guarddog.map((row) => ({ isMalicious: toBool(row.isMalicious), flagged: toBool(row.guarddog) }))));
    }
  } catch { /* baselines optional */ }
  out.push('');

  out.push('## Table 4 source: detected malicious samples by technique class (gate classification)', '');
  out.push('| Technique class (as classified by the gate) | Count | Share of malicious sample |', '|---|---|---|');
  for (const bucket of recallByTechnique(combinedWarn.filter((row) => row.isMalicious).map((row) => ({ ...row, technique: row.flagged ? row.technique : 'undetected' })))) {
    out.push(`| ${bucket.technique} | ${bucket.total} | ${pct(bucket.total / Math.max(1, malicious.length))} |`);
  }
  out.push('');

  out.push('## Install-script reliance before and after npm v12 GA (the paper\'s own measurement)', '');
  out.push('| Period | Malicious samples | Declare a lifecycle script | Share | Gate recall (warn or fail) |', '|---|---|---|---|---|');
  for (const [label, subset] of [['Before 2026-07-08', malicious.filter((row) => !row.postGa)], ['On or after 2026-07-08', malicious.filter((row) => row.postGa)], ['All', malicious]]) {
    const scripted = subset.filter((row) => row.hasInstallScript).length;
    const detected = subset.filter((row) => row.score >= warn).length;
    out.push(`| ${label} | ${subset.length} | ${scripted} | ${pct(scripted / Math.max(1, subset.length))} | ${pct(detected / Math.max(1, subset.length))} |`);
  }
  out.push('', 'Compare with Guo et al. 2026: 72.21% of 6,420 malicious npm packages exploited install scripts.', '');

  out.push('## Layer contribution (malicious dataset sample)', '');
  const staticHit = malicious.filter((row) => row.staticScore >= warn).length;
  const combinedHit = malicious.filter((row) => row.score >= warn).length;
  const dynamicOnlyHit = malicious.filter((row) => row.staticScore < warn && row.score >= warn).length;
  const dynamicObserved = malicious.filter((row) => row.dynamicDelta > 0).length;
  out.push(`- Static layer alone flags ${staticHit}/${malicious.length} (${pct(staticHit / Math.max(1, malicious.length))}).`);
  if (dynamicRan) {
    out.push(`- Dynamic layer observed behaviour in ${dynamicObserved}/${malicious.length} (${pct(dynamicObserved / Math.max(1, malicious.length))}); `
      + `it added ${dynamicOnlyHit} detections the static layer missed; combined ${combinedHit}/${malicious.length} (${pct(combinedHit / Math.max(1, malicious.length))}).`);
    const outcomes = new Map();
    for (const row of dataset) outcomes.set(row.dynamicOutcome || 'n/a', (outcomes.get(row.dynamicOutcome || 'n/a') ?? 0) + 1);
    out.push(`- Sandbox outcomes: ${[...outcomes.entries()].map(([key, value]) => `${key} ${value}`).join(', ')}.`);
  }
  out.push('');

  out.push('## Table 6 source: benign false positives', '');
  const benignFlagged = benign.filter((row) => row.score >= warn);
  const benignFailed = benign.filter((row) => row.score >= fail);
  out.push(`${benignFlagged.length}/${benign.length} benign packages reached warn (${pct(benignFlagged.length / Math.max(1, benign.length))}); `
    + `${benignFailed.length} reached fail (${pct(benignFailed.length / Math.max(1, benign.length))}).`, '');
  out.push('| Benign package | Category | Score | Verdict | Top contributing rule | Install script? |', '|---|---|---|---|---|---|');
  for (const row of [...benignFlagged].sort((left, right) => right.score - left.score)) {
    out.push(`| ${row.name} | ${row.category} | ${row.score} | ${row.verdict} | ${row.topRule} | ${row.hasInstallScript ? 'yes' : 'no'} |`);
  }
  out.push('', '| Category | Benign packages | Warn or fail | Share |', '|---|---|---|---|');
  const categories = [...new Set(benign.map((row) => row.category))].sort();
  for (const category of categories) {
    const subset = benign.filter((row) => row.category === category);
    const flagged = subset.filter((row) => row.score >= warn).length;
    out.push(`| ${category} | ${subset.length} | ${flagged} | ${pct(flagged / Math.max(1, subset.length))} |`);
  }
  out.push('', '| Top rule among benign false positives | Count |', '|---|---|');
  const ruleCounts = new Map();
  for (const row of benignFlagged) ruleCounts.set(row.topRule, (ruleCounts.get(row.topRule) ?? 0) + 1);
  for (const [rule, count] of [...ruleCounts.entries()].sort((left, right) => right[1] - left[1])) out.push(`| ${rule} | ${count} |`);
  out.push('');

  out.push('## Table 7 source: cost', '');
  const secondsOf = (items) => items.map((row) => row.seconds).filter(Number.isFinite);
  out.push('| Set | Packages | Mean s/package | Median s/package | Total s |', '|---|---|---|---|---|');
  for (const [label, subset] of [['Malicious', malicious], ['Benign', benign], ['All dataset', dataset]]) {
    const seconds = secondsOf(subset);
    out.push(`| ${label}${dynamicRan ? ' (static + dynamic)' : ' (static)'} | ${subset.length} | ${mean(seconds).toFixed(2)} | ${median(seconds).toFixed(2)} | ${seconds.reduce((sum, value) => sum + value, 0).toFixed(0)} |`);
  }
  out.push('');

  out.push('## Figure 7 source: threshold sweep (fail threshold; flag = score ≥ t; dataset sample)', '');
  out.push('| t | Precision | Recall | F1 | FP rate |', '|---|---|---|---|---|');
  const sweep = [];
  for (const threshold of SWEEP_THRESHOLDS) {
    const result = evaluate(withFlag(dataset, (row) => row.score >= threshold));
    sweep.push({ threshold, ...result });
    out.push(`| ${threshold} | ${pct(result.precision)} | ${pct(result.recall)} | ${pct(result.f1)} | ${pct(result.falsePositiveRate)} |`);
  }
  out.push('');

  out.push('## Reconstructions (labelled ground truth, one per technique class)', '');
  out.push('| Fixture | Truth | Static score | Dynamic delta | Score | Verdict | Gate classification | Patterns |', '|---|---|---|---|---|---|---|---|');
  for (const row of reconstructions) {
    out.push(`| ${row.name} | ${row.truth} | ${row.staticScore} | ${row.dynamicDelta} | ${row.score} | ${row.verdict} | ${row.technique} | ${row.patterns.replaceAll('|', ', ')} |`);
  }
  out.push('');

  out.push('## Score distribution (malicious vs benign)', '');
  out.push('| Band | Malicious | Benign |', '|---|---|---|');
  for (const [low, high] of [[0, 19], [20, 34], [35, 59], [60, 79], [80, 100]]) {
    const inBand = (row) => row.score >= low && row.score <= high;
    out.push(`| ${low}–${high} | ${malicious.filter(inBand).length} | ${benign.filter(inBand).length} |`);
  }
  out.push('');

  await mkdir(EVIDENCE_RESULTS_DIR, { recursive: true });
  await writeFile(path.join(EVIDENCE_RESULTS_DIR, `NUMBERS${tag}.md`), `${out.join('\n')}\n`);
  const technique = recallByTechnique(combinedWarn.filter((row) => row.isMalicious).map((row) => ({ ...row, technique: row.flagged ? row.technique : 'undetected' })));
  await writeFile(path.join(EVIDENCE_RESULTS_DIR, `numbers${tag}.json`), `${JSON.stringify({
    generatedAt: new Date().toISOString(), thresholds: DEFAULT_THRESHOLDS, dynamicRan,
    counts: { malicious: malicious.length, benign: benign.length, reconstructions: reconstructions.length },
    staticOnly: { warn: evaluate(staticWarn), fail: evaluate(staticFail) },
    combined: { warn: evaluate(combinedWarn), fail: evaluate(combinedFail) },
    installScriptOnly: evaluate(installOnly),
    technique, sweep,
    layers: { staticHit, combinedHit, dynamicOnlyHit, dynamicObserved },
    reconstructions,
  }, null, 2)}\n`);
  await copyFile(csvPath, path.join(EVIDENCE_RESULTS_DIR, `gate-results${tag}.csv`));
  try { await copyFile(BASELINES_CSV, path.join(EVIDENCE_RESULTS_DIR, 'baselines.csv')); } catch { /* optional */ }
  process.stdout.write(`Wrote ${path.join(EVIDENCE_RESULTS_DIR, `NUMBERS${tag}.md`)} and numbers${tag}.json\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exit(1);
});
