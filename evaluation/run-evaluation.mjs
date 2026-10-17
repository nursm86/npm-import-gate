// Runs the gate over the malicious sample, the benign set and the four reconstruction fixtures,
// appending one CSV row per package as it finishes so a time-boxed or interrupted run leaves
// usable data. Static by default; --dynamic adds the Docker sandbox. --resume skips packages
// already in the CSV; --limit N stops after N new packages.
//
//   node evaluation/run-evaluation.mjs [--dynamic] [--resume] [--limit N] [--set malicious|benign|reconstruction]
//
// Loose package directories have no lockfile, so the one lockfile signal the real gate would
// have (a declared lifecycle script) is reconstructed from package.json so scoring matches.
import { appendFile, mkdir, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { DEFAULT_THRESHOLDS, LOCKFILE_RULE_WEIGHTS } from '../src/config/constants.js';
import { analyzePackageDirectory } from '../src/static/analyze-package.js';
import { scorePackage } from '../src/static/scoring.js';
import { verdictFor } from '../src/score/aggregate.js';
import { runDynamicAnalysis } from '../src/dynamic/sandbox.js';
import { classifyResult } from './lib/classify.mjs';
import {
  BENIGN_DIR, BENIGN_MANIFEST, GATE_RESULTS_CSV, MALICIOUS_DIR, MALICIOUS_MANIFEST, RECONSTRUCTIONS_DIR, RESULTS_DIR,
  csvLine, parseCsv, parseFlags, readJsonIfExists,
} from './lib/work.mjs';

const LIFECYCLE = ['preinstall', 'install', 'postinstall'];
const HEADERS = [
  'name', 'set', 'category', 'truth', 'isMalicious', 'date', 'postGa', 'hasInstallScript',
  'staticScore', 'dynamicDelta', 'score', 'verdict', 'flagged', 'technique', 'topRule', 'patterns',
  'seconds', 'dynamicOutcome', 'dynamicAttempts', 'filesScanned',
];

const RECONSTRUCTIONS = [
  { dir: 'p0-lifecycle', truth: 'install-time' },
  { dir: 'p1-import-loader', truth: 'import-time' },
  { dir: 'p2-sorted-btree', truth: 'deferred-runtime' },
  { dir: 'p3-optional-helper', truth: 'import-time' },
];

async function listDirs(root) {
  try {
    return (await readdir(root, { withFileTypes: true })).filter((entry) => entry.isDirectory()).map((entry) => entry.name);
  } catch {
    return [];
  }
}

async function buildWorklist(setFilter) {
  const items = [];
  if (!setFilter || setFilter === 'malicious') {
    const manifest = (await readJsonIfExists(MALICIOUS_MANIFEST)) ?? (await listDirs(MALICIOUS_DIR)).map((dir) => ({ dir }));
    for (const entry of manifest) {
      items.push({ name: entry.dir, dir: path.join(MALICIOUS_DIR, entry.dir), set: 'malicious', isMalicious: true,
        category: entry.category ?? '', truth: '', date: entry.date ?? '', postGa: entry.postGa ?? '' });
    }
  }
  if (!setFilter || setFilter === 'benign') {
    const manifest = (await readJsonIfExists(BENIGN_MANIFEST)) ?? (await listDirs(BENIGN_DIR)).map((dir) => ({ dir }));
    for (const entry of manifest) {
      items.push({ name: entry.dir, dir: path.join(BENIGN_DIR, entry.dir), set: 'benign', isMalicious: false,
        category: entry.category ?? '', truth: 'benign', date: '', postGa: '' });
    }
  }
  if (!setFilter || setFilter === 'reconstruction') {
    for (const fixture of RECONSTRUCTIONS) {
      items.push({ name: `recon_${fixture.dir}`, dir: path.join(RECONSTRUCTIONS_DIR, fixture.dir), set: 'reconstruction',
        isMalicious: true, category: 'reconstruction', truth: fixture.truth, date: '2026-10-17', postGa: true });
    }
  }
  return items;
}

async function lifecycleFinding(manifest) {
  const scripts = manifest.scripts ?? {};
  const hasInstallScript = LIFECYCLE.some((name) => typeof scripts[name] === 'string');
  const finding = hasInstallScript
    ? [{ rule: 'lockfile.lifecycle-script', weight: LOCKFILE_RULE_WEIGHTS['lockfile.lifecycle-script'], detail: 'declares a lifecycle script' }]
    : [];
  return { hasInstallScript, finding };
}

async function scanOne(item, dynamic) {
  const started = performance.now();
  const analysis = await analyzePackageDirectory(item.dir);
  const { hasInstallScript, finding } = await lifecycleFinding(analysis.manifest);
  const scored = scorePackage(analysis.findings, finding, analysis.purpose);
  const staticScore = scored.score;

  let dynamicDelta = 0;
  let dynamicOutcome = '';
  let dynamicAttempts = '';
  if (dynamic) {
    const result = await runDynamicAnalysis({ name: item.name, dir: item.dir }, analysis.manifest);
    dynamicDelta = result.scoreDelta;
    dynamicOutcome = result.outcome;
    dynamicAttempts = result.attempts.length;
    scored.patterns.push(...result.patterns);
  }
  const score = Math.min(100, staticScore + dynamicDelta);
  const verdict = verdictFor(score, DEFAULT_THRESHOLDS);
  const patterns = [...new Set(scored.patterns)];
  const topRule = scored.contributions[0]?.source ?? '';
  const seconds = ((performance.now() - started) / 1000).toFixed(2);

  return {
    name: item.name, set: item.set, category: item.category, truth: item.truth, isMalicious: item.isMalicious,
    date: item.date, postGa: item.postGa, hasInstallScript,
    staticScore, dynamicDelta, score, verdict, flagged: verdict !== 'pass',
    technique: classifyResult({ patterns, findings: analysis.findings, lockfileFindings: finding }),
    topRule, patterns: patterns.join('|'), seconds, dynamicOutcome, dynamicAttempts, filesScanned: analysis.stats.filesScanned,
  };
}

async function existingNames(csvPath) {
  try {
    return new Set(parseCsv(await readFile(csvPath, 'utf8')).map((row) => row.name));
  } catch {
    return new Set();
  }
}

async function main() {
  const flags = parseFlags(process.argv.slice(2));
  const dynamic = Boolean(flags.dynamic);
  const resume = Boolean(flags.resume);
  const limit = flags.limit ? Number(flags.limit) : Infinity;
  const setFilter = typeof flags.set === 'string' ? flags.set : null;
  const outCsv = typeof flags.out === 'string' ? path.resolve(flags.out) : GATE_RESULTS_CSV;

  await mkdir(RESULTS_DIR, { recursive: true });
  const worklist = await buildWorklist(setFilter);
  if (worklist.length === 0) throw new Error('nothing to scan; run sample-dataset.mjs and fetch-benign.mjs first');

  const done = resume ? await existingNames(outCsv) : new Set();
  let csvExists = false;
  try { await stat(outCsv); csvExists = true; } catch { /* new file */ }
  if (!resume || !csvExists) await writeFile(outCsv, `${HEADERS.join(',')}\n`);

  const pending = worklist.filter((item) => !done.has(item.name));
  process.stdout.write(`Scanning ${Math.min(pending.length, limit)} of ${pending.length} pending (${worklist.length} total)`
    + `${dynamic ? ' with the dynamic layer' : ' (static only)'}${resume ? ', resuming' : ''}...\n`);

  let scanned = 0;
  const counts = { pass: 0, warn: 0, fail: 0 };
  for (const item of pending) {
    if (scanned >= limit) break;
    let row;
    try {
      row = await scanOne(item, dynamic);
    } catch (error) {
      row = { name: item.name, set: item.set, category: item.category, truth: item.truth, isMalicious: item.isMalicious,
        date: item.date, postGa: item.postGa, hasInstallScript: '', staticScore: '', dynamicDelta: '', score: '',
        verdict: 'error', flagged: '', technique: '', topRule: '', patterns: '', seconds: '', dynamicOutcome: '',
        dynamicAttempts: '', filesScanned: '' };
      process.stdout.write(`  error ${item.name}: ${error.message}\n`);
    }
    await appendFile(outCsv, csvLine(HEADERS, row));
    if (row.verdict in counts) counts[row.verdict] += 1;
    scanned += 1;
    if (scanned % 10 === 0 || row.set === 'reconstruction') {
      process.stdout.write(`  ${scanned}/${pending.length}  ${row.set.padEnd(14)} ${row.verdict.toUpperCase().padEnd(5)} ${row.name}\n`);
    }
  }
  process.stdout.write(`\nDone: ${scanned} scanned (pass ${counts.pass}, warn ${counts.warn}, fail ${counts.fail}). `
    + `CSV: ${outCsv}\nNext: node evaluation/metrics.mjs --csv ${outCsv}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exit(1);
});
