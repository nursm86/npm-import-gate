// Explains why malicious samples stayed below the warn threshold by re-running the static analysis
// on each one and looking at what the package actually ships. Writes a markdown table with one
// reason per sample and a count per reason (the source of the "why we miss" paragraph in §4.4).
//
//   node evaluation/explain-misses.mjs --csv evaluation/results/gate-results.csv \
//     --out ../04-evidence/results/misses.md
import { readdir, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { DEFAULT_THRESHOLDS, SOURCE_EXTENSIONS } from '../src/config/constants.js';
import { analyzePackageDirectory } from '../src/static/analyze-package.js';
import { TINY_PACKAGE_RULE } from '../src/config/constants.js';
import { GATE_RESULTS_CSV, MALICIOUS_DIR, parseCsv, parseFlags, toBool, toNum } from './lib/work.mjs';

/** A package whose whole JavaScript fits in this many bytes and does nothing dangerous is a name reservation. */
const PLACEHOLDER_MAX_BYTES = 400;
const TYPE_DECLARATION_SUFFIX = '.d.ts';
const UNINTERESTING_EXTENSIONS = new Set(['.md', '.json', '.txt', '.map', 'LICENSE', 'LICENCE']);
const MAX_OTHER_TYPES = 5;

const REASON = Object.freeze({
  NO_JS: 'no JavaScript shipped',
  JS_SKIPPED: 'JavaScript only in excluded or oversized files',
  UNPARSEABLE: 'unparseable JavaScript (broken sample)',
  PLACEHOLDER: 'inert placeholder',
  NO_CAPABILITY: 'no capability in source',
  BELOW_WARN: 'capabilities present but below warn',
});

async function listFiles(dir, found = []) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules') continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) await listFiles(fullPath, found);
    else found.push(fullPath);
  }
  return found;
}

function isSourceFile(filePath) {
  return SOURCE_EXTENSIONS.includes(path.extname(filePath)) && !filePath.endsWith(TYPE_DECLARATION_SUFFIX);
}

function otherFileTypes(files) {
  const types = files.filter((file) => !isSourceFile(file)).map((file) => path.extname(file) || path.basename(file));
  return [...new Set(types)].filter((type) => !UNINTERESTING_EXTENSIONS.has(type)).slice(0, MAX_OTHER_TYPES);
}

function reasonFor(analysis, sourceFileCount, sourceBytes, families) {
  const { filesScanned, parseErrors } = analysis.stats;
  if (filesScanned === 0) return sourceFileCount === 0 ? REASON.NO_JS : REASON.JS_SKIPPED;
  if (parseErrors === filesScanned) return REASON.UNPARSEABLE;
  const dangerous = families.some((family) => TINY_PACKAGE_RULE.families.includes(family));
  if (sourceBytes <= PLACEHOLDER_MAX_BYTES && !dangerous) return REASON.PLACEHOLDER;
  if (analysis.findings.length === 0) return REASON.NO_CAPABILITY;
  return REASON.BELOW_WARN;
}

async function explain(row) {
  const dir = path.join(MALICIOUS_DIR, row.name);
  const analysis = await analyzePackageDirectory(dir);
  const files = await listFiles(dir);
  const sourceFiles = files.filter(isSourceFile);
  let sourceBytes = 0;
  for (const file of sourceFiles) sourceBytes += (await stat(file)).size;
  const families = [...new Set(analysis.findings.map((finding) => finding.family))];
  return {
    reason: reasonFor(analysis, sourceFiles.length, sourceBytes, families),
    line: `| ${row.name} | ${row.staticScore} | ${row.hasInstallScript ? 'yes' : 'no'} | ${analysis.stats.filesScanned} | ${sourceBytes} | `
      + `${families.join(', ') || '–'} | ${otherFileTypes(files).join(' ') || '–'} | `,
  };
}

async function main() {
  const flags = parseFlags(process.argv.slice(2));
  const csvPath = typeof flags.csv === 'string' ? path.resolve(flags.csv) : GATE_RESULTS_CSV;
  const threshold = flags.threshold ? Number(flags.threshold) : DEFAULT_THRESHOLDS.warn;
  if (typeof flags.out !== 'string') throw new Error('usage: explain-misses.mjs [--csv <csv>] --out <markdown> [--threshold N]');

  const rows = parseCsv(await readFile(csvPath, 'utf8'))
    .filter((row) => row.set === 'malicious' && row.score !== '')
    .map((row) => ({ ...row, isMalicious: toBool(row.isMalicious), hasInstallScript: toBool(row.hasInstallScript), staticScore: toNum(row.staticScore) }));
  const total = rows.length;
  const missed = rows.filter((row) => row.staticScore < threshold);

  const counts = new Map();
  const lines = [];
  for (const row of missed) {
    const { reason, line } = await explain(row);
    counts.set(reason, (counts.get(reason) ?? 0) + 1);
    lines.push(`${line}${reason} |`);
  }
  const out = [
    `# Why ${missed.length} of ${total} malicious samples stayed below ${threshold} (static layer)`, '',
    `Generated ${new Date().toISOString()} from \`${path.basename(csvPath)}\`. Reasons come from re-running the static analysis on each sample.`, '',
    '| Reason | Count | Share of malicious sample |', '|---|---|---|',
    ...[...counts.entries()].sort((left, right) => right[1] - left[1])
      .map(([reason, count]) => `| ${reason} | ${count} | ${(100 * count / Math.max(1, total)).toFixed(1)}% |`), '',
    '| Sample | Static score | Install script | JS files scanned | JS bytes | Capability families seen | Other file types | Reason |',
    '|---|---|---|---|---|---|---|---|',
    ...lines, '',
  ].join('\n');
  await writeFile(path.resolve(flags.out), `${out}\n`);
  process.stdout.write(`Wrote ${path.resolve(flags.out)} (${missed.length} misses explained)\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exit(1);
});
