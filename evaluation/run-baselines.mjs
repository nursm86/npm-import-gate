// Runs the comparison baselines over the same work set and writes results/baselines.csv plus a
// metrics summary. Baselines:
//   install-scripts  a package is "caught" iff it declares a preinstall/install/postinstall script
//                    (this is exactly what npm v12 blocking neutralises; reproduces the ~72% figure)
//   guarddog         DataDog GuardDog static scanner via `uvx guarddog npm scan <dir>`. A local scan,
//                    so registry-metadata rules (typosquatting, maintainer email) do not run. Two
//                    readings are kept: threat-* rule hits, and any hit including the informational
//                    capability-* notices. The raw JSON per package goes to results/work/guarddog/.
//   npm-audit        advisory-based; flags only packages with a known advisory. On a freshly
//                    collected malicious set that is zero by construction, which is the point.
//
//   node evaluation/run-baselines.mjs
import { spawnSync } from 'node:child_process';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { hasLifecycleScript } from '../src/static/lifecycle-scripts.js';
import { evaluate, asPercent } from './lib/metrics.mjs';
import { BASELINES_CSV, BENIGN_DIR, MALICIOUS_DIR, RESULTS_DIR, WORK_DIR, toCsv } from './lib/work.mjs';

const GUARDDOG_OUTPUT_DIR = path.join(WORK_DIR, 'guarddog');
const GUARDDOG_TIMEOUT_MS = 120_000;
const GUARDDOG_MAX_OUTPUT_BYTES = 64 * 1024 * 1024;
const CAPABILITY_RULE_PREFIX = 'capability-';
const PROGRESS_EVERY = 25;

async function packageDirs(root) {
  try {
    return (await readdir(root, { withFileTypes: true }))
      .filter((entry) => entry.isDirectory())
      .map((entry) => path.join(root, entry.name));
  } catch {
    return [];
  }
}

async function readManifest(dir) {
  try {
    return JSON.parse(await readFile(path.join(dir, 'package.json'), 'utf8'));
  } catch {
    return {};
  }
}

function guarddogAvailable() {
  return spawnSync('uvx', ['guarddog', '--help'], { stdio: 'ignore' }).status === 0;
}

/** Rule ids with at least one hit in a GuardDog results map. */
function hitRules(results) {
  return Object.entries(results ?? {})
    .filter(([, hits]) => (Array.isArray(hits) ? hits.length > 0 : Object.keys(hits ?? {}).length > 0))
    .map(([rule]) => rule);
}

/** Runs GuardDog on one package directory. Returns an error field when the scan failed or timed out. */
async function scanWithGuarddog(dir, name) {
  const started = performance.now();
  const result = spawnSync('uvx', ['guarddog', 'npm', 'scan', dir, '--output-format', 'json'], {
    encoding: 'utf8', timeout: GUARDDOG_TIMEOUT_MS, maxBuffer: GUARDDOG_MAX_OUTPUT_BYTES,
  });
  const seconds = ((performance.now() - started) / 1000).toFixed(2);
  if (result.status === null || !result.stdout) {
    return { seconds, error: (result.stderr ?? '').trim().slice(-200) || 'no output' };
  }
  let report;
  try {
    report = JSON.parse(result.stdout);
  } catch {
    return { seconds, error: 'unparseable JSON' };
  }
  await writeFile(path.join(GUARDDOG_OUTPUT_DIR, `${name}.json`), result.stdout);
  const rules = hitRules(report.results);
  return {
    seconds,
    issues: report.issues ?? rules.length,
    riskScore: report.risk_score ?? '',
    rules,
    threat: rules.some((rule) => !rule.startsWith(CAPABILITY_RULE_PREFIX)),
    any: rules.length > 0,
  };
}

async function main() {
  const malicious = await packageDirs(MALICIOUS_DIR);
  const benign = await packageDirs(BENIGN_DIR);
  if (malicious.length + benign.length === 0) {
    process.stderr.write('No work packages. Run sample-dataset.mjs and fetch-benign.mjs first.\n');
    process.exit(1);
  }
  const useGuarddog = guarddogAvailable();
  if (useGuarddog) await mkdir(GUARDDOG_OUTPUT_DIR, { recursive: true });
  else process.stdout.write('GuardDog not available via uvx; skipping that baseline.\n');

  const rows = [];
  let scanned = 0;
  const total = malicious.length + benign.length;
  for (const [set, isMalicious, dirs] of [['malicious', true, malicious], ['benign', false, benign]]) {
    for (const dir of dirs) {
      const name = path.basename(dir);
      const manifest = await readManifest(dir);
      const guarddog = useGuarddog ? await scanWithGuarddog(dir, name) : null;
      const guarddogOk = guarddog && !guarddog.error;
      rows.push({
        name,
        set,
        isMalicious,
        installScripts: hasLifecycleScript(manifest),
        guarddogThreat: guarddogOk ? guarddog.threat : '',
        guarddogAny: guarddogOk ? guarddog.any : '',
        guarddogIssues: guarddogOk ? guarddog.issues : '',
        guarddogRiskScore: guarddogOk ? guarddog.riskScore : '',
        guarddogRules: guarddogOk ? guarddog.rules.join('|') : '',
        guarddogSeconds: guarddog?.seconds ?? '',
        guarddogError: guarddog?.error ?? '',
        npmAudit: false,
      });
      scanned += 1;
      if (scanned % PROGRESS_EVERY === 0) process.stdout.write(`  ${scanned}/${total}  ${set.padEnd(9)} ${name}\n`);
    }
  }

  await mkdir(RESULTS_DIR, { recursive: true });
  await writeFile(BASELINES_CSV, toCsv(rows), 'utf8');

  const report = (label, key) => {
    const usable = rows.filter((row) => row[key] !== '');
    if (usable.length === 0) return;
    const metrics = evaluate(usable.map((row) => ({ isMalicious: row.isMalicious, flagged: Boolean(row[key]) })));
    process.stdout.write(`${label.padEnd(16)} precision ${asPercent(metrics.precision)}  `
      + `recall ${asPercent(metrics.recall)}  F1 ${asPercent(metrics.f1)}  FP ${asPercent(metrics.falsePositiveRate)}  (n=${usable.length})\n`);
  };

  process.stdout.write('\n=== baselines ===\n');
  report('install-scripts', 'installScripts');
  if (useGuarddog) {
    report('guarddog-threat', 'guarddogThreat');
    report('guarddog-any', 'guarddogAny');
    const failed = rows.filter((row) => row.guarddogError !== '').length;
    if (failed) process.stdout.write(`GuardDog failed on ${failed} package(s); see guarddogError in the CSV.\n`);
  }
  report('npm-audit', 'npmAudit');
  const maliciousWithScripts = rows.filter((row) => row.isMalicious && row.installScripts).length;
  process.stdout.write(`\nInstall-script share of malicious sample: `
    + `${maliciousWithScripts}/${malicious.length} (${asPercent(maliciousWithScripts / malicious.length)}). `
    + 'Compare with Guo et al. 2026 (72.21%).\n');
  process.stdout.write('npm-audit is advisory-based; on a fresh malicious set it flags nothing, by design.\n');
  process.stdout.write(`Rows written to ${BASELINES_CSV}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exit(1);
});
