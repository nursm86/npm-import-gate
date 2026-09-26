// Runs the comparison baselines over the same work set and writes results/baselines.csv plus a
// metrics summary. Baselines:
//   install-scripts  a package is "caught" iff it declares a preinstall/install/postinstall script
//                    (this is exactly what npm v12 blocking neutralises; reproduces the ~72% figure)
//   guarddog         DataDog GuardDog static scanner, if available via `uvx guarddog`
//   npm-audit        advisory-based; flags only packages with a known advisory. On a freshly
//                    collected malicious set that is zero by construction, which is the point.
import { spawnSync } from 'node:child_process';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { evaluate, asPercent } from './lib/metrics.mjs';
import { BENIGN_DIR, MALICIOUS_DIR, RESULTS_DIR, toCsv } from './lib/work.mjs';

const LIFECYCLE = ['preinstall', 'install', 'postinstall'];

async function packageDirs(root) {
  try {
    return (await readdir(root, { withFileTypes: true }))
      .filter((entry) => entry.isDirectory())
      .map((entry) => path.join(root, entry.name));
  } catch {
    return [];
  }
}

async function readScripts(dir) {
  try {
    const manifest = JSON.parse(await readFile(path.join(dir, 'package.json'), 'utf8'));
    return manifest.scripts ?? {};
  } catch {
    return {};
  }
}

function guarddogAvailable() {
  return spawnSync('uvx', ['guarddog', '--help'], { stdio: 'ignore' }).status === 0;
}

function guarddogFlags(dir) {
  const result = spawnSync('uvx', ['guarddog', 'npm', 'scan', dir, '--output-format', 'json'],
    { encoding: 'utf8', timeout: 120000 });
  if (result.status === null) return null;
  try {
    const report = JSON.parse(result.stdout);
    const issues = report.issues ?? report.results?.issues ?? 0;
    return (typeof issues === 'number' ? issues : Object.keys(issues).length) > 0;
  } catch {
    return null;
  }
}

async function main() {
  const malicious = await packageDirs(MALICIOUS_DIR);
  const benign = await packageDirs(BENIGN_DIR);
  if (malicious.length + benign.length === 0) {
    process.stderr.write('No work packages. Run sample-dataset.mjs and fetch-benign.mjs first.\n');
    process.exit(1);
  }
  const useGuarddog = guarddogAvailable();
  if (!useGuarddog) process.stdout.write('GuardDog not available via uvx; skipping that baseline.\n');

  const rows = [];
  for (const [isMalicious, dirs] of [[true, malicious], [false, benign]]) {
    for (const dir of dirs) {
      const scripts = await readScripts(dir);
      const installScriptFlag = LIFECYCLE.some((name) => typeof scripts[name] === 'string');
      const guarddogFlag = useGuarddog ? guarddogFlags(dir) : null;
      rows.push({
        name: path.basename(dir),
        isMalicious,
        installScripts: installScriptFlag,
        guarddog: guarddogFlag === null ? '' : guarddogFlag,
        npmAudit: false,
      });
    }
  }

  await mkdir(RESULTS_DIR, { recursive: true });
  await writeFile(path.join(RESULTS_DIR, 'baselines.csv'), toCsv(rows), 'utf8');

  const report = (label, key) => {
    const usable = rows.filter((row) => row[key] !== '');
    if (usable.length === 0) return;
    const metrics = evaluate(usable.map((row) => ({ isMalicious: row.isMalicious, flagged: Boolean(row[key]) })));
    process.stdout.write(`${label.padEnd(16)} precision ${asPercent(metrics.precision)}  `
      + `recall ${asPercent(metrics.recall)}  F1 ${asPercent(metrics.f1)}  FP ${asPercent(metrics.falsePositiveRate)}\n`);
  };

  process.stdout.write('\n=== baselines ===\n');
  report('install-scripts', 'installScripts');
  if (useGuarddog) report('guarddog', 'guarddog');
  report('npm-audit', 'npmAudit');
  const maliciousWithScripts = rows.filter((row) => row.isMalicious && row.installScripts).length;
  process.stdout.write(`\nInstall-script share of malicious sample: `
    + `${maliciousWithScripts}/${malicious.length} (${asPercent(maliciousWithScripts / malicious.length)}). `
    + 'Compare with Guo et al. 2026 (72.21%).\n');
  process.stdout.write('npm-audit is advisory-based; on a fresh malicious set it flags nothing, by design.\n');
  process.stdout.write(`Rows written to ${path.join(RESULTS_DIR, 'baselines.csv')}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
});
