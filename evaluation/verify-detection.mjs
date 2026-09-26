// End-to-end check that the gate detects each reconstructed pattern and passes clean code.
// Builds a throwaway project in the OS temp dir whose node_modules holds the four fixtures plus
// one benign package, writes a matching package-lock.json, runs the real gate (static layer),
// and asserts the verdicts. No network, no registry needed. Run: node evaluation/verify-detection.mjs
import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runGate } from '../src/gate.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RECON_DIR = path.join(HERE, '..', 'reconstructions');
const REGISTRY = 'https://registry.npmjs.org';

const RECON_PACKAGES = [
  { name: '@recon/p0-lifecycle', dir: 'p0-lifecycle', hasInstallScript: true, expect: ['warn', 'fail'] },
  { name: '@recon/p1-import-loader', dir: 'p1-import-loader', expect: ['fail'] },
  { name: '@recon/p2-sorted-btree', dir: 'p2-sorted-btree', expect: ['warn', 'fail'] },
  { name: '@recon/p3-optional-helper', dir: 'p3-optional-helper', optional: true, git: true, expect: ['fail'] },
];

const BENIGN = { name: 'tiny-pure', version: '1.0.0' };

async function buildProject() {
  const projectDir = await mkdtemp(path.join(tmpdir(), 'gate-verify-'));
  const nodeModules = path.join(projectDir, 'node_modules');

  for (const pkg of RECON_PACKAGES) {
    await cp(path.join(RECON_DIR, pkg.dir), path.join(nodeModules, pkg.name), { recursive: true });
  }
  const benignDir = path.join(nodeModules, BENIGN.name);
  await mkdir(benignDir, { recursive: true });
  await writeFile(path.join(benignDir, 'package.json'), JSON.stringify({ name: BENIGN.name, version: BENIGN.version, main: 'index.js' }));
  await writeFile(path.join(benignDir, 'index.js'), 'export const clamp = (n, lo, hi) => Math.min(hi, Math.max(lo, n));\n');

  const packages = {
    '': { name: 'verify-project', version: '1.0.0' },
    [`node_modules/${BENIGN.name}`]: {
      version: BENIGN.version,
      resolved: `${REGISTRY}/${BENIGN.name}/-/${BENIGN.name}-${BENIGN.version}.tgz`,
      integrity: 'sha512-benign',
    },
  };
  for (const pkg of RECON_PACKAGES) {
    packages[`node_modules/${pkg.name}`] = {
      version: '1.0.0',
      resolved: pkg.git
        ? 'git+https://sinkhole.invalid/p3-native-ext.git'
        : `${REGISTRY}/${pkg.name}/-/${pkg.dir}-1.0.0.tgz`,
      integrity: pkg.git ? undefined : 'sha512-recon',
      optional: pkg.optional === true,
      hasInstallScript: pkg.hasInstallScript === true,
    };
  }
  await writeFile(
    path.join(projectDir, 'package-lock.json'),
    JSON.stringify({ name: 'verify-project', lockfileVersion: 3, packages }, null, 2),
  );
  return projectDir;
}

async function main() {
  const projectDir = await buildProject();
  try {
    const report = await runGate(projectDir, { dynamic: false });
    const byName = new Map(report.packages.map((result) => [result.name, result]));

    for (const pkg of RECON_PACKAGES) {
      const result = byName.get(pkg.name);
      assert.ok(result, `${pkg.name} was not scanned`);
      assert.ok(
        pkg.expect.includes(result.verdict),
        `${pkg.name}: expected ${pkg.expect.join(' or ')}, got ${result.verdict} (score ${result.score}; patterns ${result.patterns.join(', ') || 'none'})`,
      );
      process.stdout.write(`  ${result.verdict.toUpperCase().padEnd(5)} ${pkg.name} score=${result.score} patterns=[${result.patterns.join(', ')}]\n`);
    }

    const benign = byName.get(BENIGN.name);
    assert.equal(benign.verdict, 'pass', `benign package should pass, got ${benign.verdict} (score ${benign.score})`);
    process.stdout.write(`  PASS  ${BENIGN.name} score=${benign.score} (benign, correctly cleared)\n`);

    const p1 = byName.get('@recon/p1-import-loader');
    assert.ok(p1.patterns.includes('import-time-execution'), 'P1 should be flagged as import-time execution');
    const p2 = byName.get('@recon/p2-sorted-btree');
    assert.ok(!p2.patterns.includes('import-time-execution'), 'P2 should NOT be import-time (it is deferred to a method call)');

    process.stdout.write('\nOK: every reconstructed pattern was detected and the benign package passed.\n');
  } finally {
    await rm(projectDir, { recursive: true, force: true });
  }
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
});
