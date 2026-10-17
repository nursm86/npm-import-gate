import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_THRESHOLDS } from './config/constants.js';
import { readLockfile, toPackageNodes } from './resolve/lockfile.js';
import { evaluateLockfileNode } from './resolve/lockfile-rules.js';
import { analyzePackageDirectory } from './static/analyze-package.js';
import { scorePackage } from './static/scoring.js';
import { summarise, verdictFor } from './score/aggregate.js';
import { runDynamicAnalysis } from './dynamic/sandbox.js';
import { logger } from './util/logger.js';

const OWN_MANIFEST = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'package.json');

async function toolVersion() {
  const manifest = JSON.parse(await readFile(OWN_MANIFEST, 'utf8'));
  return manifest.version;
}

/**
 * @typedef {object} GateOptions
 * @property {{fail:number, warn:number}} [thresholds]
 * @property {boolean} [dynamic]           run the sandbox layer (needs Docker)
 * @property {string[]} [only]             restrict to these package names
 * @property {boolean} [includeDev]        scan devDependencies too (default true: CI installs them)
 * @property {string[]} [allowedRegistryHosts]
 */

/**
 * Runs the whole gate over a project directory that has a package-lock.json and an installed
 * node_modules. Returns the full report object; rendering is separate.
 */
export async function runGate(projectDir, options = {}) {
  const thresholds = options.thresholds ?? DEFAULT_THRESHOLDS;
  const includeDev = options.includeDev ?? true;
  const absoluteProjectDir = path.resolve(projectDir);

  const lockfile = await readLockfile(absoluteProjectDir);
  let nodes = toPackageNodes(lockfile, absoluteProjectDir);
  if (!includeDev) nodes = nodes.filter((node) => !node.isDev);
  if (options.only?.length) nodes = nodes.filter((node) => options.only.includes(node.name));
  logger.info({ packages: nodes.length, dynamic: Boolean(options.dynamic) }, 'gate started');

  const packages = [];
  for (const node of nodes) {
    const lockfileFindings = evaluateLockfileNode(node, { allowedRegistryHosts: options.allowedRegistryHosts });
    const analysis = await analyzePackageDirectory(node.dir);
    const scored = scorePackage(analysis.findings, lockfileFindings, analysis.purpose);

    let dynamic;
    if (options.dynamic) {
      dynamic = await runDynamicAnalysis(node, analysis.manifest);
      scored.score = Math.min(100, scored.score + dynamic.scoreDelta);
      scored.contributions.push(...dynamic.contributions);
      scored.patterns.push(...dynamic.patterns);
    }

    packages.push({
      name: node.name,
      // Linked (file:) dependencies carry no version in the lockfile; fall back to the manifest.
      version: node.version === 'unknown' ? (analysis.manifest.version ?? 'unknown') : node.version,
      lockKey: node.lockKey,
      purpose: analysis.purpose,
      score: scored.score,
      verdict: verdictFor(scored.score, thresholds),
      patterns: [...new Set(scored.patterns)],
      contributions: scored.contributions,
      findings: analysis.findings,
      lockfileFindings,
      dynamic,
      stats: analysis.stats,
    });
    logger.debug({ name: node.name, version: node.version, score: scored.score }, 'package scored');
  }

  packages.sort((left, right) => right.score - left.score);
  return {
    toolVersion: await toolVersion(),
    generatedAt: new Date().toISOString(),
    project: { name: lockfile.name, dir: absoluteProjectDir, lockfileVersion: lockfile.lockfileVersion },
    dynamicEnabled: Boolean(options.dynamic),
    summary: summarise(packages, thresholds),
    packages,
  };
}
