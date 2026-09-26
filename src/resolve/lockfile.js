import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { z } from 'zod';

const LOCKFILE_NAME = 'package-lock.json';
const SUPPORTED_LOCKFILE_VERSIONS = [2, 3];
const NODE_MODULES_SEGMENT = 'node_modules/';

const LockfileEntrySchema = z
  .object({
    name: z.string().optional(),
    version: z.string().optional(),
    resolved: z.string().optional(),
    integrity: z.string().optional(),
    dev: z.boolean().optional(),
    optional: z.boolean().optional(),
    devOptional: z.boolean().optional(),
    link: z.boolean().optional(),
    hasInstallScript: z.boolean().optional(),
    dependencies: z.record(z.string(), z.string()).optional(),
    optionalDependencies: z.record(z.string(), z.string()).optional(),
  })
  .passthrough();

const LockfileSchema = z
  .object({
    name: z.string().optional(),
    lockfileVersion: z.number(),
    packages: z.record(z.string(), LockfileEntrySchema),
  })
  .passthrough();

/**
 * @typedef {object} PackageNode
 * @property {string} name        package name as npm resolves it
 * @property {string} version
 * @property {string} lockKey     key in lockfile.packages, e.g. "node_modules/a/node_modules/b"
 * @property {string} dir         absolute path of the installed package directory
 * @property {string|undefined} resolved
 * @property {string|undefined} integrity
 * @property {boolean} isDev
 * @property {boolean} isOptional
 * @property {boolean} isLink
 * @property {boolean} hasInstallScript
 * @property {string[]} optionalDependencyNames
 */

export async function readLockfile(projectDir) {
  const lockfilePath = path.join(projectDir, LOCKFILE_NAME);
  const raw = await readFile(lockfilePath, 'utf8');
  const parsed = LockfileSchema.parse(JSON.parse(raw));
  if (!SUPPORTED_LOCKFILE_VERSIONS.includes(parsed.lockfileVersion)) {
    throw new Error(`Unsupported lockfileVersion ${parsed.lockfileVersion}; expected one of ${SUPPORTED_LOCKFILE_VERSIONS.join(', ')}`);
  }
  return parsed;
}

/** The package name is the part of the lock key after the last "node_modules/". */
export function packageNameFromLockKey(lockKey) {
  const lastIndex = lockKey.lastIndexOf(NODE_MODULES_SEGMENT);
  if (lastIndex === -1) return lockKey;
  return lockKey.slice(lastIndex + NODE_MODULES_SEGMENT.length);
}

/**
 * Flattens lockfile.packages into installed dependency nodes. The root entry ("") and
 * workspace links are excluded because they are the project under test, not dependencies.
 * @returns {PackageNode[]}
 */
export function toPackageNodes(lockfile, projectDir) {
  const nodes = [];
  for (const [lockKey, entry] of Object.entries(lockfile.packages)) {
    const isRoot = lockKey === '';
    const isInsideNodeModules = lockKey.includes(NODE_MODULES_SEGMENT);
    if (isRoot || !isInsideNodeModules) continue;
    nodes.push({
      name: entry.name ?? packageNameFromLockKey(lockKey),
      version: entry.version ?? 'unknown',
      lockKey,
      dir: path.join(projectDir, lockKey),
      resolved: entry.resolved,
      integrity: entry.integrity,
      isDev: entry.dev === true,
      isOptional: entry.optional === true || entry.devOptional === true,
      isLink: entry.link === true,
      hasInstallScript: entry.hasInstallScript === true,
      optionalDependencyNames: Object.keys(entry.optionalDependencies ?? {}),
    });
  }
  return nodes;
}
