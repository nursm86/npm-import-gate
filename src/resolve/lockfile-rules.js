import { LOCKFILE_RULE_WEIGHTS, OFFICIAL_REGISTRY_HOSTS } from '../config/constants.js';

const GIT_SOURCE_PREFIXES = ['git+', 'git://', 'github:', 'gitlab:', 'bitbucket:'];

/**
 * @typedef {object} LockfileFinding
 * @property {string} rule
 * @property {number} weight
 * @property {string} detail
 */

export function isOfficialRegistryUrl(resolved, allowedHosts = OFFICIAL_REGISTRY_HOSTS) {
  if (!resolved) return false;
  if (GIT_SOURCE_PREFIXES.some((prefix) => resolved.startsWith(prefix))) return false;
  try {
    const url = new URL(resolved);
    return url.protocol === 'https:' && allowedHosts.includes(url.hostname);
  } catch {
    return false;
  }
}

/**
 * Lockfile-level checks that need no source code. npm v12 already refuses git and remote
 * sources by default, so a non-registry `resolved` in a fresh lockfile means someone opted in.
 * @param {import('./lockfile.js').PackageNode} node
 * @returns {LockfileFinding[]}
 */
export function evaluateLockfileNode(node, options = {}) {
  const allowedHosts = options.allowedRegistryHosts ?? OFFICIAL_REGISTRY_HOSTS;
  const findings = [];
  if (node.isLink) return findings;

  const fromOfficialRegistry = isOfficialRegistryUrl(node.resolved, allowedHosts);
  if (!fromOfficialRegistry) {
    findings.push({
      rule: 'lockfile.non-registry-source',
      weight: LOCKFILE_RULE_WEIGHTS['lockfile.non-registry-source'],
      detail: `resolved from ${node.resolved ?? 'an unknown source'}`,
    });
    if (node.isOptional) {
      findings.push({
        rule: 'lockfile.optional-non-registry',
        weight: LOCKFILE_RULE_WEIGHTS['lockfile.optional-non-registry'],
        detail: 'optional dependency from a non-registry source can fail silently at install',
      });
    }
  }

  if (!node.integrity) {
    findings.push({
      rule: 'lockfile.missing-integrity',
      weight: LOCKFILE_RULE_WEIGHTS['lockfile.missing-integrity'],
      detail: 'no integrity hash recorded, so the tarball cannot be verified',
    });
  }

  if (node.hasInstallScript) {
    findings.push({
      rule: 'lockfile.lifecycle-script',
      weight: LOCKFILE_RULE_WEIGHTS['lockfile.lifecycle-script'],
      detail: 'declares a lifecycle script (blocked by default since npm v12 unless approved)',
    });
  }

  return findings;
}
