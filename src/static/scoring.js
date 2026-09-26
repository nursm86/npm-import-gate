import {
  CAPABILITY_WEIGHTS,
  COMBINATION_BOOSTS,
  CONTEXT_MULTIPLIERS,
  PURPOSE_MISMATCH_FAMILIES,
  PURPOSE_MISMATCH_MULTIPLIER,
  SCORE_CAP,
} from '../config/constants.js';
import { PURPOSE } from './purpose.js';

/**
 * @typedef {object} ScoreContribution
 * @property {string} source        capability id, lockfile rule id, or combination id
 * @property {number} points
 * @property {string} reason
 * @property {object} [finding]     the highest-context finding that produced it
 */

function contextMultiplier(scope) {
  return CONTEXT_MULTIPLIERS[scope] ?? CONTEXT_MULTIPLIERS.function;
}

function purposeMultiplier(family, purpose) {
  const mismatch = purpose === PURPOSE.PURE && PURPOSE_MISMATCH_FAMILIES.includes(family);
  return mismatch ? PURPOSE_MISMATCH_MULTIPLIER : 1;
}

function pointsFor(finding, purpose) {
  const base = CAPABILITY_WEIGHTS[finding.capability] ?? 0;
  return base * contextMultiplier(finding.scope) * purposeMultiplier(finding.family, purpose);
}

/** Each capability contributes once, at its most dangerous occurrence. */
function bestFindingPerCapability(findings, purpose) {
  const best = new Map();
  for (const finding of findings) {
    const points = pointsFor(finding, purpose);
    const current = best.get(finding.capability);
    if (!current || points > current.points) best.set(finding.capability, { finding, points });
  }
  return best;
}

function combinationBoosts(presentCapabilities) {
  return COMBINATION_BOOSTS.filter(({ requires }) =>
    requires.every((alternatives) => alternatives.some((capability) => presentCapabilities.has(capability))),
  );
}

/**
 * Scores one package from its static findings and lockfile findings.
 * @param {import('./capabilities.js').CapabilityFinding[]} capabilityFindings
 * @param {import('../resolve/lockfile-rules.js').LockfileFinding[]} lockfileFindings
 * @param {string} purpose  from inferPurpose()
 * @returns {{ score: number, contributions: ScoreContribution[], patterns: string[] }}
 */
export function scorePackage(capabilityFindings, lockfileFindings, purpose) {
  const contributions = [];

  for (const [capability, { finding, points }] of bestFindingPerCapability(capabilityFindings, purpose)) {
    const reasonParts = [`${finding.scope} scope in ${finding.file}:${finding.line}`];
    if (purposeMultiplier(finding.family, purpose) > 1) reasonParts.push('purpose mismatch (pure-logic package)');
    contributions.push({ source: capability, points, reason: reasonParts.join('; '), finding });
  }

  for (const lockfileFinding of lockfileFindings) {
    contributions.push({ source: lockfileFinding.rule, points: lockfileFinding.weight, reason: lockfileFinding.detail });
  }

  const presentCapabilities = new Set(capabilityFindings.map((finding) => finding.capability));
  const patterns = [];
  for (const { id, boost } of combinationBoosts(presentCapabilities)) {
    contributions.push({ source: id, points: boost, reason: 'capabilities combine into a known malicious pattern' });
    patterns.push(id);
  }

  const EXECUTABLE_FAMILIES = ['process', 'net', 'code', 'dns'];
  const runsDangerously = (finding, executedAt) =>
    finding.scope === 'module'
    && EXECUTABLE_FAMILIES.includes(finding.family)
    && (finding.executedAt ?? 'import-or-runtime') === executedAt;

  if (capabilityFindings.some((finding) => runsDangerously(finding, 'install'))) {
    patterns.push('install-time-execution');
  }
  if (capabilityFindings.some((finding) => runsDangerously(finding, 'import-or-runtime'))) {
    patterns.push('import-time-execution');
  }
  const deferredToMethod = !patterns.includes('import-time-execution')
    && capabilityFindings.some((finding) => finding.scope === 'method' && EXECUTABLE_FAMILIES.includes(finding.family));
  if (deferredToMethod) patterns.push('deferred-runtime-trigger');

  const total = contributions.reduce((sum, contribution) => sum + contribution.points, 0);
  return {
    score: Math.min(SCORE_CAP, Math.round(total)),
    contributions: contributions.sort((left, right) => right.points - left.points),
    patterns,
  };
}
