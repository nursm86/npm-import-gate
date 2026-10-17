import {
  CAPABILITY_WEIGHTS,
  COMBINATION_BOOSTS,
  CONTEXT_MULTIPLIERS,
  DECLARED_TOOL_DISCOUNT,
  EXECUTED_AT,
  PURPOSE_MISMATCH_FAMILIES,
  PURPOSE_MISMATCH_MULTIPLIER,
  SCORE_CAP,
  TINY_PACKAGE_RULE,
} from '../config/constants.js';
import { PURPOSE, declaresExecutable } from './purpose.js';

/** Families whose module-scope use means code runs as soon as the package is loaded. */
const EXECUTABLE_FAMILIES = Object.freeze(['process', 'net', 'code', 'dns']);

/**
 * @typedef {object} ScoreContribution
 * @property {string} source        capability id, lockfile rule id, combination id or context rule id
 * @property {number} points
 * @property {string} reason
 * @property {object} [finding]     the highest-context finding that produced it
 */

/**
 * @typedef {object} ScoringContext
 * @property {number} [filesScanned]   source files the static walk parsed
 * @property {boolean} [declaresBin]   the manifest installs a command-line executable
 */

/** The scoring context for one analysis from analyzePackageDirectory(). */
export function scoringContext(analysis) {
  return { filesScanned: analysis.stats?.filesScanned, declaresBin: declaresExecutable(analysis.manifest) };
}

function contextMultiplier(scope) {
  return CONTEXT_MULTIPLIERS[scope] ?? CONTEXT_MULTIPLIERS.function;
}

function purposeMultiplier(family, purpose) {
  const mismatch = purpose === PURPOSE.PURE && PURPOSE_MISMATCH_FAMILIES.includes(family);
  return mismatch ? PURPOSE_MISMATCH_MULTIPLIER : 1;
}

function isDeclaredTool(purpose, context) {
  return Boolean(context.declaresBin) || (DECLARED_TOOL_DISCOUNT.appliesToInferredTool && purpose === PURPOSE.TOOL);
}

/** Tools spawn, read env and eval by design; their import-time and runtime findings are discounted. */
function toolMultiplier(finding, purpose, context) {
  const discounted = isDeclaredTool(purpose, context)
    && DECLARED_TOOL_DISCOUNT.families.includes(finding.family)
    && finding.executedAt !== EXECUTED_AT.INSTALL;
  return discounted ? DECLARED_TOOL_DISCOUNT.multiplier : 1;
}

function pointsFor(finding, purpose, context) {
  const base = CAPABILITY_WEIGHTS[finding.capability] ?? 0;
  return base
    * contextMultiplier(finding.scope)
    * purposeMultiplier(finding.family, purpose)
    * toolMultiplier(finding, purpose, context);
}

/** Each capability contributes once, at its most dangerous occurrence. */
function bestFindingPerCapability(findings, purpose, context) {
  const best = new Map();
  for (const finding of findings) {
    const points = pointsFor(finding, purpose, context);
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

/** A one- or two-file package with a dangerous capability has little else to be for. */
function tinyPackageBoost(capabilityFindings, context) {
  const { filesScanned } = context;
  if (!Number.isFinite(filesScanned) || filesScanned > TINY_PACKAGE_RULE.maxFilesScanned) return null;
  const dangerous = capabilityFindings.find((finding) => TINY_PACKAGE_RULE.families.includes(finding.family));
  if (!dangerous) return null;
  return {
    source: TINY_PACKAGE_RULE.id,
    points: TINY_PACKAGE_RULE.boost,
    reason: `${filesScanned} source file(s) and a ${dangerous.family} capability`,
  };
}

/** Which technique class the findings describe: install-time, import-time, or deferred to a method. */
function executionPatterns(capabilityFindings) {
  const runsDangerously = (finding, executedAt) =>
    finding.scope === 'module'
    && EXECUTABLE_FAMILIES.includes(finding.family)
    && (finding.executedAt ?? EXECUTED_AT.IMPORT_OR_RUNTIME) === executedAt;

  const patterns = [];
  if (capabilityFindings.some((finding) => runsDangerously(finding, EXECUTED_AT.INSTALL))) {
    patterns.push('install-time-execution');
  }
  if (capabilityFindings.some((finding) => runsDangerously(finding, EXECUTED_AT.IMPORT_OR_RUNTIME))) {
    patterns.push('import-time-execution');
  }
  const deferredToMethod = !patterns.includes('import-time-execution')
    && capabilityFindings.some((finding) => finding.scope === 'method' && EXECUTABLE_FAMILIES.includes(finding.family));
  if (deferredToMethod) patterns.push('deferred-runtime-trigger');
  return patterns;
}

/**
 * Scores one package from its static findings and lockfile findings.
 * @param {import('./capabilities.js').CapabilityFinding[]} capabilityFindings
 * @param {import('../resolve/lockfile-rules.js').LockfileFinding[]} lockfileFindings
 * @param {string} purpose  from inferPurpose()
 * @param {ScoringContext} [context]  from scoringContext()
 * @returns {{ score: number, contributions: ScoreContribution[], patterns: string[] }}
 */
export function scorePackage(capabilityFindings, lockfileFindings, purpose, context = {}) {
  const contributions = [];

  for (const [capability, { finding, points }] of bestFindingPerCapability(capabilityFindings, purpose, context)) {
    const reasonParts = [`${finding.scope} scope in ${finding.file}:${finding.line}`];
    if (purposeMultiplier(finding.family, purpose) > 1) reasonParts.push('purpose mismatch (pure-logic package)');
    if (toolMultiplier(finding, purpose, context) < 1) reasonParts.push(`declared-tool discount ×${DECLARED_TOOL_DISCOUNT.multiplier}`);
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

  const tiny = tinyPackageBoost(capabilityFindings, context);
  if (tiny) contributions.push(tiny);

  patterns.push(...executionPatterns(capabilityFindings));

  const total = contributions.reduce((sum, contribution) => sum + contribution.points, 0);
  return {
    score: Math.min(SCORE_CAP, Math.round(total)),
    contributions: contributions.sort((left, right) => right.points - left.points),
    patterns,
  };
}
