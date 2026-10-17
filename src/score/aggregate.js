import { DEFAULT_THRESHOLDS, VERDICT } from '../config/constants.js';

export function verdictFor(score, thresholds = DEFAULT_THRESHOLDS) {
  if (score >= thresholds.fail) return VERDICT.FAIL;
  if (score >= thresholds.warn) return VERDICT.WARN;
  return VERDICT.PASS;
}

/**
 * @typedef {object} PackageResult
 * @property {string} name
 * @property {string} version
 * @property {string} lockKey
 * @property {string} purpose
 * @property {number} score
 * @property {string} verdict
 * @property {string[]} patterns
 * @property {object[]} contributions
 * @property {object[]} findings
 * @property {object[]} lockfileFindings
 * @property {object} [dynamic]
 * @property {object} stats
 */

/** An allowed package that still trips a threshold is reported but does not count against the project. */
export function isAllowedException(result) {
  return Boolean(result.allowance) && result.verdict !== VERDICT.PASS;
}

export function summarise(packageResults, thresholds = DEFAULT_THRESHOLDS) {
  const counts = { [VERDICT.PASS]: 0, [VERDICT.WARN]: 0, [VERDICT.FAIL]: 0, allowed: 0 };
  for (const result of packageResults) {
    if (isAllowedException(result)) counts.allowed += 1;
    else counts[result.verdict] += 1;
  }
  const overall = counts[VERDICT.FAIL] > 0 ? VERDICT.FAIL : counts[VERDICT.WARN] > 0 ? VERDICT.WARN : VERDICT.PASS;
  return { overall, counts, thresholds, packagesScanned: packageResults.length };
}
