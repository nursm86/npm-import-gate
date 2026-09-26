// Pure metric functions shared by the evaluation and baseline scripts. No I/O here so they can be
// unit tested. A "detection" is a positive prediction; how a tool marks positive is decided by the
// caller (for our gate, verdict !== 'pass').

/**
 * @typedef {object} Labelled
 * @property {string} name
 * @property {boolean} isMalicious   ground truth
 * @property {boolean} flagged       tool prediction
 * @property {string} [technique]    technique class for malicious samples
 */

export function confusionMatrix(rows) {
  const matrix = { tp: 0, fp: 0, tn: 0, fn: 0 };
  for (const row of rows) {
    if (row.isMalicious && row.flagged) matrix.tp += 1;
    else if (row.isMalicious && !row.flagged) matrix.fn += 1;
    else if (!row.isMalicious && row.flagged) matrix.fp += 1;
    else matrix.tn += 1;
  }
  return matrix;
}

const ratio = (numerator, denominator) => (denominator === 0 ? 0 : numerator / denominator);

export function scores(matrix) {
  const precision = ratio(matrix.tp, matrix.tp + matrix.fp);
  const recall = ratio(matrix.tp, matrix.tp + matrix.fn);
  const f1 = ratio(2 * precision * recall, precision + recall);
  const falsePositiveRate = ratio(matrix.fp, matrix.fp + matrix.tn);
  return { precision, recall, f1, falsePositiveRate };
}

export function evaluate(rows) {
  const matrix = confusionMatrix(rows);
  return { ...matrix, ...scores(matrix), total: rows.length };
}

/** Recall within each technique class (malicious rows only). */
export function recallByTechnique(rows) {
  const byTechnique = new Map();
  for (const row of rows) {
    if (!row.isMalicious) continue;
    const key = row.technique ?? 'unknown';
    const bucket = byTechnique.get(key) ?? { technique: key, total: 0, detected: 0 };
    bucket.total += 1;
    if (row.flagged) bucket.detected += 1;
    byTechnique.set(key, bucket);
  }
  return [...byTechnique.values()]
    .map((bucket) => ({ ...bucket, recall: ratio(bucket.detected, bucket.total) }))
    .sort((left, right) => left.technique.localeCompare(right.technique));
}

export function asPercent(value) {
  return `${(value * 100).toFixed(1)}%`;
}
