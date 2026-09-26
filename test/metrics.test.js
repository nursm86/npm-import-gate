import assert from 'node:assert/strict';
import { test } from 'node:test';
import { confusionMatrix, evaluate, recallByTechnique, scores } from '../evaluation/lib/metrics.mjs';

const rows = [
  { name: 'm1', isMalicious: true, flagged: true, technique: 'import-time' },
  { name: 'm2', isMalicious: true, flagged: true, technique: 'import-time' },
  { name: 'm3', isMalicious: true, flagged: false, technique: 'deferred' },
  { name: 'b1', isMalicious: false, flagged: false },
  { name: 'b2', isMalicious: false, flagged: true },
  { name: 'b3', isMalicious: false, flagged: false },
];

test('confusion matrix counts each quadrant', () => {
  assert.deepEqual(confusionMatrix(rows), { tp: 2, fp: 1, tn: 2, fn: 1 });
});

test('precision, recall, F1 and FP rate are computed from the matrix', () => {
  const result = scores({ tp: 2, fp: 1, tn: 2, fn: 1 });
  assert.equal(result.precision.toFixed(3), (2 / 3).toFixed(3));
  assert.equal(result.recall.toFixed(3), (2 / 3).toFixed(3));
  assert.equal(result.f1.toFixed(3), (2 / 3).toFixed(3));
  assert.equal(result.falsePositiveRate.toFixed(3), (1 / 3).toFixed(3));
});

test('evaluate merges matrix, scores and total', () => {
  const result = evaluate(rows);
  assert.equal(result.total, 6);
  assert.equal(result.tp, 2);
  assert.ok(result.f1 > 0 && result.f1 <= 1);
});

test('empty denominators yield zero, never NaN', () => {
  const result = scores({ tp: 0, fp: 0, tn: 5, fn: 0 });
  assert.equal(result.precision, 0);
  assert.equal(result.recall, 0);
  assert.equal(result.f1, 0);
  assert.equal(result.falsePositiveRate, 0);
});

test('recall by technique groups malicious rows only', () => {
  const byTechnique = recallByTechnique(rows);
  assert.deepEqual(byTechnique.map((bucket) => bucket.technique), ['deferred', 'import-time']);
  assert.equal(byTechnique.find((bucket) => bucket.technique === 'import-time').recall, 1);
  assert.equal(byTechnique.find((bucket) => bucket.technique === 'deferred').recall, 0);
});
