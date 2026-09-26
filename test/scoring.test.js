import assert from 'node:assert/strict';
import { test } from 'node:test';
import { DEFAULT_THRESHOLDS } from '../src/config/constants.js';
import { PURPOSE, inferPurpose } from '../src/static/purpose.js';
import { scorePackage } from '../src/static/scoring.js';
import { verdictFor } from '../src/score/aggregate.js';

const finding = (capability, family, scope, extra = {}) => ({
  capability, family, scope, file: 'index.js', line: 1, enclosing: scope, evidence: '', ...extra,
});

test('a module-scope detached spawn with a C2 indicator fails the gate', () => {
  const findings = [
    finding('process.spawn', 'process', 'module'),
    finding('process.detached', 'process', 'module'),
    finding('net.outbound', 'net', 'module'),
    finding('indicator.c2', 'indicator', 'module', { indicator: 'ipfs' }),
  ];
  const { score, patterns } = scorePackage(findings, [], PURPOSE.UNKNOWN);
  assert.equal(verdictFor(score, DEFAULT_THRESHOLDS), 'fail');
  assert.ok(patterns.includes('import-time-execution'));
  assert.ok(patterns.includes('detached-loader-pattern'));
});

test('a pure-logic package that beacons from a method fails through purpose mismatch and pattern boost', () => {
  const findings = [
    finding('net.outbound', 'net', 'method'),
    finding('os.fingerprint', 'os', 'method'),
    finding('indicator.c2', 'indicator', 'method', { indicator: 'telegram' }),
  ];
  const { score, patterns } = scorePackage(findings, [], PURPOSE.PURE);
  assert.equal(verdictFor(score, DEFAULT_THRESHOLDS), 'fail');
  assert.ok(patterns.includes('beacon-pattern'));
  assert.ok(!patterns.includes('import-time-execution'), 'method-scope code does not run on import');
});

test('a legitimate HTTP client used inside functions stays below the fail threshold', () => {
  const findings = [
    finding('net.outbound', 'net', 'function'),
    finding('dns.lookup', 'dns', 'function'),
  ];
  const { score } = scorePackage(findings, [], PURPOSE.TOOL);
  assert.ok(score < DEFAULT_THRESHOLDS.fail, `score ${score} should not fail`);
});

test('each capability counts once at its highest-context occurrence', () => {
  const many = Array.from({ length: 40 }, () => finding('net.outbound', 'net', 'function'));
  const { score: manyScore } = scorePackage(many, [], PURPOSE.TOOL);
  const { score: oneScore } = scorePackage([finding('net.outbound', 'net', 'function')], [], PURPOSE.TOOL);
  assert.equal(manyScore, oneScore);
});

test('lockfile findings add to the score without any source findings', () => {
  const lockfileFindings = [
    { rule: 'lockfile.non-registry-source', weight: 40, detail: 'git+https://…' },
    { rule: 'lockfile.optional-non-registry', weight: 30, detail: 'optional' },
  ];
  const { score } = scorePackage([], lockfileFindings, PURPOSE.UNKNOWN);
  assert.equal(verdictFor(score, DEFAULT_THRESHOLDS), 'fail');
});

test('score is capped at 100', () => {
  const findings = Object.keys({
    'process.spawn': 1, 'net.outbound': 1, 'code.dynamic': 1, 'env.enumerate': 1, 'indicator.c2': 1, 'fs.read-sensitive': 1,
  }).map((capability) => finding(capability, capability.split('.')[0], 'module'));
  assert.equal(scorePackage(findings, [], PURPOSE.PURE).score, 100);
});

test('purpose inference reads the manifest', () => {
  assert.equal(inferPurpose({ name: 'indexed-btree', description: 'A sorted B-tree', keywords: ['btree'] }), PURPOSE.PURE);
  assert.equal(inferPurpose({ name: 'axios', description: 'Promise based HTTP client' }), PURPOSE.TOOL);
  assert.equal(inferPurpose({ name: 'left-pad' }), PURPOSE.UNKNOWN);
});
