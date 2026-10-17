import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { ProjectConfigSchema, allowancesFromNames, findAllowance, readProjectAllowList } from '../src/config/allow-list.js';
import { isAllowedException, summarise } from '../src/score/aggregate.js';

const result = (name, verdict, allowance) => ({ name, verdict, score: 0, allowance });

test('an allowance needs a name and a reason of substance', () => {
  assert.ok(ProjectConfigSchema.safeParse({ allow: [{ name: 'real-require', reason: 'dynamic import shim for bundlers, reviewed' }] }).success);
  assert.equal(ProjectConfigSchema.safeParse({ allow: [{ name: 'real-require' }] }).success, false);
  assert.equal(ProjectConfigSchema.safeParse({ allow: [{ name: 'real-require', reason: 'ok' }] }).success, false);
  assert.equal(ProjectConfigSchema.safeParse({ allowed: [] }).success, false, 'unknown keys are rejected so typos surface');
});

test('allowed packages are reported but do not fail the project', () => {
  const packages = [
    result('real-require', 'fail', { name: 'real-require', reason: 'dynamic import shim for bundlers, reviewed' }),
    result('express', 'pass', undefined),
    result('debug', 'warn', undefined),
  ];
  const summary = summarise(packages);
  assert.equal(summary.overall, 'warn');
  assert.deepEqual(summary.counts, { pass: 1, warn: 1, fail: 0, allowed: 1 });
  assert.ok(isAllowedException(packages[0]));
});

test('an allowance on a package that passes anyway counts as a pass', () => {
  const summary = summarise([result('lodash', 'pass', { name: 'lodash', reason: 'kept for the day it needs it' })]);
  assert.deepEqual(summary.counts, { pass: 1, warn: 0, fail: 0, allowed: 0 });
  assert.equal(summary.overall, 'pass');
});

test('the project allow-list comes from package.json and is empty when absent', async () => {
  const emptyDir = await mkdtemp(path.join(os.tmpdir(), 'import-gate-empty-'));
  assert.deepEqual(await readProjectAllowList(emptyDir), []);

  const projectDir = await mkdtemp(path.join(os.tmpdir(), 'import-gate-project-'));
  await writeFile(path.join(projectDir, 'package.json'), JSON.stringify({
    name: 'demo',
    importGate: { allow: [{ name: 'real-require', reason: 'dynamic import shim for bundlers, reviewed' }] },
  }));
  const allowList = await readProjectAllowList(projectDir);
  assert.equal(allowList.length, 1);
  assert.equal(findAllowance(allowList, 'real-require').name, 'real-require');
  assert.equal(findAllowance(allowList, 'express'), undefined);
});

test('command-line names become allowances with a standard reason', () => {
  const [allowance] = allowancesFromNames(['esbuild']);
  assert.equal(allowance.name, 'esbuild');
  assert.ok(allowance.reason.length > 0);
});
