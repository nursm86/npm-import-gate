import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { packageNameFromLockKey, readLockfile, toPackageNodes } from '../src/resolve/lockfile.js';
import { evaluateLockfileNode, isOfficialRegistryUrl } from '../src/resolve/lockfile-rules.js';

const FIXTURE_LOCKFILE = {
  name: 'testbed',
  lockfileVersion: 3,
  packages: {
    '': { name: 'testbed', version: '1.0.0', dependencies: { express: '^5.1.0' } },
    'node_modules/express': {
      version: '5.1.0',
      resolved: 'https://registry.npmjs.org/express/-/express-5.1.0.tgz',
      integrity: 'sha512-abc',
    },
    'node_modules/express/node_modules/debug': {
      version: '4.4.0',
      resolved: 'https://registry.npmjs.org/debug/-/debug-4.4.0.tgz',
      integrity: 'sha512-def',
    },
    'node_modules/@scope/native-thing': {
      version: '2.0.0',
      resolved: 'https://registry.npmjs.org/@scope/native-thing/-/native-thing-2.0.0.tgz',
      integrity: 'sha512-ghi',
      hasInstallScript: true,
    },
    'node_modules/orphan-helper': {
      version: '0.0.1',
      resolved: 'git+ssh://git@github.com/someone/orphan-helper.git#deadbeef',
      optional: true,
    },
  },
};

test('package names come from the last node_modules segment', () => {
  assert.equal(packageNameFromLockKey('node_modules/express'), 'express');
  assert.equal(packageNameFromLockKey('node_modules/express/node_modules/debug'), 'debug');
  assert.equal(packageNameFromLockKey('node_modules/@scope/native-thing'), '@scope/native-thing');
});

test('lockfile parses and flattens into package nodes, excluding the root', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'lockfile-test-'));
  await writeFile(path.join(dir, 'package-lock.json'), JSON.stringify(FIXTURE_LOCKFILE));
  const lockfile = await readLockfile(dir);
  const nodes = toPackageNodes(lockfile, dir);
  assert.equal(nodes.length, 4);
  assert.deepEqual(nodes.map((node) => node.name).sort(), ['@scope/native-thing', 'debug', 'express', 'orphan-helper']);
  assert.equal(nodes.find((node) => node.name === 'debug').dir, path.join(dir, 'node_modules/express/node_modules/debug'));
});

test('official registry detection', () => {
  assert.equal(isOfficialRegistryUrl('https://registry.npmjs.org/a/-/a-1.0.0.tgz'), true);
  assert.equal(isOfficialRegistryUrl('http://registry.npmjs.org/a/-/a-1.0.0.tgz'), false, 'plain http is not accepted');
  assert.equal(isOfficialRegistryUrl('git+https://github.com/x/y.git#abc'), false);
  assert.equal(isOfficialRegistryUrl('https://example.com/a.tgz'), false);
  assert.equal(isOfficialRegistryUrl(undefined), false);
  assert.equal(isOfficialRegistryUrl('https://npm.internal.example/a.tgz', ['npm.internal.example']), true);
});

test('lockfile rules flag git optional dependencies, missing integrity and lifecycle scripts', () => {
  const nodes = toPackageNodes(FIXTURE_LOCKFILE, '/tmp/x');
  const orphan = evaluateLockfileNode(nodes.find((node) => node.name === 'orphan-helper'));
  assert.deepEqual(orphan.map((finding) => finding.rule).sort(), [
    'lockfile.missing-integrity', 'lockfile.non-registry-source', 'lockfile.optional-non-registry',
  ]);
  const native = evaluateLockfileNode(nodes.find((node) => node.name === '@scope/native-thing'));
  assert.deepEqual(native.map((finding) => finding.rule), ['lockfile.lifecycle-script']);
  const express = evaluateLockfileNode(nodes.find((node) => node.name === 'express'));
  assert.equal(express.length, 0);
});
