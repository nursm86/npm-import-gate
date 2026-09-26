'use strict';
/**
 * Runs inside the sandbox before the package under test, via `node --require`.
 * It wraps the APIs a malicious import would reach for and records every attempt.
 * It does not try to be unbypassable: the container (no network, read-only, dropped
 * capabilities) and Node's permission model are the enforcement; this file records intent.
 */
const childProcess = require('node:child_process');
const dns = require('node:dns');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const tls = require('node:tls');

const SENSITIVE_PATH_PATTERN = /\.ssh|\.npmrc|\.git-credentials|\.aws|\.docker\/config|\.kube|id_rsa|id_ed25519|\/etc\/passwd/i;
const MAX_ATTEMPTS = 500;
const attempts = [];

function describe(value) {
  try {
    if (typeof value === 'string') return value.slice(0, 200);
    if (value && typeof value === 'object') return JSON.stringify(value).slice(0, 200);
    return String(value);
  } catch {
    return '[unprintable]';
  }
}

function recordAttempt(kind, detail) {
  if (attempts.length >= MAX_ATTEMPTS) return;
  attempts.push({ kind, detail: describe(detail), at: Date.now() });
}

function wrap(target, methodName, kind, detailFrom) {
  const original = target[methodName];
  if (typeof original !== 'function') return;
  target[methodName] = function wrapped(...args) {
    recordAttempt(kind, detailFrom(args));
    return original.apply(this, args);
  };
}

const firstArgument = (args) => args[0];
const commandLine = (args) => [args[0], ...(Array.isArray(args[1]) ? args[1] : [])].join(' ');

for (const method of ['exec', 'execSync', 'spawn', 'spawnSync', 'fork', 'execFile', 'execFileSync']) {
  wrap(childProcess, method, 'spawn', commandLine);
}
for (const method of ['request', 'get']) {
  wrap(http, method, 'network', firstArgument);
  wrap(https, method, 'network', firstArgument);
}
wrap(net.Socket.prototype, 'connect', 'network', firstArgument);
wrap(net, 'createConnection', 'network', firstArgument);
wrap(tls, 'connect', 'network', firstArgument);
for (const method of ['lookup', 'resolve', 'resolve4', 'resolve6', 'resolveTxt', 'resolveAny']) {
  wrap(dns, method, 'network', firstArgument);
}
if (dns.promises) {
  for (const method of ['lookup', 'resolve', 'resolve4', 'resolve6', 'resolveTxt']) {
    wrap(dns.promises, method, 'network', firstArgument);
  }
}
if (typeof globalThis.fetch === 'function') {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = function wrappedFetch(...args) {
    recordAttempt('network', args[0]);
    return originalFetch.apply(this, args);
  };
}
for (const method of ['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream', 'mkdir', 'mkdirSync', 'chmod', 'chmodSync']) {
  wrap(fs, method, 'write', firstArgument);
}
for (const method of ['readFile', 'readFileSync', 'createReadStream']) {
  const original = fs[method];
  if (typeof original !== 'function') continue;
  fs[method] = function wrappedRead(...args) {
    const target = describe(args[0]);
    if (SENSITIVE_PATH_PATTERN.test(target)) recordAttempt('sensitive-read', target);
    return original.apply(this, args);
  };
}

const realEnv = process.env;
process.env = new Proxy(realEnv, {
  ownKeys(target) {
    recordAttempt('env-enumerate', 'ownKeys(process.env)');
    return Reflect.ownKeys(target);
  },
  get(target, property, receiver) {
    if (typeof property === 'string' && /TOKEN|SECRET|PASSWORD|KEY|AWS_|NPM_|GITHUB_/i.test(property)) {
      recordAttempt('env-sensitive', property);
    }
    return Reflect.get(target, property, receiver);
  },
});

globalThis.__importGateAttempts = attempts;
