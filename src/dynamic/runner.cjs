'use strict';
/**
 * Runs inside the sandbox. Imports the package entry point exactly as an application would,
 * waits briefly for asynchronous side effects, then emits what the preload hook observed as a
 * single JSON line on stdout, prefixed with a sentinel. The host reads it from stdout, so no
 * writable mount is needed (bind-mount write-back is unreliable across Docker backends).
 */
const path = require('node:path');

const RESULT_SENTINEL = '__IMPORT_GATE_RESULT__';
const PACKAGE_DIR = process.cwd();
const ENTRY = process.env.SANDBOX_ENTRY || 'index.js';
const TIMEOUT_MS = Number(process.env.SANDBOX_TIMEOUT_MS || 30000);
const SETTLE_MS = 1500;
const PERMISSION_ERROR_CODE = 'ERR_ACCESS_DENIED';

const permissionDenials = [];
let outcome = 'completed';
let errorMessage = null;
let emitted = false;

function noteError(error) {
  if (error && error.code === PERMISSION_ERROR_CODE) {
    permissionDenials.push(`${error.permission || 'unknown'}: ${error.resource || error.message}`);
    return;
  }
  errorMessage = error && error.message ? error.message.slice(0, 300) : String(error);
}

process.on('uncaughtException', noteError);
process.on('unhandledRejection', noteError);

function emitResult() {
  if (emitted) return;
  emitted = true;
  const result = {
    entryPoint: ENTRY,
    outcome,
    error: errorMessage,
    permissionDenials,
    attempts: globalThis.__importGateAttempts || [],
  };
  process.stdout.write(`\n${RESULT_SENTINEL}${JSON.stringify(result)}\n`);
}

const hardStop = setTimeout(() => {
  outcome = 'timed-out';
  emitResult();
  process.exit(0);
}, TIMEOUT_MS);

async function importEntry() {
  const entryPath = path.resolve(PACKAGE_DIR, ENTRY);
  try {
    require(entryPath);
  } catch (requireError) {
    if (requireError && requireError.code === 'ERR_REQUIRE_ESM') {
      await import(entryPath);
    } else {
      throw requireError;
    }
  }
}

importEntry()
  .catch(noteError)
  .finally(() => {
    // Referenced timer: keep the loop alive through the settle window so async side effects are seen.
    setTimeout(() => {
      clearTimeout(hardStop);
      emitResult();
      process.exit(0);
    }, SETTLE_MS);
  });
