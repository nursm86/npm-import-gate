import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DYNAMIC_SANDBOX } from '../config/constants.js';
import { logger } from '../util/logger.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const HOOK_FILE = path.join(HERE, 'preload-hook.cjs');
const RUNNER_FILE = path.join(HERE, 'runner.cjs');
const RESULT_SENTINEL = '__IMPORT_GATE_RESULT__';
const SCRATCH_DIR = 'scratch';

const DYNAMIC_WEIGHTS = Object.freeze({
  attemptedNetwork: 30,
  attemptedSpawn: 30,
  attemptedSensitiveRead: 30,
  attemptedEnvEnumeration: 25,
  attemptedWrite: 5,
  permissionDenial: 15,
});

const OUTCOME = Object.freeze({
  COMPLETED: 'completed',
  TIMED_OUT: 'timed-out',
  CRASHED: 'crashed',
  UNAVAILABLE: 'unavailable',
});

function dockerArguments(packageDir, entryPoint) {
  const mount = DYNAMIC_SANDBOX.mountPoint;
  return [
    'run', '--rm',
    '--network', 'none',
    '--read-only',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--memory', DYNAMIC_SANDBOX.memoryLimit,
    '--cpus', DYNAMIC_SANDBOX.cpuLimit,
    '--pids-limit', String(DYNAMIC_SANDBOX.pidsLimit),
    '--tmpfs', `${mount}/${SCRATCH_DIR}:rw,size=64m`,
    '-v', `${packageDir}:${mount}/pkg:ro`,
    '-v', `${HOOK_FILE}:${mount}/preload-hook.cjs:ro`,
    '-v', `${RUNNER_FILE}:${mount}/runner.cjs:ro`,
    '-e', `SANDBOX_ENTRY=${entryPoint}`,
    '-e', `SANDBOX_TIMEOUT_MS=${DYNAMIC_SANDBOX.timeoutSeconds * 1000}`,
    '-w', `${mount}/pkg`,
    DYNAMIC_SANDBOX.image,
    'node',
    '--permission',
    `--allow-fs-read=${mount}`,
    `--allow-fs-write=${mount}/${SCRATCH_DIR}`,
    '--require', `${mount}/preload-hook.cjs`,
    `${mount}/runner.cjs`,
  ];
}

function runDocker(args, timeoutMs) {
  return new Promise((resolve) => {
    const child = spawn('docker', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, stdout, stderr });
    });
    child.on('error', (error) => {
      clearTimeout(timer);
      resolve({ code: null, signal: null, stdout, stderr: error.message });
    });
  });
}

/** Pulls the sentinel-prefixed JSON result line out of the container's stdout. */
function parseResultFromStdout(stdout) {
  const line = stdout.split('\n').reverse().find((candidate) => candidate.startsWith(RESULT_SENTINEL));
  if (!line) return null;
  try {
    return JSON.parse(line.slice(RESULT_SENTINEL.length));
  } catch {
    return null;
  }
}

function entryPointOf(manifest) {
  if (typeof manifest.exports === 'string') return manifest.exports;
  if (manifest.exports && typeof manifest.exports === 'object') {
    const root = manifest.exports['.'] ?? manifest.exports;
    if (typeof root === 'string') return root;
    if (root && typeof root === 'object') return root.require ?? root.default ?? root.import ?? 'index.js';
  }
  return manifest.main ?? 'index.js';
}

function scoreDynamic(result) {
  const contributions = [];
  const patterns = [];
  const attemptsByKind = Map.groupBy(result.attempts, (attempt) => attempt.kind);
  const add = (kind, weight, reason) => {
    const attempts = attemptsByKind.get(kind);
    if (!attempts?.length) return;
    contributions.push({ source: `dynamic.${kind}`, points: weight, reason: `${attempts.length}× ${reason} during import: ${attempts[0].detail}` });
  };
  add('network', DYNAMIC_WEIGHTS.attemptedNetwork, 'outbound connection attempted');
  add('spawn', DYNAMIC_WEIGHTS.attemptedSpawn, 'child process attempted');
  add('sensitive-read', DYNAMIC_WEIGHTS.attemptedSensitiveRead, 'credential file read attempted');
  add('env-enumerate', DYNAMIC_WEIGHTS.attemptedEnvEnumeration, 'environment enumerated');
  add('write', DYNAMIC_WEIGHTS.attemptedWrite, 'file write attempted');
  if (result.permissionDenials.length) {
    contributions.push({
      source: 'dynamic.permission-denied',
      points: DYNAMIC_WEIGHTS.permissionDenial,
      reason: `Node permission model denied ${result.permissionDenials.length} operation(s): ${result.permissionDenials[0]}`,
    });
  }
  if (attemptsByKind.has('network') || attemptsByKind.has('spawn')) patterns.push('import-time-behaviour-observed');
  const scoreDelta = contributions.reduce((sum, contribution) => sum + contribution.points, 0);
  return { contributions, patterns, scoreDelta };
}

/**
 * Imports the package inside a locked-down container and records what it tries to do.
 * Two independent sensors: the preload hook (intent) and Node's permission model (enforcement).
 * The container has no network and a read-only filesystem, so nothing can actually leave.
 */
export async function runDynamicAnalysis(node, manifest) {
  const entryPoint = entryPointOf(manifest);
  const args = dockerArguments(node.dir, entryPoint);
  const killAfterMs = (DYNAMIC_SANDBOX.timeoutSeconds + 15) * 1000;

  let result = { attempts: [], permissionDenials: [], outcome: OUTCOME.UNAVAILABLE, entryPoint, error: null };
  const { code, signal, stdout, stderr } = await runDocker(args, killAfterMs);
  const parsed = parseResultFromStdout(stdout);
  if (parsed) {
    result = { ...result, ...parsed };
  } else {
    result.outcome = signal ? OUTCOME.TIMED_OUT : OUTCOME.CRASHED;
    result.error = stderr.trim().split('\n').slice(-3).join(' | ');
    logger.warn({ name: node.name, code, signal, error: result.error }, 'sandbox produced no result');
  }

  const scored = scoreDynamic(result);
  return { ...result, ...scored };
}
