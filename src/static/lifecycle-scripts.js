import path from 'node:path';
import { EXECUTED_AT, INLINE_SCRIPT_PATTERN, SCAN_LIMITS, SCRIPT_COMMAND_RULES } from '../config/constants.js';
import { extractCapabilities } from './capabilities.js';
import { matchC2Indicators } from './indicators.js';
import { parseSource } from './parse.js';

export const LIFECYCLE_SCRIPT_NAMES = Object.freeze(['preinstall', 'install', 'postinstall']);

const SCRIPT_FILE_PATTERN = /[\w./-]+\.(?:c|m)?js/g;
const MANIFEST_FILE = 'package.json';
const MANIFEST_LINE = 1;

/** The lifecycle commands a manifest declares, as [{ name, command }]. */
export function lifecycleCommands(manifest) {
  const scripts = manifest?.scripts ?? {};
  return LIFECYCLE_SCRIPT_NAMES
    .filter((name) => typeof scripts[name] === 'string')
    .map((name) => ({ name, command: scripts[name] }));
}

export function hasLifecycleScript(manifest) {
  return lifecycleCommands(manifest).length > 0;
}

/**
 * The relative source files that a lifecycle script invokes. Code in these runs at install time
 * (and is blocked by npm v12 defaults), which is a different technique class from code that runs
 * when the package is imported, so the two are tracked separately.
 */
export function installScriptFiles(manifest) {
  const files = new Set();
  for (const { command } of lifecycleCommands(manifest)) {
    for (const match of command.matchAll(SCRIPT_FILE_PATTERN)) files.add(path.normalize(match[0]));
  }
  return files;
}

function excerpt(command) {
  return command.replace(/\s+/g, ' ').slice(0, SCAN_LIMITS.evidenceSnippetChars);
}

function commandFinding(capability, family, scriptName, command, extra = {}) {
  return {
    capability,
    family,
    file: MANIFEST_FILE,
    line: MANIFEST_LINE,
    scope: 'module',
    enclosing: `scripts.${scriptName}`,
    evidence: excerpt(command),
    executedAt: EXECUTED_AT.INSTALL,
    ...extra,
  };
}

/** Inline JavaScript passed with -e/--eval/-p/--print is analysed like a module-scope source file. */
function inlineScriptFindings(scriptName, command) {
  const match = INLINE_SCRIPT_PATTERN.exec(command);
  const source = match?.[1] ?? match?.[2];
  if (!source) return [];
  const ast = parseSource(source);
  if (!ast) return [];
  return extractCapabilities(ast, source, `${MANIFEST_FILE}#scripts.${scriptName}`)
    .map((finding) => ({ ...finding, executedAt: EXECUTED_AT.INSTALL }));
}

/**
 * Findings from the lifecycle script commands themselves. Everything here runs at install time,
 * at module scope, before any file in the package is imported. The static walk never sees these
 * commands otherwise, and 18 of the 64 misses in the first evaluation pass were exactly this shape.
 */
export function analyseLifecycleCommands(manifest) {
  const findings = [];
  for (const { name, command } of lifecycleCommands(manifest)) {
    for (const rule of SCRIPT_COMMAND_RULES) {
      if (rule.pattern.test(command)) findings.push(commandFinding(rule.id, rule.family, name, command));
    }
    for (const indicator of matchC2Indicators(command)) {
      findings.push(commandFinding('indicator.c2', 'indicator', name, command, { indicator }));
    }
    findings.push(...inlineScriptFindings(name, command));
  }
  return findings;
}
