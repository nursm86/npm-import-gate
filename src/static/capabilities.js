import {
  DNS_CALLS,
  FS_READ_CALLS,
  FS_WRITE_CALLS,
  MIN_OS_FINGERPRINT_CALLS,
  MODULE_FAMILIES,
  NET_CALLS,
  OS_FINGERPRINT_CALLS,
  PROCESS_CALLS,
  SCAN_LIMITS,
  SENSITIVE_ENV_PATTERN,
  SENSITIVE_PATH_PATTERN,
  SHELL_DOWNLOAD_PATTERN,
  VM_CALLS,
} from '../config/constants.js';
import { hasObfuscatedIdentifiers, isHighEntropyString, matchC2Indicators } from './indicators.js';
import { memberExpressionText, walk } from './walk.js';

const NODE_PREFIX = 'node:';
const BASE64_ENCODINGS = new Set(['base64', 'base64url', 'hex']);

/**
 * @typedef {object} CapabilityFinding
 * @property {string} capability   e.g. "process.spawn"
 * @property {string} family       e.g. "process"
 * @property {string} file         path relative to the package root
 * @property {number} line
 * @property {'module'|'function'|'method'} scope
 * @property {string} enclosing    name of the enclosing function or method
 * @property {string} evidence     short source excerpt
 * @property {string} [indicator]  matched indicator id for indicator.c2
 */

function normaliseModuleName(specifier) {
  return specifier.startsWith(NODE_PREFIX) ? specifier.slice(NODE_PREFIX.length) : specifier;
}

function familyOf(specifier) {
  return MODULE_FAMILIES[normaliseModuleName(specifier)] ?? null;
}

function literalString(node) {
  if (!node) return null;
  if (node.type === 'StringLiteral') return node.value;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return node.quasis.map((quasi) => quasi.value.cooked ?? '').join('');
  }
  return null;
}

function isRequireCall(node) {
  return node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'require';
}

function propertyName(node) {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'StringLiteral') return node.value;
  return null;
}

function hasDetachedTrue(objectExpression) {
  if (objectExpression?.type !== 'ObjectExpression') return false;
  return objectExpression.properties.some(
    (property) => property.type === 'ObjectProperty'
      && propertyName(property.key) === 'detached'
      && property.value.type === 'BooleanLiteral'
      && property.value.value === true,
  );
}

/**
 * Tracks which local names refer to sensitive modules within one file.
 * `const cp = require('child_process')` binds cp -> process family;
 * `const { exec } = require('child_process')` binds exec -> process family with member exec.
 */
class BindingTable {
  constructor() {
    /** @type {Map<string, {family: string, member: string|null}>} */
    this.bindings = new Map();
  }

  bindDeclarator(declarator, family) {
    const { id } = declarator;
    if (id.type === 'Identifier') {
      this.bindings.set(id.name, { family, member: null });
    } else if (id.type === 'ObjectPattern') {
      for (const property of id.properties) {
        if (property.type !== 'ObjectProperty' || property.value.type !== 'Identifier') continue;
        this.bindings.set(property.value.name, { family, member: propertyName(property.key) });
      }
    }
  }

  bindImport(importDeclaration, family) {
    for (const specifier of importDeclaration.specifiers) {
      const member = specifier.type === 'ImportSpecifier' ? propertyName(specifier.imported) : null;
      this.bindings.set(specifier.local.name, { family, member });
    }
  }

  /** Resolves a call target like `cp.exec`, `exec`, or `child_process.default.spawn`. */
  resolveCallee(callee) {
    if (callee.type === 'Identifier') {
      const binding = this.bindings.get(callee.name);
      if (!binding) return null;
      return { family: binding.family, member: binding.member ?? callee.name };
    }
    if (callee.type === 'MemberExpression') {
      let objectNode = callee.object;
      while (objectNode.type === 'MemberExpression' && objectNode.property?.name === 'default') {
        objectNode = objectNode.object;
      }
      if (objectNode.type === 'Identifier') {
        const binding = this.bindings.get(objectNode.name);
        if (binding) return { family: binding.family, member: propertyName(callee.property) };
      }
      if (isRequireCall(objectNode)) {
        const family = familyOf(literalString(objectNode.arguments[0]) ?? '');
        if (family) return { family, member: propertyName(callee.property) };
      }
    }
    return null;
  }

  isBound(name) {
    return this.bindings.has(name);
  }
}

/**
 * Extracts capability findings from one parsed file.
 * @param {object} ast            Babel File node
 * @param {string} sourceText
 * @param {string} relativePath
 * @returns {CapabilityFinding[]}
 */
export function extractCapabilities(ast, sourceText, relativePath) {
  const findings = [];
  const bindings = new BindingTable();
  const osCallsSeen = new Set();
  const lines = sourceText.split('\n');

  const evidenceAt = (node) => {
    const line = node.loc?.start.line ?? 0;
    const text = (lines[line - 1] ?? '').trim();
    return { line, evidence: text.slice(0, SCAN_LIMITS.evidenceSnippetChars) };
  };

  const record = (capability, family, node, context, extra = {}) => {
    findings.push({
      capability,
      family,
      file: relativePath,
      scope: context.scope.kind,
      enclosing: context.scope.name,
      ...evidenceAt(node),
      ...extra,
    });
  };

  const inspectStringLiteral = (value, node, context) => {
    for (const indicator of matchC2Indicators(value)) {
      record('indicator.c2', 'indicator', node, context, { indicator });
    }
    if (isHighEntropyString(value)) {
      record('obfuscation.high-entropy', 'obfuscation', node, context);
    }
  };

  const inspectCall = (node, context) => {
    const { callee } = node;
    const firstArgumentText = literalString(node.arguments[0]);

    if (isRequireCall(node)) {
      if (firstArgumentText === null) record('require.dynamic', 'code', node, context);
      return;
    }
    if (callee.type === 'Import') {
      if (literalString(node.arguments[0]) === null) record('require.dynamic', 'code', node, context);
      return;
    }
    if (callee.type === 'Identifier') {
      if (callee.name === 'eval') record('code.dynamic', 'code', node, context);
      if (callee.name === 'atob') record('decode.base64', 'decode', node, context);
      if (callee.name === 'fetch' && !bindings.isBound('fetch')) record('net.outbound', 'net', node, context);
    }
    if (callee.type === 'MemberExpression' && !callee.computed) {
      const objectText = memberExpressionText(callee.object);
      const member = propertyName(callee.property);
      if (objectText === 'Buffer' && member === 'from') {
        const encoding = literalString(node.arguments[1]);
        if (encoding && BASE64_ENCODINGS.has(encoding)) record('decode.base64', 'decode', node, context);
      }
      if (objectText === 'globalThis' && member === 'fetch') record('net.outbound', 'net', node, context);
      if (objectText === 'process' && member === 'binding') record('code.dynamic', 'code', node, context);
    }

    const resolved = bindings.resolveCallee(callee);
    if (!resolved) return;
    const { family, member } = resolved;

    if (family === 'process' && PROCESS_CALLS.includes(member)) {
      record('process.spawn', 'process', node, context);
      if (node.arguments.some(hasDetachedTrue)) record('process.detached', 'process', node, context);
      if (firstArgumentText && SHELL_DOWNLOAD_PATTERN.test(firstArgumentText)) {
        record('process.shell-download', 'process', node, context);
      }
    } else if (family === 'net' && (NET_CALLS.includes(member) || member === null || member === callee.name)) {
      record('net.outbound', 'net', node, context);
    } else if (family === 'dns' && DNS_CALLS.includes(member)) {
      record('dns.lookup', 'dns', node, context);
    } else if (family === 'fs' && FS_WRITE_CALLS.includes(member)) {
      const sensitive = firstArgumentText && SENSITIVE_PATH_PATTERN.test(firstArgumentText);
      record(sensitive ? 'fs.write-sensitive' : 'fs.write', 'fs', node, context);
    } else if (family === 'fs' && FS_READ_CALLS.includes(member)) {
      if (firstArgumentText && SENSITIVE_PATH_PATTERN.test(firstArgumentText)) {
        record('fs.read-sensitive', 'fs', node, context);
      }
    } else if (family === 'vm' && VM_CALLS.includes(member)) {
      record('code.dynamic', 'code', node, context);
    } else if (family === 'os' && OS_FINGERPRINT_CALLS.includes(member)) {
      osCallsSeen.add(member);
      if (osCallsSeen.size === MIN_OS_FINGERPRINT_CALLS) record('os.fingerprint', 'os', node, context);
    } else if (family === 'worker') {
      record('worker.spawn', 'process', node, context);
    }
  };

  const inspectNew = (node, context) => {
    const resolved = bindings.resolveCallee(node.callee);
    if (!resolved) {
      if (node.callee.type === 'Identifier' && node.callee.name === 'Function') record('code.dynamic', 'code', node, context);
      return;
    }
    if (resolved.family === 'vm' && VM_CALLS.includes(resolved.member)) record('code.dynamic', 'code', node, context);
    if (resolved.family === 'net') record('net.outbound', 'net', node, context);
    if (resolved.family === 'worker') record('worker.spawn', 'process', node, context);
  };

  const inspectMember = (node, context, parent) => {
    if (memberExpressionText(node.object) !== 'process' || propertyName(node.property) !== 'env') return;
    const parentReadsWholeObject = !(parent?.type === 'MemberExpression' && parent.object === node);
    if (parentReadsWholeObject) {
      const isSpreadOrArgument = parent?.type === 'SpreadElement' || parent?.type === 'CallExpression'
        || parent?.type === 'VariableDeclarator' || parent?.type === 'AssignmentExpression'
        || parent?.type === 'ObjectProperty' || parent?.type === 'ArrayExpression' || parent?.type === 'ReturnStatement';
      if (isSpreadOrArgument) record('env.enumerate', 'env', node, context);
      return;
    }
    const key = parent.computed ? literalString(parent.property) : propertyName(parent.property);
    if (key && SENSITIVE_ENV_PATTERN.test(key)) record('env.sensitive', 'env', node, context);
  };

  walk(ast, (node, context) => {
    switch (node.type) {
      case 'ImportDeclaration': {
        const family = familyOf(node.source.value);
        if (family) bindings.bindImport(node, family);
        break;
      }
      case 'VariableDeclarator': {
        const init = node.init;
        if (init && isRequireCall(init)) {
          const family = familyOf(literalString(init.arguments[0]) ?? '');
          if (family) bindings.bindDeclarator(node, family);
        } else if (init?.type === 'AwaitExpression' && init.argument?.type === 'CallExpression' && init.argument.callee.type === 'Import') {
          const family = familyOf(literalString(init.argument.arguments[0]) ?? '');
          if (family) bindings.bindDeclarator(node, family);
        }
        break;
      }
      case 'CallExpression':
        inspectCall(node, context);
        break;
      case 'NewExpression':
        inspectNew(node, context);
        break;
      case 'MemberExpression':
        inspectMember(node, context, context.parent);
        break;
      case 'StringLiteral':
        inspectStringLiteral(node.value, node, context);
        break;
      case 'TemplateLiteral':
        for (const quasi of node.quasis) {
          const text = quasi.value.cooked ?? quasi.value.raw ?? '';
          if (text) inspectStringLiteral(text, node, context);
        }
        break;
      default:
        break;
    }
  });

  if (hasObfuscatedIdentifiers(sourceText)) {
    findings.push({
      capability: 'obfuscation.identifiers',
      family: 'obfuscation',
      file: relativePath,
      line: 1,
      scope: 'module',
      enclosing: '<file>',
      evidence: 'identifiers renamed to _0x… style',
    });
  }

  return findings;
}
