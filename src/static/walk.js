const FUNCTION_NODE_TYPES = new Set([
  'FunctionDeclaration',
  'FunctionExpression',
  'ArrowFunctionExpression',
  'ObjectMethod',
  'ClassMethod',
  'ClassPrivateMethod',
]);

const SCOPE_KIND = Object.freeze({
  MODULE: 'module',
  IIFE: 'iife',
  FUNCTION: 'function',
  METHOD: 'method',
});

const SKIPPED_KEYS = new Set(['loc', 'start', 'end', 'extra', 'leadingComments', 'trailingComments', 'innerComments']);

function isImmediatelyInvoked(node, parent) {
  return parent?.type === 'CallExpression' && parent.callee === node;
}

function isPrototypeAssignment(parent) {
  if (parent?.type !== 'AssignmentExpression' || parent.left?.type !== 'MemberExpression') return false;
  const target = parent.left.object;
  return target?.type === 'MemberExpression' && target.property?.name === 'prototype';
}

function memberExpressionText(node) {
  if (!node) return '';
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'ThisExpression') return 'this';
  if (node.type === 'MemberExpression') {
    const property = node.computed ? '[…]' : node.property?.name ?? '';
    return `${memberExpressionText(node.object)}.${property}`;
  }
  return '';
}

function describeFunction(node, parent) {
  if (node.type === 'ClassMethod' || node.type === 'ClassPrivateMethod' || node.type === 'ObjectMethod') {
    return { kind: SCOPE_KIND.METHOD, name: node.key?.name ?? node.key?.id?.name ?? 'method' };
  }
  if (isPrototypeAssignment(parent)) {
    return { kind: SCOPE_KIND.METHOD, name: memberExpressionText(parent.left) };
  }
  if (node.type === 'FunctionDeclaration' && node.id) {
    return { kind: SCOPE_KIND.FUNCTION, name: node.id.name };
  }
  if (parent?.type === 'VariableDeclarator' && parent.id?.type === 'Identifier') {
    return { kind: SCOPE_KIND.FUNCTION, name: parent.id.name };
  }
  if (parent?.type === 'ObjectProperty' && parent.key?.name) {
    return { kind: SCOPE_KIND.FUNCTION, name: parent.key.name };
  }
  if (parent?.type === 'AssignmentExpression') {
    return { kind: SCOPE_KIND.FUNCTION, name: memberExpressionText(parent.left) || 'anonymous' };
  }
  return { kind: SCOPE_KIND.FUNCTION, name: 'anonymous' };
}

/**
 * The scope that matters for scoring: code at module level or inside an immediately invoked
 * function runs the moment the file is imported; code inside a method only runs when the
 * consuming application calls it.
 */
export function effectiveScope(scopeStack) {
  const executedOnImport = scopeStack.every((entry) => entry.kind === SCOPE_KIND.IIFE);
  if (executedOnImport) return { kind: SCOPE_KIND.MODULE, name: '<module>' };
  const innermostReal = [...scopeStack].reverse().find((entry) => entry.kind !== SCOPE_KIND.IIFE);
  return { kind: innermostReal.kind, name: innermostReal.name };
}

/**
 * Depth-first walk that calls `visit(node, context)` for every node, where context carries the
 * parent and the current scope stack. Deliberately small; no dependency on @babel/traverse.
 */
export function walk(root, visit) {
  const scopeStack = [];

  function visitNode(node, parent) {
    if (!node || typeof node.type !== 'string') return;

    const entersFunction = FUNCTION_NODE_TYPES.has(node.type);
    if (entersFunction) {
      const descriptor = isImmediatelyInvoked(node, parent)
        ? { kind: SCOPE_KIND.IIFE, name: '<iife>' }
        : describeFunction(node, parent);
      scopeStack.push(descriptor);
    }

    visit(node, { parent, scope: effectiveScope(scopeStack), scopeDepth: scopeStack.length });

    for (const key of Object.keys(node)) {
      if (SKIPPED_KEYS.has(key)) continue;
      const value = node[key];
      if (Array.isArray(value)) {
        for (const child of value) visitNode(child, node);
      } else if (value && typeof value === 'object' && typeof value.type === 'string') {
        visitNode(value, node);
      }
    }

    if (entersFunction) scopeStack.pop();
  }

  visitNode(root, null);
}

export { SCOPE_KIND, memberExpressionText };
