import { PURE_PURPOSE_HINTS, TOOL_PURPOSE_HINTS } from '../config/constants.js';

export const PURPOSE = Object.freeze({
  PURE: 'pure',
  TOOL: 'tool',
  UNKNOWN: 'unknown',
});

const WORD_SPLIT_PATTERN = /[^a-z0-9]+/;

function wordsFrom(manifest) {
  const parts = [manifest.name ?? '', manifest.description ?? '', ...(manifest.keywords ?? [])];
  return new Set(parts.join(' ').toLowerCase().split(WORD_SPLIT_PATTERN).filter(Boolean));
}

/**
 * Infers what a package is for from its own manifest. A package that describes itself as a
 * sorted tree and then spawns processes is a purpose mismatch; the indexed-btree campaign of
 * September 2026 is exactly that shape.
 */
export function inferPurpose(manifest) {
  const words = wordsFrom(manifest);
  const looksLikeTool = TOOL_PURPOSE_HINTS.some((hint) => words.has(hint));
  if (looksLikeTool) return PURPOSE.TOOL;
  const looksPure = PURE_PURPOSE_HINTS.some((hint) => words.has(hint));
  if (looksPure) return PURPOSE.PURE;
  return PURPOSE.UNKNOWN;
}

/** True when the manifest installs a command-line executable (`bin` as a string or a non-empty map). */
export function declaresExecutable(manifest) {
  const bin = manifest?.bin;
  if (typeof bin === 'string') return bin.length > 0;
  return Boolean(bin) && typeof bin === 'object' && Object.keys(bin).length > 0;
}
