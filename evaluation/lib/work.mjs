// Shared paths and helpers for the evaluation scripts.
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));

export const ARTEFACT_ROOT = path.resolve(HERE, '..', '..');
export const RESULTS_DIR = path.join(ARTEFACT_ROOT, 'evaluation', 'results');
export const WORK_DIR = path.join(RESULTS_DIR, 'work');
export const MALICIOUS_DIR = path.join(WORK_DIR, 'malicious');
export const BENIGN_DIR = path.join(WORK_DIR, 'benign');

/** Minimal `--flag value` / `--flag` parser for the evaluation CLIs. */
export function parseFlags(argv) {
  const flags = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const next = argv[index + 1];
    if (next === undefined || next.startsWith('--')) {
      flags[key] = true;
    } else {
      flags[key] = next;
      index += 1;
    }
  }
  return flags;
}

export function toCsv(rows) {
  if (rows.length === 0) return '';
  const headers = Object.keys(rows[0]);
  const escape = (value) => {
    const text = value === null || value === undefined ? '' : String(value);
    return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
  };
  const lines = [headers.join(',')];
  for (const row of rows) lines.push(headers.map((header) => escape(row[header])).join(','));
  return `${lines.join('\n')}\n`;
}
