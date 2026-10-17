// Shared paths and helpers for the evaluation scripts.
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));

export const ARTEFACT_ROOT = path.resolve(HERE, '..', '..');
export const RESULTS_DIR = path.join(ARTEFACT_ROOT, 'evaluation', 'results');
export const WORK_DIR = path.join(RESULTS_DIR, 'work');
export const DATASET_DIR = path.join(WORK_DIR, 'dataset');
export const MALICIOUS_DIR = path.join(WORK_DIR, 'malicious');
export const BENIGN_DIR = path.join(WORK_DIR, 'benign');
export const RECONSTRUCTIONS_DIR = path.join(ARTEFACT_ROOT, 'reconstructions');
export const EVIDENCE_RESULTS_DIR = path.resolve(ARTEFACT_ROOT, '..', '04-evidence', 'results');

export const MALICIOUS_MANIFEST = path.join(MALICIOUS_DIR, 'malicious-manifest.json');
export const BENIGN_MANIFEST = path.join(BENIGN_DIR, 'benign-manifest.json');
export const GATE_RESULTS_CSV = path.join(RESULTS_DIR, 'gate-results.csv');
export const BASELINES_CSV = path.join(RESULTS_DIR, 'baselines.csv');

/** npm v12 reached general availability and started blocking install scripts on this date. */
export const NPM12_GA_DATE = '2026-07-08';

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

export function csvEscape(value) {
  const text = value === null || value === undefined ? '' : String(value);
  return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

export function toCsv(rows) {
  if (rows.length === 0) return '';
  const headers = Object.keys(rows[0]);
  const lines = [headers.join(',')];
  for (const row of rows) lines.push(headers.map((header) => csvEscape(row[header])).join(','));
  return `${lines.join('\n')}\n`;
}

export function csvLine(headers, row) {
  return `${headers.map((header) => csvEscape(row[header])).join(',')}\n`;
}

/** Parses CSV text produced by toCsv/csvLine back into objects (strings; caller converts). */
export function parseCsv(text) {
  const rows = [];
  let headers = null;
  let field = '';
  let record = [];
  let inQuotes = false;
  const pushField = () => { record.push(field); field = ''; };
  const pushRecord = () => {
    if (record.length === 1 && record[0] === '') { record = []; return; }
    if (!headers) headers = record;
    else rows.push(Object.fromEntries(headers.map((header, index) => [header, record[index] ?? ''])));
    record = [];
  };
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (inQuotes) {
      if (char === '"' && text[index + 1] === '"') { field += '"'; index += 1; }
      else if (char === '"') inQuotes = false;
      else field += char;
    } else if (char === '"') inQuotes = true;
    else if (char === ',') pushField();
    else if (char === '\n') { pushField(); pushRecord(); }
    else if (char !== '\r') field += char;
  }
  if (field.length || record.length) { pushField(); pushRecord(); }
  return rows;
}

export async function readJsonIfExists(filePath) {
  try {
    return JSON.parse(await readFile(filePath, 'utf8'));
  } catch {
    return null;
  }
}

export const toBool = (value) => value === true || value === 'true';
export const toNum = (value) => (value === '' || value === undefined ? NaN : Number(value));
