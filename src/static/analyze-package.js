import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { EXECUTED_AT, NON_RUNTIME_DIRECTORIES, NON_RUNTIME_FILE_PATTERN, SCAN_LIMITS, SOURCE_EXTENSIONS } from '../config/constants.js';
import { extractCapabilities } from './capabilities.js';
import { analyseLifecycleCommands, installScriptFiles } from './lifecycle-scripts.js';
import { parseSource } from './parse.js';
import { inferPurpose } from './purpose.js';

const SKIPPED_DIRECTORIES = new Set(['node_modules', '.git', ...NON_RUNTIME_DIRECTORIES]);
const TYPE_DECLARATION_SUFFIX = '.d.ts';

async function readManifest(packageDir) {
  try {
    return JSON.parse(await readFile(path.join(packageDir, 'package.json'), 'utf8'));
  } catch {
    return {};
  }
}

async function collectSourceFiles(rootDir, limit) {
  const files = [];
  async function visit(dir) {
    if (files.length >= limit) return;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (files.length >= limit) return;
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIPPED_DIRECTORIES.has(entry.name)) await visit(fullPath);
      } else if (
        entry.isFile()
        && SOURCE_EXTENSIONS.includes(path.extname(entry.name))
        && !entry.name.endsWith(TYPE_DECLARATION_SUFFIX)
        && !NON_RUNTIME_FILE_PATTERN.test(entry.name)
      ) {
        files.push(fullPath);
      }
    }
  }
  await visit(rootDir);
  return files;
}

/**
 * Static analysis of one installed package directory. Never executes anything. Findings come from
 * the lifecycle script commands in package.json and from every runtime source file.
 * @returns {Promise<{ manifest: object, purpose: string, findings: import('./capabilities.js').CapabilityFinding[], stats: object }>}
 */
export async function analyzePackageDirectory(packageDir, limits = SCAN_LIMITS) {
  const manifest = await readManifest(packageDir);
  const purpose = inferPurpose(manifest);
  const scriptFiles = installScriptFiles(manifest);
  const files = await collectSourceFiles(packageDir, limits.maxFilesPerPackage);
  const findings = analyseLifecycleCommands(manifest);
  const stats = { filesScanned: 0, filesSkippedForSize: 0, parseErrors: 0 };

  const tag = (finding, relativePath) => ({
    ...finding,
    executedAt: scriptFiles.has(path.normalize(relativePath)) ? EXECUTED_AT.INSTALL : EXECUTED_AT.IMPORT_OR_RUNTIME,
  });

  for (const filePath of files) {
    const relativePath = path.relative(packageDir, filePath);
    const { size } = await stat(filePath);
    if (size > limits.maxFileBytes) {
      stats.filesSkippedForSize += 1;
      continue;
    }
    const sourceText = await readFile(filePath, 'utf8');
    const ast = parseSource(sourceText);
    stats.filesScanned += 1;
    if (!ast) {
      stats.parseErrors += 1;
      findings.push(tag({
        capability: 'parse.error', family: 'obfuscation', file: relativePath, line: 1,
        scope: 'module', enclosing: '<file>', evidence: 'unparseable as JavaScript',
      }, relativePath));
      continue;
    }
    findings.push(...extractCapabilities(ast, sourceText, relativePath).map((finding) => tag(finding, relativePath)));
  }

  return { manifest, purpose, findings, stats };
}
