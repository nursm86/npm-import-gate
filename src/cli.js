#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { z } from 'zod';
import { DEFAULT_THRESHOLDS, EXIT_CODE, VERDICT } from './config/constants.js';
import { runGate } from './gate.js';
import { RENDERERS } from './report/render.js';
import { ruleCatalogueMarkdown } from './static/rules.js';
import { logger } from './util/logger.js';

const USAGE = `npm-import-gate

Usage:
  import-gate scan [projectDir] [--format json|md|sarif] [--out file]
                   [--fail N] [--warn N] [--dynamic] [--only a,b] [--prod-only]
                   [--registry-host host ...]
  import-gate rules [--format md|json]

Exit codes: 0 pass or warn, 1 fail, 2 error.
`;

const ScanOptionsSchema = z.object({
  projectDir: z.string().default('.'),
  format: z.enum(['json', 'md', 'markdown', 'sarif']).default('md'),
  out: z.string().optional(),
  fail: z.coerce.number().int().min(1).max(100).default(DEFAULT_THRESHOLDS.fail),
  warn: z.coerce.number().int().min(0).max(100).default(DEFAULT_THRESHOLDS.warn),
  dynamic: z.boolean().default(false),
  only: z.string().optional(),
  prodOnly: z.boolean().default(false),
  registryHost: z.array(z.string()).default([]),
});

function parseCli(argv) {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      format: { type: 'string' },
      out: { type: 'string' },
      fail: { type: 'string' },
      warn: { type: 'string' },
      dynamic: { type: 'boolean' },
      only: { type: 'string' },
      'prod-only': { type: 'boolean' },
      'registry-host': { type: 'string', multiple: true },
      help: { type: 'boolean', short: 'h' },
    },
  });
  const [command, projectDir] = positionals;
  return { command, projectDir, values };
}

async function emit(text, outPath) {
  if (outPath) {
    await writeFile(outPath, text, 'utf8');
    logger.info({ outPath }, 'report written');
  } else {
    process.stdout.write(text);
  }
}

async function runScan(projectDir, values) {
  const options = ScanOptionsSchema.parse({
    projectDir,
    format: values.format,
    out: values.out,
    fail: values.fail,
    warn: values.warn,
    dynamic: values.dynamic,
    only: values.only,
    prodOnly: values['prod-only'],
    registryHost: values['registry-host'],
  });
  const report = await runGate(options.projectDir, {
    thresholds: { fail: options.fail, warn: options.warn },
    dynamic: options.dynamic,
    only: options.only ? options.only.split(',').map((name) => name.trim()).filter(Boolean) : undefined,
    includeDev: !options.prodOnly,
    allowedRegistryHosts: options.registryHost.length ? options.registryHost : undefined,
  });
  await emit(RENDERERS[options.format](report), options.out);
  if (options.out) {
    process.stdout.write(`${report.summary.overall.toUpperCase()}: ${report.summary.counts.fail} fail, `
      + `${report.summary.counts.warn} warn, ${report.summary.counts.pass} pass\n`);
  }
  return report.summary.overall === VERDICT.FAIL ? EXIT_CODE.FAIL : EXIT_CODE.PASS;
}

async function runRules(values) {
  const format = values.format ?? 'md';
  const text = format === 'json'
    ? `${JSON.stringify((await import('./static/rules.js')).ruleCatalogue(), null, 2)}\n`
    : `${ruleCatalogueMarkdown()}\n`;
  await emit(text, values.out);
  return EXIT_CODE.PASS;
}

async function main() {
  const { command, projectDir, values } = parseCli(process.argv.slice(2));
  if (values.help || !command) {
    process.stdout.write(USAGE);
    return EXIT_CODE.PASS;
  }
  if (command === 'scan') return runScan(projectDir, values);
  if (command === 'rules') return runRules(values);
  process.stderr.write(`Unknown command: ${command}\n${USAGE}`);
  return EXIT_CODE.ERROR;
}

main()
  .then((code) => process.exit(code))
  .catch((error) => {
    logger.error({ err: error }, 'gate failed');
    process.exit(EXIT_CODE.ERROR);
  });
