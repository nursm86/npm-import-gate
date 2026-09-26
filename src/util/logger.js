import pino from 'pino';

const LOG_LEVEL = process.env.IMPORT_GATE_LOG_LEVEL ?? 'info';

/** All diagnostics go to stderr through pino so stdout stays clean for the report. */
export const logger = pino(
  { level: LOG_LEVEL, base: { tool: 'npm-import-gate' } },
  pino.destination({ dest: 2, sync: true }),
);
