import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { z } from 'zod';

const PROJECT_MANIFEST = 'package.json';
const CONFIG_FIELD = 'importGate';
const COMMAND_LINE_REASON = 'allowed on the command line';
const MIN_REASON_LENGTH = 10;
const FILE_NOT_FOUND = 'ENOENT';

/**
 * A reviewed exception: the named package is still scanned and reported, but its verdict does
 * not fail the gate. The reason is mandatory so that every exception carries its review note
 * into code review, the same way a committed `npm approve-scripts` allow-list does.
 */
const AllowanceSchema = z.object({
  name: z.string().min(1),
  reason: z.string().min(MIN_REASON_LENGTH),
});

export const ProjectConfigSchema = z
  .object({
    allow: z.array(AllowanceSchema).default([]),
  })
  .strict();

/**
 * Reads the `importGate` field of the project's package.json. A project without a manifest or
 * without the field has no exceptions.
 */
export async function readProjectAllowList(projectDir) {
  let raw;
  try {
    raw = await readFile(path.join(projectDir, PROJECT_MANIFEST), 'utf8');
  } catch (error) {
    if (error.code === FILE_NOT_FOUND) return [];
    throw error;
  }
  const manifest = JSON.parse(raw);
  if (manifest[CONFIG_FIELD] === undefined) return [];
  return ProjectConfigSchema.parse(manifest[CONFIG_FIELD]).allow;
}

export function allowancesFromNames(names = []) {
  return names.map((name) => ({ name, reason: COMMAND_LINE_REASON }));
}

export function findAllowance(allowList, packageName) {
  return allowList.find((allowance) => allowance.name === packageName);
}
