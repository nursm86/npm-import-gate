// Maps a gate report for one package to a technique class, using the patterns the gate emits and
// its lockfile/capability findings. Used to fill the per-technique column of Table 4 for samples
// whose ground-truth class is not given by the dataset manifest.

export const TECHNIQUE = Object.freeze({
  INSTALL_TIME: 'install-time',
  IMPORT_TIME: 'import-time',
  DEFERRED: 'deferred-runtime',
  LOCKFILE: 'lockfile-only',
  OTHER: 'other',
});

export function classifyResult(result) {
  const patterns = new Set(result.patterns ?? []);
  if (patterns.has('install-time-execution')) return TECHNIQUE.INSTALL_TIME;
  if (patterns.has('import-time-execution')) return TECHNIQUE.IMPORT_TIME;
  if (patterns.has('deferred-runtime-trigger')) return TECHNIQUE.DEFERRED;
  const hasCapabilityFinding = (result.findings ?? []).some((finding) => finding.family !== 'obfuscation');
  if (!hasCapabilityFinding && (result.lockfileFindings ?? []).length > 0) return TECHNIQUE.LOCKFILE;
  return TECHNIQUE.OTHER;
}
