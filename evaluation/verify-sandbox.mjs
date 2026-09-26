// Checks the dynamic layer: importing P1 inside the no-network sandbox should surface a blocked
// network attempt (import-time execution), while P2 should stay silent on import (its trigger is
// deferred to a method call). Needs Docker. Run: node evaluation/verify-sandbox.mjs
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFile } from 'node:fs/promises';
import { runDynamicAnalysis } from '../src/dynamic/sandbox.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RECON = path.join(HERE, '..', 'reconstructions');

async function analyse(dirName) {
  const dir = path.join(RECON, dirName);
  const manifest = JSON.parse(await readFile(path.join(dir, 'package.json'), 'utf8'));
  const result = await runDynamicAnalysis({ name: manifest.name, dir }, manifest);
  const attemptKinds = [...new Set(result.attempts.map((attempt) => attempt.kind))];
  process.stdout.write(
    `  ${dirName.padEnd(20)} outcome=${result.outcome} attempts=${result.attempts.length} `
    + `kinds=[${attemptKinds.join(', ')}] denials=${result.permissionDenials.length} scoreDelta=${result.scoreDelta}\n`,
  );
  return result;
}

async function main() {
  process.stdout.write('Dynamic sandbox check (no network, read-only, Node permission model):\n');
  const p1 = await analyse('p1-import-loader');
  const p2 = await analyse('p2-sorted-btree');

  if (p1.outcome === 'unavailable') {
    process.stdout.write('\nDocker not available; sandbox layer skipped. Static layer is unaffected.\n');
    return;
  }
  const p1SawNetwork = p1.attempts.some((attempt) => attempt.kind === 'network');
  const p2SawNetwork = p2.attempts.some((attempt) => attempt.kind === 'network');
  process.stdout.write('\n');
  process.stdout.write(`  P1 import-time network attempt observed: ${p1SawNetwork ? 'yes' : 'no'} (expected yes)\n`);
  process.stdout.write(`  P2 deferred trigger silent on import:     ${p2SawNetwork ? 'no' : 'yes'} (expected yes)\n`);
  process.stdout.write('\nThe sandbox sees import-time behaviour and, by design, misses the method-gated trigger.\n');
  process.stdout.write('That gap is why the static layer exists; §4.4 of the report discusses it.\n');
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
});
