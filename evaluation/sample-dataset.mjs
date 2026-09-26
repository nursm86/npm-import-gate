// Stratified sample of npm packages from DataDog's malicious-software-packages-dataset, extracted
// into results/work/malicious/. Reads the dataset's manifest.json, samples by discovery month so
// recent campaigns are represented, and unzips each selected sample with the dataset password.
// Extraction only unzips; nothing is executed. Needs the `unzip` command.
//   node evaluation/sample-dataset.mjs --dataset ./dataset --count 150 [--seed 42]
import { spawnSync } from 'node:child_process';
import { access, mkdir, readFile, readdir, rm } from 'node:fs/promises';
import path from 'node:path';
import { MALICIOUS_DIR, parseFlags } from './lib/work.mjs';

const DATASET_PASSWORD = 'infected';
const DEFAULT_COUNT = 150;

// Deterministic PRNG so a run is reproducible from --seed.
function mulberry32(seed) {
  let state = seed >>> 0;
  return () => {
    state |= 0;
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function stratifiedSample(samples, count, random) {
  const byMonth = new Map();
  for (const sample of samples) {
    const month = (sample.date ?? '0000-00').slice(0, 7);
    if (!byMonth.has(month)) byMonth.set(month, []);
    byMonth.get(month).push(sample);
  }
  const months = [...byMonth.keys()].sort();
  const perMonth = Math.max(1, Math.floor(count / months.length));
  const chosen = [];
  for (const month of months) {
    const bucket = byMonth.get(month).sort(() => random() - 0.5);
    chosen.push(...bucket.slice(0, perMonth));
  }
  return chosen.sort(() => random() - 0.5).slice(0, count);
}

async function findZips(npmSamplesDir) {
  const zips = [];
  async function walk(dir) {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) await walk(full);
      else if (entry.name.endsWith('.zip')) zips.push(full);
    }
  }
  await walk(npmSamplesDir);
  return zips;
}

async function main() {
  const flags = parseFlags(process.argv.slice(2));
  const datasetDir = flags.dataset ? path.resolve(flags.dataset) : null;
  const count = Number(flags.count ?? DEFAULT_COUNT);
  const seed = Number(flags.seed ?? 42);
  if (!datasetDir) {
    process.stderr.write('Usage: node evaluation/sample-dataset.mjs --dataset ./dataset --count 150\n');
    process.exit(1);
  }

  const npmDir = path.join(datasetDir, 'samples', 'npm');
  try {
    await access(npmDir);
  } catch {
    process.stderr.write(`Could not find ${npmDir}. Clone the DataDog dataset there first.\n`);
    process.exit(1);
  }
  if (spawnSync('unzip', ['-v'], { stdio: 'ignore' }).status !== 0) {
    process.stderr.write('The `unzip` command is required.\n');
    process.exit(1);
  }

  const zips = await findZips(npmDir);
  const samples = zips.map((zipPath) => {
    const base = path.basename(zipPath, '.zip');
    const dateMatch = base.match(/(\d{4}-\d{2}-\d{2})/);
    return { zipPath, name: base.replace(/[^\w.@-]/g, '_'), date: dateMatch ? dateMatch[1] : '0000-00-00' };
  });
  process.stdout.write(`Found ${samples.length} npm sample zips. Sampling ${count} across `
    + `${new Set(samples.map((s) => s.date.slice(0, 7))).size} months...\n`);

  const random = mulberry32(seed);
  const chosen = stratifiedSample(samples, count, random);

  await rm(MALICIOUS_DIR, { recursive: true, force: true });
  await mkdir(MALICIOUS_DIR, { recursive: true });
  let extracted = 0;
  for (const sample of chosen) {
    const target = path.join(MALICIOUS_DIR, `${sample.name}__${extracted}`);
    const result = spawnSync('unzip', ['-o', '-q', '-P', DATASET_PASSWORD, sample.zipPath, '-d', target], { stdio: 'ignore' });
    if (result.status === 0) extracted += 1;
  }
  process.stdout.write(`Extracted ${extracted} samples into ${MALICIOUS_DIR}\n`);
  process.stdout.write('These are real malware. They are only unzipped here; never run them outside the sandbox.\n');
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
});
