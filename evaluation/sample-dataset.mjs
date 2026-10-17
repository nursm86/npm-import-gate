// Stratified sample of npm packages from DataDog's malicious-software-packages-dataset without
// cloning its 33 GB: a partial clone holds only the tree index, the sample is chosen from the
// dated zip file names, and a sparse checkout fetches just those zips. Each zip is then unzipped
// (password `infected`) into results/work/malicious/<id>/ so that package.json sits at the root.
// Nothing is executed. Needs git >= 2.35 and `unzip`.
//
//   node evaluation/sample-dataset.mjs [--count 150] [--post-ga 60] [--min-compromised 15] [--seed 42]
//
// Design: the report compares malware published before and after npm v12 went GA (8 Jul 2026),
// so the sample is split into a pre-GA part stratified by month and a post-GA part stratified by
// month, with a floor on compromised-library samples (legitimate packages that were backdoored,
// the AsyncAPI / @antv shape).
import { spawnSync } from 'node:child_process';
import { access, mkdir, readdir, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { DATASET_DIR, MALICIOUS_DIR, MALICIOUS_MANIFEST, NPM12_GA_DATE, parseFlags } from './lib/work.mjs';

const DATASET_REPO = 'https://github.com/DataDog/malicious-software-packages-dataset';
const DATASET_PASSWORD = 'infected';
const DEFAULTS = Object.freeze({ count: 150, postGa: 60, minCompromised: 15, seed: 42 });
const ZIP_PATH_PATTERN = /^samples\/npm\/(malicious_intent|compromised_lib)\/([^/]+)\/([^/]+)\/(\d{4}-\d{2}-\d{2})-.*\.zip$/;

function mulberry32(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function shuffled(items, random) {
  const copy = [...items];
  for (let index = copy.length - 1; index > 0; index -= 1) {
    const swap = Math.floor(random() * (index + 1));
    [copy[index], copy[swap]] = [copy[swap], copy[index]];
  }
  return copy;
}

function git(args, options = {}) {
  const result = spawnSync('git', ['-C', DATASET_DIR, ...args], { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, ...options });
  if (result.status !== 0) throw new Error(`git ${args[0]} failed: ${result.stderr.trim().split('\n').slice(-2).join(' | ')}`);
  return result.stdout;
}

async function ensurePartialClone() {
  try {
    await access(path.join(DATASET_DIR, '.git'));
    return;
  } catch {
    process.stdout.write('Partial-cloning the dataset index (trees only, no blobs)...\n');
    await mkdir(path.dirname(DATASET_DIR), { recursive: true });
    const result = spawnSync('git', ['clone', '--filter=blob:none', '--no-checkout', '--depth', '1', '--single-branch', '--branch', 'main', DATASET_REPO, DATASET_DIR], { stdio: 'inherit' });
    if (result.status !== 0) throw new Error('partial clone failed');
  }
}

function listSamples() {
  const paths = git(['ls-tree', '-r', '--name-only', 'HEAD', '--', 'samples/npm']).split('\n');
  const samples = [];
  for (const zipPath of paths) {
    const match = zipPath.match(ZIP_PATH_PATTERN);
    if (!match) continue;
    const [, category, packageDir, version, date] = match;
    samples.push({
      zipPath,
      category,
      name: packageDir.replace(/^@([^@]+)@/, '@$1/'),
      version,
      date,
      month: date.slice(0, 7),
      postGa: date >= NPM12_GA_DATE,
    });
  }
  return samples;
}

/** One version per package name, chosen at random, so no single campaign version-spams the sample. */
function onePerPackage(samples, random) {
  const byName = new Map();
  for (const sample of shuffled(samples, random)) if (!byName.has(sample.name)) byName.set(sample.name, sample);
  return [...byName.values()];
}

function stratifiedByMonth(samples, count, random) {
  const byMonth = new Map();
  for (const sample of samples) {
    if (!byMonth.has(sample.month)) byMonth.set(sample.month, []);
    byMonth.get(sample.month).push(sample);
  }
  const months = [...byMonth.keys()].sort();
  const chosen = [];
  const pools = months.map((month) => shuffled(byMonth.get(month), random));
  // Round-robin across months until the quota is met, so sparse months still contribute.
  let cursor = 0;
  while (chosen.length < count && pools.some((pool) => pool.length > 0)) {
    const pool = pools[cursor % pools.length];
    if (pool.length) chosen.push(pool.pop());
    cursor += 1;
  }
  return chosen;
}

function chooseSample(all, options, random) {
  const unique = onePerPackage(all, random);
  const preGa = unique.filter((sample) => !sample.postGa);
  const postGa = unique.filter((sample) => sample.postGa);
  const postCount = Math.min(options.postGa, postGa.length);
  const preCount = options.count - postCount;

  let chosen = [...stratifiedByMonth(postGa, postCount, random), ...stratifiedByMonth(preGa, preCount, random)];

  const compromisedChosen = chosen.filter((sample) => sample.category === 'compromised_lib').length;
  if (compromisedChosen < options.minCompromised) {
    const chosenPaths = new Set(chosen.map((sample) => sample.zipPath));
    const extra = shuffled(unique.filter((sample) => sample.category === 'compromised_lib' && !chosenPaths.has(sample.zipPath)), random)
      .slice(0, options.minCompromised - compromisedChosen);
    // Replace the same number of malicious_intent picks (from the end) to keep the total fixed.
    const keep = chosen.filter((sample) => sample.category === 'compromised_lib');
    const intent = chosen.filter((sample) => sample.category === 'malicious_intent').slice(0, options.count - keep.length - extra.length);
    chosen = [...keep, ...extra, ...intent];
  }
  return shuffled(chosen, random);
}

function sparseCheckout(zipPaths) {
  process.stdout.write(`Sparse-checking out ${zipPaths.length} zips (fetches only those blobs)...\n`);
  git(['sparse-checkout', 'set', '--no-cone', '--', ...zipPaths]);
  git(['checkout', '--quiet', 'main']);
}

async function findPackageRoot(dir, depth = 0) {
  const entries = await readdir(dir, { withFileTypes: true });
  if (entries.some((entry) => entry.isFile() && entry.name === 'package.json')) return dir;
  if (depth >= 3) return null;
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const found = await findPackageRoot(path.join(dir, entry.name), depth + 1);
    if (found) return found;
  }
  return null;
}

/** Unzips one sample and hoists the folder that holds package.json to the target root. */
async function extractSample(sample, index) {
  const safeName = sample.name.replace('/', '__').replace(/[^\w.@-]/g, '_');
  const id = `${String(index).padStart(3, '0')}_${sample.category === 'compromised_lib' ? 'lib' : 'int'}_${safeName}@${sample.version}`;
  const target = path.join(MALICIOUS_DIR, id);
  await mkdir(target, { recursive: true });
  const unzip = spawnSync('unzip', ['-o', '-q', '-P', DATASET_PASSWORD, path.join(DATASET_DIR, sample.zipPath), '-d', target], { stdio: 'ignore' });
  if (unzip.status !== 0) return null;
  const root = await findPackageRoot(target);
  if (root && root !== target) {
    const hoisted = `${target}__hoist`;
    await rename(root, hoisted);
    await rm(target, { recursive: true, force: true });
    await rename(hoisted, target);
  }
  return { id, dir: id, ...sample };
}

async function main() {
  const flags = parseFlags(process.argv.slice(2));
  const options = {
    count: Number(flags.count ?? DEFAULTS.count),
    postGa: Number(flags['post-ga'] ?? DEFAULTS.postGa),
    minCompromised: Number(flags['min-compromised'] ?? DEFAULTS.minCompromised),
    seed: Number(flags.seed ?? DEFAULTS.seed),
  };
  if (spawnSync('unzip', ['-v'], { stdio: 'ignore' }).status !== 0) throw new Error('`unzip` is required');

  await ensurePartialClone();
  const all = listSamples();
  process.stdout.write(`Index: ${all.length} npm sample zips, ${all.filter((sample) => sample.postGa).length} after npm v12 GA (${NPM12_GA_DATE}).\n`);

  const random = mulberry32(options.seed);
  const chosen = chooseSample(all, options, random);
  sparseCheckout(chosen.map((sample) => sample.zipPath));

  await rm(MALICIOUS_DIR, { recursive: true, force: true });
  await mkdir(MALICIOUS_DIR, { recursive: true });
  const manifest = [];
  for (const [index, sample] of chosen.entries()) {
    const extracted = await extractSample(sample, index + 1);
    if (extracted) manifest.push(extracted);
  }
  await writeFile(MALICIOUS_MANIFEST, `${JSON.stringify(manifest, null, 2)}\n`);

  const postCount = manifest.filter((sample) => sample.postGa).length;
  const libCount = manifest.filter((sample) => sample.category === 'compromised_lib').length;
  process.stdout.write(`Extracted ${manifest.length} samples into ${MALICIOUS_DIR}\n`
    + `  post-GA (>= ${NPM12_GA_DATE}): ${postCount}, pre-GA: ${manifest.length - postCount}\n`
    + `  compromised_lib: ${libCount}, malicious_intent: ${manifest.length - libCount}\n`
    + 'These are real malware samples: unzipped only, never run outside the sandbox.\n');
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
});
