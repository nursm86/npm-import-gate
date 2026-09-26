// Builds the benign set: the most-depended-upon npm packages, downloaded at a pinned version and
// extracted into results/work/benign/. Uses the public npm registry API and tarball. Read-only
// with respect to the packages: they are downloaded and unpacked, never installed or executed.
//   node evaluation/fetch-benign.mjs --count 100
import { spawnSync } from 'node:child_process';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { BENIGN_DIR, parseFlags } from './lib/work.mjs';

const REGISTRY = 'https://registry.npmjs.org';
const SEARCH = `${REGISTRY}/-/v1/search`;
const DEFAULT_COUNT = 100;
const PAGE_SIZE = 250;

async function mostDependedUpon(count) {
  const names = [];
  for (let offset = 0; names.length < count && offset < 1000; offset += PAGE_SIZE) {
    const url = `${SEARCH}?text=boost-exact:false&popularity=1.0&size=${PAGE_SIZE}&from=${offset}`;
    const response = await fetch(url);
    if (!response.ok) break;
    const body = await response.json();
    for (const entry of body.objects ?? []) {
      const name = entry.package?.name;
      if (name && !name.startsWith('@recon/')) names.push(name);
    }
    if ((body.objects ?? []).length < PAGE_SIZE) break;
  }
  return names.slice(0, count);
}

async function latestVersion(name) {
  const response = await fetch(`${REGISTRY}/${name.replace('/', '%2F')}/latest`);
  if (!response.ok) return null;
  const body = await response.json();
  return { version: body.version, tarball: body.dist?.tarball };
}

async function download(url, toFile) {
  const response = await fetch(url);
  if (!response.ok) return false;
  const buffer = Buffer.from(await response.arrayBuffer());
  await writeFile(toFile, buffer);
  return true;
}

async function main() {
  const flags = parseFlags(process.argv.slice(2));
  const count = Number(flags.count ?? DEFAULT_COUNT);

  await rm(BENIGN_DIR, { recursive: true, force: true });
  await mkdir(BENIGN_DIR, { recursive: true });

  const names = await mostDependedUpon(count);
  process.stdout.write(`Fetching ${names.length} popular packages into ${BENIGN_DIR}...\n`);

  let fetched = 0;
  for (const name of names) {
    const info = await latestVersion(name);
    if (!info?.tarball) continue;
    const safeName = name.replace('/', '__');
    const target = path.join(BENIGN_DIR, `${safeName}@${info.version}`);
    await mkdir(target, { recursive: true });
    const tgz = path.join(target, 'package.tgz');
    if (!(await download(info.tarball, tgz))) continue;
    // npm tarballs unpack to a top-level "package/" folder; --strip-components=1 flattens it.
    const result = spawnSync('tar', ['-xzf', tgz, '-C', target, '--strip-components=1'], { stdio: 'ignore' });
    if (result.status === 0) fetched += 1;
    await rm(tgz, { force: true });
  }
  process.stdout.write(`Fetched and unpacked ${fetched} benign packages (pinned versions).\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
});
