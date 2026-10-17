// Builds the benign set: 100 widely used npm packages, each downloaded at its current latest
// version and unpacked into results/work/benign/<name>@<version>/. A curated list is used rather
// than a registry search so the set is deterministic and every package can carry a category tag,
// which the false-positive analysis groups by. Packages are downloaded and unpacked only; nothing
// is installed or executed.
//   node evaluation/fetch-benign.mjs [--count 100]
import { spawnSync } from 'node:child_process';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { BENIGN_DIR, parseFlags } from './lib/work.mjs';

const REGISTRY = 'https://registry.npmjs.org';
const DEFAULT_COUNT = 100;
const FETCH_TIMEOUT_MS = 60000;

/**
 * Category tags: pure = logic-only utilities; validation; http = network clients and servers;
 * cli = command-line and process tooling; logging; build = bundlers, compilers, linters;
 * framework = UI and app frameworks; db = database drivers; native = ships or builds native
 * code (expected to declare install scripts); test = testing tools; browser-automation.
 */
export const BENIGN_PACKAGES = Object.freeze([
  // pure utilities
  ['lodash', 'pure'], ['underscore', 'pure'], ['ramda', 'pure'], ['date-fns', 'pure'], ['dayjs', 'pure'],
  ['moment', 'pure'], ['luxon', 'pure'], ['uuid', 'pure'], ['nanoid', 'pure'], ['semver', 'pure'],
  ['ms', 'pure'], ['classnames', 'pure'], ['deepmerge', 'pure'], ['fast-deep-equal', 'pure'], ['immer', 'pure'],
  ['qs', 'pure'], ['slugify', 'pure'], ['escape-string-regexp', 'pure'], ['string-width', 'pure'], ['strip-ansi', 'pure'],
  ['picocolors', 'pure'], ['mime-types', 'pure'], ['bytes', 'pure'], ['cookie', 'pure'], ['iconv-lite', 'pure'],
  ['entities', 'pure'], ['js-yaml', 'pure'], ['yaml', 'pure'], ['ini', 'pure'], ['minimist', 'pure'],
  // validation
  ['zod', 'validation'], ['joi', 'validation'], ['yup', 'validation'], ['ajv', 'validation'], ['validator', 'validation'],
  // http clients and servers
  ['axios', 'http'], ['node-fetch', 'http'], ['got', 'http'], ['undici', 'http'], ['superagent', 'http'],
  ['ws', 'http'], ['socket.io', 'http'], ['express', 'http'], ['koa', 'http'], ['fastify', 'http'],
  ['cors', 'http'], ['helmet', 'http'], ['body-parser', 'http'], ['compression', 'http'], ['follow-redirects', 'http'],
  // cli and process tooling
  ['commander', 'cli'], ['yargs', 'cli'], ['inquirer', 'cli'], ['ora', 'cli'], ['chalk', 'cli'],
  ['fs-extra', 'cli'], ['glob', 'cli'], ['fast-glob', 'cli'], ['rimraf', 'cli'], ['chokidar', 'cli'],
  ['execa', 'cli'], ['cross-spawn', 'cli'], ['shelljs', 'cli'], ['nodemon', 'cli'], ['concurrently', 'cli'],
  ['dotenv', 'cli'], ['husky', 'cli'], ['lint-staged', 'cli'],
  // logging and telemetry
  ['debug', 'logging'], ['pino', 'logging'], ['winston', 'logging'], ['morgan', 'logging'],
  // build, compile, lint
  ['typescript', 'build'], ['esbuild', 'build'], ['rollup', 'build'], ['webpack', 'build'], ['vite', 'build'],
  ['@babel/core', 'build'], ['acorn', 'build'], ['terser', 'build'], ['postcss', 'build'], ['autoprefixer', 'build'],
  ['sass', 'build'], ['prettier', 'build'], ['eslint', 'build'],
  // frameworks and ui
  ['react', 'framework'], ['react-dom', 'framework'], ['vue', 'framework'], ['svelte', 'framework'], ['rxjs', 'framework'],
  ['redux', 'framework'], ['jquery', 'framework'], ['d3', 'framework'],
  // database drivers
  ['pg', 'db'], ['mysql2', 'db'], ['mongoose', 'db'], ['redis', 'db'], ['ioredis', 'db'],
  // native code (legitimate install scripts expected)
  ['sqlite3', 'native'], ['bcrypt', 'native'], ['sharp', 'native'],
  // testing
  ['jest', 'test'], ['mocha', 'test'], ['chai', 'test'], ['sinon', 'test'], ['supertest', 'test'],
  // browser automation (downloads a browser in a postinstall)
  ['puppeteer', 'browser-automation'], ['playwright', 'browser-automation'],
  // misc application libraries
  ['jsonwebtoken', 'http'], ['bcryptjs', 'pure'], ['nodemailer', 'http'], ['cheerio', 'pure'], ['jsdom', 'framework'],
  ['marked', 'pure'], ['dompurify', 'pure'],
]);

async function fetchJson(url) {
  const response = await fetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  if (!response.ok) throw new Error(`${response.status} for ${url}`);
  return response.json();
}

async function latestVersion(name) {
  const body = await fetchJson(`${REGISTRY}/${name.replace('/', '%2F')}/latest`);
  return { version: body.version, tarball: body.dist?.tarball };
}

async function download(url, toFile) {
  const response = await fetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  if (!response.ok) return false;
  await writeFile(toFile, Buffer.from(await response.arrayBuffer()));
  return true;
}

async function main() {
  const flags = parseFlags(process.argv.slice(2));
  const count = Number(flags.count ?? DEFAULT_COUNT);
  const selected = BENIGN_PACKAGES.slice(0, count);

  await rm(BENIGN_DIR, { recursive: true, force: true });
  await mkdir(BENIGN_DIR, { recursive: true });
  process.stdout.write(`Fetching ${selected.length} benign packages into ${BENIGN_DIR}...\n`);

  const manifest = [];
  for (const [name, category] of selected) {
    try {
      const info = await latestVersion(name);
      if (!info.tarball) throw new Error('no tarball');
      const dirName = `${name.replace('/', '__')}@${info.version}`;
      const target = path.join(BENIGN_DIR, dirName);
      await mkdir(target, { recursive: true });
      const tgz = path.join(target, 'package.tgz');
      if (!(await download(info.tarball, tgz))) throw new Error('download failed');
      // npm tarballs unpack to a top-level "package/" folder; strip it so package.json sits at the root.
      const result = spawnSync('tar', ['-xzf', tgz, '-C', target, '--strip-components=1'], { stdio: 'ignore' });
      await rm(tgz, { force: true });
      if (result.status !== 0) throw new Error('tar failed');
      manifest.push({ dir: dirName, name, version: info.version, category });
      process.stdout.write(`  ok   ${dirName}\n`);
    } catch (error) {
      process.stdout.write(`  skip ${name}: ${error.message}\n`);
    }
  }

  await writeFile(path.join(BENIGN_DIR, 'benign-manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  process.stdout.write(`\nFetched ${manifest.length}/${selected.length}. Manifest: ${path.join(BENIGN_DIR, 'benign-manifest.json')}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
});
