/**
 * Every tunable number and name in one place. The report's rule catalogue (Table 2)
 * is generated from these tables, so a change here is a change in the report.
 */

export const OFFICIAL_REGISTRY_HOSTS = Object.freeze(['registry.npmjs.org', 'registry.yarnpkg.com']);

export const SCAN_LIMITS = Object.freeze({
  maxFilesPerPackage: 400,
  maxFileBytes: 2 * 1024 * 1024,
  evidenceSnippetChars: 120,
});

export const SOURCE_EXTENSIONS = Object.freeze(['.js', '.cjs', '.mjs']);

/** When a finding's code runs: from a lifecycle script at install time, or when the package is imported or used. */
export const EXECUTED_AT = Object.freeze({ INSTALL: 'install', IMPORT_OR_RUNTIME: 'import-or-runtime' });

/**
 * Directories that ship inside npm tarballs but do not run when the package is imported. Code here
 * is not part of the consumer-facing surface, so scanning it produces false positives (a logger's
 * own test suite spawns processes and reads env). Excluded from the walk, matching what static
 * scanners such as GuardDog do.
 */
export const NON_RUNTIME_DIRECTORIES = Object.freeze([
  'test', 'tests', '__tests__', '__mocks__', 'spec', 'specs', 'benchmark', 'benchmarks', 'bench',
  'example', 'examples', 'demo', 'demos', 'doc', 'docs', 'coverage', 'fixture', 'fixtures',
  '.github', 'samples', 'scripts', '__snapshots__',
]);

export const NON_RUNTIME_FILE_PATTERN = /\.(test|spec|bench|mock|fixture)\.[cm]?js$/i;

/** Which imported/required module belongs to which capability family. */
export const MODULE_FAMILIES = Object.freeze({
  child_process: 'process',
  http: 'net',
  https: 'net',
  http2: 'net',
  net: 'net',
  tls: 'net',
  dgram: 'net',
  undici: 'net',
  axios: 'net',
  'node-fetch': 'net',
  got: 'net',
  request: 'net',
  ws: 'net',
  dns: 'dns',
  'dns/promises': 'dns',
  fs: 'fs',
  'fs/promises': 'fs',
  vm: 'vm',
  os: 'os',
  worker_threads: 'worker',
});

export const PROCESS_CALLS = Object.freeze(['exec', 'execSync', 'spawn', 'spawnSync', 'fork', 'execFile', 'execFileSync']);
export const NET_CALLS = Object.freeze(['request', 'get', 'post', 'put', 'connect', 'createConnection', 'fetch']);
export const DNS_CALLS = Object.freeze(['lookup', 'resolve', 'resolve4', 'resolve6', 'resolveTxt', 'resolveAny']);
export const FS_WRITE_CALLS = Object.freeze([
  'writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'createWriteStream',
  'mkdir', 'mkdirSync', 'chmod', 'chmodSync', 'rename', 'renameSync', 'copyFile', 'copyFileSync', 'symlink', 'symlinkSync',
]);
export const FS_READ_CALLS = Object.freeze(['readFile', 'readFileSync', 'createReadStream', 'readdir', 'readdirSync']);
export const VM_CALLS = Object.freeze(['runInThisContext', 'runInNewContext', 'runInContext', 'compileFunction', 'Script']);
export const OS_FINGERPRINT_CALLS = Object.freeze(['hostname', 'userInfo', 'networkInterfaces', 'cpus', 'totalmem', 'platform', 'arch', 'release', 'homedir']);
export const MIN_OS_FINGERPRINT_CALLS = 2;

export const SENSITIVE_ENV_PATTERN = /TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE|CREDENTIAL|API_KEY|APIKEY|AWS_|NPM_|GITHUB_|GH_|CI_JOB|VAULT|SSH_/i;
export const SENSITIVE_PATH_PATTERN = /\.ssh|\.npmrc|\.git-credentials|\.aws|\.docker\/config|\.kube|\.bashrc|\.zshrc|\.profile|LaunchAgents|\/etc\/(passwd|shadow|cron)|id_rsa|id_ed25519/i;
export const SHELL_DOWNLOAD_PATTERN = /\b(curl|wget|Invoke-WebRequest|iwr|certutil\s+-urlcache|powershell\b.*(-enc|-e\b)|bash\s+-c|sh\s+-c|base64\s+(-d|--decode))/i;

/** String indicators that point at known exfiltration, C2 or staging infrastructure. */
export const C2_INDICATORS = Object.freeze([
  { id: 'ipfs', pattern: /ipfs\.io|\/ipfs\/|\bipfs:\/\/|\bQm[1-9A-HJ-NP-Za-km-z]{44}\b|\bbafy[a-z2-7]{50,}\b/ },
  { id: 'telegram', pattern: /api\.telegram\.org/ },
  { id: 'slack-webhook', pattern: /hooks\.slack\.com/ },
  { id: 'discord-webhook', pattern: /discord(?:app)?\.com\/api\/webhooks/ },
  { id: 'ethereum-rpc', pattern: /sepolia|infura\.io|alchemy(?:api)?\.com|\beth_call\b|etherscan\.io\/api/ },
  { id: 'pastebin', pattern: /pastebin\.com|paste\.ee|rentry\.co/ },
  { id: 'tunnel', pattern: /ngrok(?:-free)?\.(?:io|app|dev)|serveo\.net|localtunnel/ },
  { id: 'tor', pattern: /\.onion\b/ },
  { id: 'raw-ip-url', pattern: /https?:\/\/\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\// },
  { id: 'interactsh-oast', pattern: /oast\.(?:fun|live|me|pro|site|online)|oastify\.com|interact\.sh|burpcollaborator|canarytokens/ },
  { id: 'request-catcher', pattern: /webhook\.site|beeceptor\.com|requestbin\.(?:com|net)|pipedream\.net|requestcatcher\.com|hookbin\.com|postb\.in|mockbin\.org|ptsv2\.com|requestrepo\.com/ },
]);

/**
 * Rules for the *command strings* of preinstall, install and postinstall scripts. npm v12 blocks
 * these by default, yet a reviewer deciding whether to allow-list a package needs the gate to fail
 * when the command itself is the payload (curl to a collaborator domain, `$(whoami)`, rm -rf /).
 * Matched against the raw command; findings carry module scope and executedAt 'install'.
 */
export const SCRIPT_COMMAND_RULES = Object.freeze([
  { id: 'script.shell-download', family: 'process', pattern: SHELL_DOWNLOAD_PATTERN },
  {
    id: 'script.host-exfil',
    family: 'process',
    pattern: /\$\(\s*(?:whoami|hostname|pwd|id|env|cat|gh\s+auth\s+token)\b|`\s*(?:whoami|hostname|pwd|id|env)\s*`|\/etc\/(?:passwd|shadow)|~?\/\.(?:ssh|npmrc|aws|git-credentials)\b/,
  },
  {
    id: 'script.destructive',
    family: 'process',
    pattern: /\brm\s+-[a-z]*r[a-z]*\s+(?:--no-preserve-root\s+)?(?:\/\*?|~|\$HOME|\*)(?:\s|$)|--no-preserve-root|\brm\s+\/s\b|\bdel\s+\/[fsq]\b|\bmkfs\.|\bdd\s+if=/i,
  },
  { id: 'script.inline-code', family: 'process', pattern: /\b(?:node|bun|deno)\s+(?:-e|--eval|-p|--print)\b|\bpython3?\s+-c\b|\bperl\s+-e\b|\beval\s/ },
  { id: 'script.encoded', family: 'decode', pattern: /\bbase64\b|\batob\(|\bfromCharCode\b|(?:\\x[0-9a-f]{2}){4}/i },
]);

/** Inline JavaScript handed to node -e / --eval / -p / --print; parsed like a source file. */
export const INLINE_SCRIPT_PATTERN = /\b(?:node|bun|deno)\s+(?:-e|--eval|-p|--print)\s+(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')/;

export const OBFUSCATION = Object.freeze({
  hexIdentifierPattern: /_0x[0-9a-f]{4,}/g,
  minHexIdentifiers: 5,
  minHighEntropyStringLength: 400,
  minEntropyBitsPerChar: 4.8,
  /** javascript-obfuscator wraps its string-array rotation in `while (!![]) { try { parseInt(...) } ... }`. */
  stringArrayRotationPattern: /while\s*\(\s*!!\[\]\s*\)/,
});

/**
 * Words in a package's name, description or keywords that suggest a pure-logic package.
 * Network or process capability inside one of these is a purpose mismatch.
 */
export const PURE_PURPOSE_HINTS = Object.freeze([
  'btree', 'b-tree', 'tree', 'sort', 'sorted', 'parse', 'parser', 'util', 'utils', 'helper', 'helpers',
  'format', 'formatter', 'string', 'math', 'color', 'colour', 'queue', 'cache', 'lru', 'map', 'set',
  'date', 'time', 'regex', 'validate', 'validator', 'schema', 'types', 'typings', 'polyfill', 'icon',
  'icons', 'css', 'component', 'components', 'hook', 'hooks', 'array', 'object', 'clone', 'deep',
  'merge', 'debounce', 'throttle', 'uuid', 'slug', 'escape', 'encode', 'decoder', 'tokenizer', 'ast',
  'matrix', 'vector', 'geometry', 'chart', 'template', 'i18n', 'locale', 'currency', 'number',
]);

export const TOOL_PURPOSE_HINTS = Object.freeze([
  'http', 'https', 'fetch', 'client', 'api', 'sdk', 'request', 'socket', 'server', 'cli', 'tool',
  'build', 'bundler', 'bundle', 'compiler', 'download', 'downloader', 'install', 'installer', 'proxy',
  'deploy', 'runner', 'test', 'testing', 'browser', 'puppeteer', 'playwright', 'webpack', 'vite',
  'esbuild', 'rollup', 'babel', 'eslint', 'prettier', 'git', 'docker', 'ssh', 'ftp', 'telemetry',
  'analytics', 'update', 'updater', 'native', 'binding', 'bindings', 'gyp', 'prebuild',
]);

/**
 * Base weights per capability. A capability counts once per package at its highest-context
 * occurrence, so a large legitimate HTTP client does not accumulate hundreds of points.
 */
export const CAPABILITY_WEIGHTS = Object.freeze({
  'process.spawn': 30,
  'process.detached': 15,
  'process.shell-download': 20,
  'net.outbound': 20,
  'dns.lookup': 10,
  'fs.write': 5,
  'fs.write-sensitive': 30,
  'fs.read-sensitive': 25,
  'env.enumerate': 25,
  'env.sensitive': 20,
  'code.dynamic': 25,
  'decode.base64': 10,
  'indicator.c2': 30,
  'script.shell-download': 25,
  'script.host-exfil': 30,
  'script.destructive': 30,
  'script.inline-code': 10,
  'script.encoded': 10,
  'os.fingerprint': 10,
  'require.dynamic': 5,
  'worker.spawn': 5,
  'obfuscation.identifiers': 15,
  'obfuscation.string-array': 20,
  'obfuscation.high-entropy': 10,
  'parse.error': 2,
});

/** Where the capability sits decides how much it matters. Module scope runs on import. */
export const CONTEXT_MULTIPLIERS = Object.freeze({
  module: 2.0,
  method: 1.25,
  function: 1.0,
});

export const PURPOSE_MISMATCH_MULTIPLIER = 1.5;
export const PURPOSE_MISMATCH_FAMILIES = Object.freeze(['process', 'net', 'dns', 'env', 'code', 'decode']);

/**
 * A package with one or two source files and a process, network, DNS, dynamic-code or environment
 * capability has little else to be for. Legitimate one-file packages are overwhelmingly pure logic.
 */
export const TINY_PACKAGE_RULE = Object.freeze({
  id: 'size.tiny-with-capability',
  maxFilesScanned: 2,
  boost: 20,
  families: ['process', 'net', 'dns', 'code', 'env'],
});

/**
 * Packages that install a `bin` entry, or describe themselves as a tool, spawn processes, read the
 * environment and evaluate code by design. Their import-time and runtime findings in those families
 * are discounted. Install-time findings are not: npm v12 blocks install scripts for tools too, and
 * the allow-list decision needs the full score.
 */
export const DECLARED_TOOL_DISCOUNT = Object.freeze({
  id: 'context.declared-tool',
  multiplier: 0.5,
  families: ['process', 'env', 'code'],
  appliesToInferredTool: true,
});

/** Findings from the lockfile itself. */
export const LOCKFILE_RULE_WEIGHTS = Object.freeze({
  'lockfile.non-registry-source': 40,
  'lockfile.missing-integrity': 30,
  'lockfile.optional-non-registry': 30,
  'lockfile.lifecycle-script': 20,
});

/** Capability pairs that together describe a known malicious pattern. */
export const COMBINATION_BOOSTS = Object.freeze([
  { id: 'exfiltration-pattern', requires: [['env.enumerate', 'env.sensitive'], ['net.outbound', 'dns.lookup']], boost: 30 },
  { id: 'dropper-pattern', requires: [['decode.base64'], ['code.dynamic', 'process.spawn']], boost: 30 },
  { id: 'detached-loader-pattern', requires: [['process.detached'], ['net.outbound', 'indicator.c2', 'fs.write']], boost: 20 },
  { id: 'beacon-pattern', requires: [['os.fingerprint'], ['indicator.c2']], boost: 25 },
  { id: 'credential-theft-pattern', requires: [['fs.read-sensitive'], ['net.outbound', 'indicator.c2']], boost: 30 },
]);

export const SCORE_CAP = 100;

export const DEFAULT_THRESHOLDS = Object.freeze({
  fail: 60,
  warn: 35,
});

export const VERDICT = Object.freeze({
  PASS: 'pass',
  WARN: 'warn',
  FAIL: 'fail',
});

export const EXIT_CODE = Object.freeze({
  PASS: 0,
  FAIL: 1,
  ERROR: 2,
});

export const DYNAMIC_SANDBOX = Object.freeze({
  image: 'node:24-bookworm-slim',
  timeoutSeconds: 30,
  memoryLimit: '512m',
  cpuLimit: '1',
  pidsLimit: 64,
  mountPoint: '/sandbox',
});
