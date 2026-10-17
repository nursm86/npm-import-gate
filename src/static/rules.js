import {
  CAPABILITY_WEIGHTS,
  COMBINATION_BOOSTS,
  CONTEXT_MULTIPLIERS,
  DECLARED_TOOL_DISCOUNT,
  DEFAULT_THRESHOLDS,
  LOCKFILE_RULE_WEIGHTS,
  PURPOSE_MISMATCH_MULTIPLIER,
  TINY_PACKAGE_RULE,
} from '../config/constants.js';

/** Human descriptions for the rule catalogue. Table 2 of the report is rendered from this. */
const CAPABILITY_DESCRIPTIONS = Object.freeze({
  'process.spawn': { description: 'Spawns or executes a child process', targets: 'P1 AsyncAPI, P2 indexed-btree, droppers' },
  'process.detached': { description: 'Child process started detached with ignored stdio (survives the parent)', targets: 'P1 AsyncAPI loader' },
  'process.shell-download': { description: 'Shell command that downloads or decodes and runs content', targets: 'droppers' },
  'net.outbound': { description: 'Outbound network request (http, https, net, fetch, popular clients)', targets: 'exfiltration, stage-two download' },
  'dns.lookup': { description: 'DNS resolution (also used for DNS exfiltration)', targets: 'beaconing' },
  'fs.write': { description: 'Writes to the filesystem', targets: 'staging, persistence' },
  'fs.write-sensitive': { description: 'Writes to shell profiles, SSH, npm or cloud credential paths', targets: 'persistence, credential theft' },
  'fs.read-sensitive': { description: 'Reads SSH keys, .npmrc, cloud or git credentials', targets: 'credential theft (Shai-Hulud)' },
  'env.enumerate': { description: 'Enumerates the whole process environment', targets: 'CI secret harvesting' },
  'env.sensitive': { description: 'Reads token, secret, key or cloud variables by name', targets: 'CI secret harvesting' },
  'code.dynamic': { description: 'eval, new Function, vm or process.binding', targets: 'stage-two execution' },
  'decode.base64': { description: 'Decodes base64 or hex material', targets: 'payload unpacking' },
  'indicator.c2': { description: 'String matches known staging, exfiltration or C2 infrastructure (IPFS, Telegram, Slack and Discord webhooks, Ethereum RPC, tunnels, OAST collaborator domains, request catchers)', targets: 'P1, P2 beaconing; dependency-confusion PoCs' },
  'script.shell-download': { description: 'Lifecycle script command downloads or pipes through curl, wget, a shell -c wrapper or base64 -d', targets: 'install-time droppers and beacons' },
  'script.host-exfil': { description: 'Lifecycle script command substitutes host identity ($(whoami), $(hostname), $(env), gh auth token) or reads /etc/passwd, .ssh, .npmrc, .aws', targets: 'dependency-confusion beacons, credential theft' },
  'script.destructive': { description: 'Lifecycle script command wipes the filesystem root or home (rm -rf /, --no-preserve-root, rm /s /q, mkfs, dd)', targets: 'wipers' },
  'script.inline-code': { description: 'Lifecycle script runs inline code (node -e, python -c, eval); inline JavaScript is also parsed and its capabilities scored', targets: 'one-line install payloads' },
  'script.encoded': { description: 'Lifecycle script command decodes base64 or hex material', targets: 'encoded install payloads' },
  'os.fingerprint': { description: 'Two or more host fingerprint calls (hostname, userInfo, interfaces, cpus)', targets: 'P2 beacon, sandbox checks' },
  'require.dynamic': { description: 'require or import with a computed specifier', targets: 'hidden loaders' },
  'worker.spawn': { description: 'Starts a worker thread', targets: 'hidden execution' },
  'obfuscation.identifiers': { description: 'Identifiers renamed in _0x… style', targets: 'obfuscated payloads' },
  'obfuscation.high-entropy': { description: 'Long high-entropy string literal', targets: 'embedded encrypted payloads' },
  'obfuscation.string-array': { description: 'javascript-obfuscator string-array rotation loop (while (!![]) { try { parseInt(…) } … })', targets: 'obfuscated install and import payloads' },
  'parse.error': { description: 'File could not be parsed as JavaScript', targets: 'malformed or disguised content' },
});

const LOCKFILE_DESCRIPTIONS = Object.freeze({
  'lockfile.non-registry-source': 'Dependency resolved from a git, URL or unknown source rather than the registry',
  'lockfile.missing-integrity': 'No integrity hash, so the tarball cannot be verified',
  'lockfile.optional-non-registry': 'Optional dependency from a non-registry source (can fail silently, P3 TanStack)',
  'lockfile.lifecycle-script': 'Declares preinstall, install or postinstall (blocked by default since npm v12)',
});

function contextRules() {
  const discountScope = DECLARED_TOOL_DISCOUNT.appliesToInferredTool ? 'bin entry or tool-like description' : 'bin entry';
  return [
    {
      id: TINY_PACKAGE_RULE.id,
      kind: 'context',
      weight: TINY_PACKAGE_RULE.boost,
      description: `At most ${TINY_PACKAGE_RULE.maxFilesScanned} source files and a ${TINY_PACKAGE_RULE.families.join(', ')} capability`,
      targets: 'one-file payloads',
    },
    {
      id: DECLARED_TOOL_DISCOUNT.id,
      kind: 'context',
      weight: `×${DECLARED_TOOL_DISCOUNT.multiplier}`,
      description: `Package has a ${discountScope}: ${DECLARED_TOOL_DISCOUNT.families.join(', ')} findings that run on import or at runtime are discounted; install-time findings are not`,
      targets: 'false-positive control for CLIs and build tools',
    },
  ];
}

export function ruleCatalogue() {
  const capabilityRules = Object.entries(CAPABILITY_WEIGHTS).map(([id, weight]) => ({
    id,
    kind: 'capability',
    weight,
    ...CAPABILITY_DESCRIPTIONS[id],
  }));
  const lockfileRules = Object.entries(LOCKFILE_RULE_WEIGHTS).map(([id, weight]) => ({
    id,
    kind: 'lockfile',
    weight,
    description: LOCKFILE_DESCRIPTIONS[id],
    targets: 'lockfile hygiene',
  }));
  const combinationRules = COMBINATION_BOOSTS.map(({ id, boost, requires }) => ({
    id,
    kind: 'combination',
    weight: boost,
    description: `Requires ${requires.map((alternatives) => alternatives.join(' or ')).join(' and ')}`,
    targets: 'pattern boost',
  }));
  return [...capabilityRules, ...lockfileRules, ...combinationRules, ...contextRules()];
}

export function ruleCatalogueMarkdown() {
  const rows = ruleCatalogue().map(
    (rule) => `| ${rule.id} | ${rule.kind} | ${rule.weight} | ${rule.description} | ${rule.targets} |`,
  );
  const header = [
    '| Rule | Kind | Base weight | What it detects | Targets |',
    '|---|---|---|---|---|',
  ];
  const footer = [
    '',
    `Context multipliers: module scope ×${CONTEXT_MULTIPLIERS.module}, method ×${CONTEXT_MULTIPLIERS.method}, function ×${CONTEXT_MULTIPLIERS.function}. `
      + `Purpose mismatch ×${PURPOSE_MISMATCH_MULTIPLIER}. Declared-tool discount ×${DECLARED_TOOL_DISCOUNT.multiplier} on `
      + `${DECLARED_TOOL_DISCOUNT.families.join('/')} findings outside install scripts. Each capability counts once per package at its `
      + `highest-context occurrence; lifecycle script commands score at module scope as install-time execution. `
      + `Thresholds: fail ≥ ${DEFAULT_THRESHOLDS.fail}, warn ≥ ${DEFAULT_THRESHOLDS.warn}.`,
  ];
  return [...header, ...rows, ...footer].join('\n');
}
