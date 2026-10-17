import { VERDICT } from '../config/constants.js';
import { isAllowedException } from '../score/aggregate.js';
import { ruleCatalogue } from '../static/rules.js';

const SARIF_VERSION = '2.1.0';
const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
const TOOL_NAME = 'npm-import-gate';
const TOOL_URI = 'https://github.com/nursm86/npm-import-gate';
const MAX_CONTRIBUTIONS_IN_MARKDOWN = 6;

const SARIF_LEVEL = Object.freeze({
  [VERDICT.FAIL]: 'error',
  [VERDICT.WARN]: 'warning',
  [VERDICT.PASS]: 'note',
});

export function renderJson(report) {
  return `${JSON.stringify(report, null, 2)}\n`;
}

function markdownRowFor(result) {
  const topReasons = result.contributions
    .slice(0, MAX_CONTRIBUTIONS_IN_MARKDOWN)
    .map((contribution) => `${contribution.source} (+${Math.round(contribution.points)})`)
    .join(', ');
  const verdict = isAllowedException(result) ? `${result.verdict.toUpperCase()} (allowed)` : result.verdict.toUpperCase();
  return `| ${result.name}@${result.version} | ${verdict} | ${result.score} | ${result.patterns.join(', ') || '–'} | ${topReasons || '–'} |`;
}

export function renderMarkdown(report) {
  const { summary, packages, project } = report;
  const flagged = packages.filter((result) => result.verdict !== VERDICT.PASS);
  const allowedCount = summary.counts.allowed ? ` · allowed ${summary.counts.allowed}` : '';
  const lines = [
    `# ${TOOL_NAME} report`,
    '',
    `Project: \`${project.name ?? project.dir}\` · packages scanned: ${summary.packagesScanned} · `
      + `pass ${summary.counts.pass} · warn ${summary.counts.warn} · fail ${summary.counts.fail}${allowedCount} · `
      + `overall: **${summary.overall.toUpperCase()}**`,
    '',
    `Thresholds: fail ≥ ${summary.thresholds.fail}, warn ≥ ${summary.thresholds.warn}. Dynamic analysis: ${report.dynamicEnabled ? 'on' : 'off'}.`,
    '',
  ];
  if (flagged.length === 0) {
    lines.push('No package reached the warning threshold.');
  } else {
    lines.push('| Package | Verdict | Score | Patterns | Top contributions |', '|---|---|---|---|---|');
    lines.push(...flagged.map(markdownRowFor));
    lines.push('');
    for (const result of flagged.filter((item) => item.verdict === VERDICT.FAIL)) {
      lines.push(`## ${result.name}@${result.version}`);
      if (result.allowance) lines.push(`- allowed: ${result.allowance.reason}`);
      for (const contribution of result.contributions) {
        const where = contribution.finding ? ` — \`${contribution.finding.evidence}\`` : '';
        lines.push(`- **${contribution.source}** +${Math.round(contribution.points)}: ${contribution.reason}${where}`);
      }
      if (result.dynamic) {
        lines.push(`- dynamic: ${result.dynamic.attempts.length} intercepted attempt(s), `
          + `${result.dynamic.permissionDenials.length} permission denial(s), outcome ${result.dynamic.outcome}`);
      }
      lines.push('');
    }
  }
  return `${lines.join('\n')}\n`;
}

function sarifRules() {
  return ruleCatalogue().map((rule) => ({
    id: rule.id,
    name: rule.id,
    shortDescription: { text: rule.description },
    properties: { weight: rule.weight, kind: rule.kind },
  }));
}

function sarifResultsFor(result, projectDir) {
  return result.contributions
    .filter((contribution) => contribution.finding)
    .map((contribution) => ({
      ruleId: contribution.source,
      level: isAllowedException(result) ? SARIF_LEVEL[VERDICT.PASS] : SARIF_LEVEL[result.verdict],
      message: {
        text: `${result.name}@${result.version} score ${result.score} (${result.verdict}`
          + `${result.allowance ? `, allowed: ${result.allowance.reason}` : ''}): ${contribution.reason}`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: `${result.lockKey}/${contribution.finding.file}`.replaceAll('\\', '/'), uriBaseId: '%SRCROOT%' },
            region: { startLine: Math.max(1, contribution.finding.line) },
          },
        },
      ],
      properties: { score: result.score, patterns: result.patterns, projectDir },
    }));
}

export function renderSarif(report) {
  const sarif = {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: { driver: { name: TOOL_NAME, informationUri: TOOL_URI, version: report.toolVersion, rules: sarifRules() } },
        results: report.packages
          .filter((result) => result.verdict !== VERDICT.PASS)
          .flatMap((result) => sarifResultsFor(result, report.project.dir)),
      },
    ],
  };
  return `${JSON.stringify(sarif, null, 2)}\n`;
}

export const RENDERERS = Object.freeze({
  json: renderJson,
  md: renderMarkdown,
  markdown: renderMarkdown,
  sarif: renderSarif,
});
