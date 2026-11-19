import { rules } from './rules.mjs';

const printable = (v) =>
  String(v ?? '')
    .replace(/[\u0000-\u001f]/g, ' ')
    .replace(/[\\<>{}\[\]()!*_#|`]/g, '\\$&');
const uri = (path) =>
  path
    .split('/')
    .map((s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16)))
    .join('/');
export function sourceUrl(base, f) {
  return base ? base + '/' + uri(f.path) + (f.line ? '#L' + f.line : '') : null;
}
export function markdown(view) {
  const o = view.output,
    c = view.change;
  const lines = [
    '# Sentinel security review',
    '',
    '**' + printable(view.name) + '**',
    '',
    printable(view.coverage),
    '',
    'Scanned at ' + view.time,
    '',
    'Score: ' + o.score + '/100 · ' + o.totalFindings + ' findings',
  ];
  if (view.sha) lines.push('', 'Revision: ' + view.sha);
  if (o.audit)
    lines.push(
      '',
      'Dependency audit: ' +
        o.audit.status +
        ' · ' +
        o.audit.checked +
        ' of ' +
        o.audit.total +
        ' exact package versions checked.'
    );
  if (c)
    lines.push(
      '',
      '## Revision comparison',
      '',
      c.fixed.length +
        ' gone from shared files · ' +
        c.remaining.length +
        ' remaining · ' +
        c.introduced.length +
        ' new matches in shared files.',
      c.changedCoverage || c.incomplete || view.partial || view.priorPartial
        ? 'Coverage differs or is incomplete. Treat the observed delta as provisional.'
        : 'Comparison uses the same file scope.',
      ...c.fixed.map(
        (f) =>
          '- ' +
          f.rule +
          ' · ' +
          printable(f.path) +
          ' · ' +
          printable(f.title) +
          (sourceUrl(view.priorLink, f)
            ? ' · [Baseline evidence](' + sourceUrl(view.priorLink, f) + ')'
            : '')
      )
    );
  lines.push('', '## Findings', '');
  if (!o.findings.length) lines.push('No matches within this scan’s coverage.');
  for (const f of o.findings) {
    const source = sourceUrl(view.link, f);
    lines.push(
      '### ' + f.level.toUpperCase() + ' · ' + printable(f.title),
      '',
      f.rule + ' · ' + printable(f.path) + (f.line ? ' line ' + f.line : ''),
      '',
      printable(f.evidence),
      '',
      f.impact,
      '',
      f.fix,
      '',
      'Validation: ' + f.verify,
      ''
    );
    if (source) lines.push('[Source line](' + source + ')', '');
    if (f.reference) lines.push('[Reference](' + f.reference + ')', '');
  }
  lines.push(
    '## Score and scope',
    '',
    '100 minus 18 per critical, 10 per high, 4 per medium, 1 per low, and 15 extra per credential match. Minimum 0. Ungraded advisories require review.',
    '',
    'Static findings need developer review. The score describes the inspected files, selected rules and available advisory data.'
  );
  return lines.join('\n') + '\n';
}
export function sarif(view) {
  const results = view.output.findings.map((f) => ({
    ruleId: f.rule,
    level: { critical: 'error', high: 'error', medium: 'warning', low: 'note', review: 'note' }[f.level],
    ...(f.scannerRule ? { properties: { sourceTool: f.scanner, sourceRule: f.scannerRule } } : {}),
    message: { text: f.title + '. ' + f.fix },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: uri(f.path) },
          ...(f.line ? { region: { startLine: f.line } } : {}),
        },
      },
    ],
  }));
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Sentinel',
            informationUri: 'https://github.com/Arjun1443/Sentinel',
            rules: Object.entries(rules).map(([id, r]) => ({
              id,
              shortDescription: { text: r.title },
              help: { text: r.fix },
            })),
          },
        },
        ...(view.sha && view.repo
          ? {
              versionControlProvenance: [
                { repositoryUri: 'https://github.com/' + view.repo, revisionId: view.sha },
              ],
            }
          : {}),
        results,
      },
    ],
  };
}
