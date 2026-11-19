import { makeFinding, summarize } from './scanner.mjs';
const mapping = {
  'sentinel-form-destinations': 'CSP-01',
  'sentinel-python-tls': 'TLS-01',
  'sentinel-browser-html': 'WEB-01',
};
const validPath = (p) =>
  p && !/^(?:[a-z]+:|[\\/])/i.test(p) && !p.split(/[\\/]/).includes('..') && !/[\u0000-\u001f]/.test(p);

export function importSarif(document) {
  if (document?.version !== '2.1.0' || !Array.isArray(document.runs) || !document.runs.length)
    throw Error('Choose a SARIF 2.1.0 report with at least one run.');
  const findings = [],
    paths = new Set(),
    ids = new Set(),
    origins = new Set();
  let omitted = 0;
  for (const run of document.runs) {
    const name = run?.tool?.driver?.name;
    if (typeof name !== 'string' || !Array.isArray(run.results))
      throw Error('The report is missing its tool name or results.');
    origins.add(name.slice(0, 80));
    for (const result of run.results) {
      const physical = result?.locations?.[0]?.physicalLocation,
        uri = physical?.artifactLocation?.uri;
      let path;
      try {
        path = typeof uri === 'string' ? decodeURIComponent(uri) : '';
      } catch {
        path = '';
      }
      if (!validPath(path) || typeof result.ruleId !== 'string' || result.ruleId.length > 200) {
        omitted++;
        continue;
      }
      const sourceRule = result.ruleId,
        suffix = sourceRule.split('.').at(-1);
      const rule = /semgrep/i.test(name) && Object.hasOwn(mapping, suffix) ? mapping[suffix] : 'SAST-01';
      const line = physical?.region?.startLine;
      const sourceLine = Number.isInteger(line) && line > 0 ? line : null;
      const key = JSON.stringify([name, path, sourceRule, sourceLine]);
      if (ids.has(key)) continue;
      ids.add(key);
      paths.add(path);
      const extra = {
        scanner: name,
        scannerRule: sourceRule,
        evidence: name + ' · ' + sourceRule,
        ...(rule === 'SAST-01'
          ? {
              title: 'Review scanner finding · ' + sourceRule,
              level: { error: 'high', warning: 'medium', note: 'low' }[result.level] || 'review',
            }
          : {}),
      };
      findings.push(makeFinding(rule, path, sourceLine, key, extra));
    }
  }
  return { output: { ...summarize(findings), paths: [...paths] }, origins: [...origins], omitted };
}
