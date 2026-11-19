import { rules, weights, levels } from './rules.mjs';

export function supported(path) {
  return (
    /\.(?:py|[cm]?[jt]sx?|json|env|ya?ml|txt|toml|ini|cfg)$/i.test(path) ||
    /(?:^|\/)\.env(?:\.[\w-]+)?$/.test(path)
  );
}

export function makeFinding(rule, path, line, key, fields = {}) {
  const details = rules[rule];
  return {
    id: JSON.stringify([path, rule, key]),
    rule,
    level: details.level,
    title: details.title,
    path,
    line,
    group: details.group,
    impact: details.impact,
    fix: details.fix,
    verify: details.verify,
    evidence: 'Review the referenced source location.',
    patch: '',
    ...fields,
  };
}

function patchLine(path, line, original, replacement) {
  if (!/^[\w./@+-]+$/.test(path) || path.split('/').includes('..') || path.startsWith('/')) return '';
  return [
    '--- a/' + path,
    '+++ b/' + path,
    '@@ -' + line + ',1 +' + line + ',1 @@',
    '-' + original,
    '+' + replacement,
    '',
  ].join('\n');
}

function policyFindings(file) {
  let config;
  try {
    config = JSON.parse(file.content);
  } catch {
    return [];
  }
  if (!Array.isArray(config?.headers)) return [];
  const lines = file.content.split(/\r?\n/);
  const findings = [];
  for (const [routeIndex, route] of config.headers.entries()) {
    if (!Array.isArray(route?.headers)) continue;
    for (const [headerIndex, header] of route.headers.entries()) {
      if (
        String(header?.key).toLowerCase() !== 'content-security-policy' ||
        typeof header.value !== 'string'
      )
        continue;
      const policy = header.value;
      if (policy.split(';').some((d) => /^form-action(?:\s|$)/i.test(d.trim()))) continue;
      const encoded = JSON.stringify(policy);
      const hits = lines.flatMap((v, i) => (v.includes(encoded) ? [i] : []));
      const index = hits.length === 1 ? hits[0] : -1;
      const original = lines[index] || '';
      // Offer the one-line diff only for a simple policy without URLs, nonces or adjacent data.
      const safePolicy =
        /^(?:(?:[a-z][a-z-]* (?:'(?:self|none|strict-dynamic)'|https:))(?:;\s*|$))+$/i.test(policy);
      const simpleLine =
        /^\s*(?:\{\s*"key"\s*:\s*"Content-Security-Policy"\s*,\s*)?"value"\s*:\s*"[^"]+"\s*\}?,?\s*$/i.test(
          original
        );
      const revised = policy.trim().replace(/;$/, '') + "; form-action 'self'";
      findings.push(
        makeFinding(
          'CSP-01',
          file.path,
          index < 0 ? null : index + 1,
          'policy-' + routeIndex + '-' + headerIndex,
          {
            evidence: 'Content-Security-Policy · form-action missing',
            patch:
              safePolicy && simpleLine
                ? patchLine(
                    file.path,
                    index + 1,
                    original,
                    original.replace(encoded, JSON.stringify(revised))
                  )
                : '',
          }
        )
      );
    }
  }
  return findings;
}

// Preserve character offsets while removing string contents and comments. This prevents
// configuration examples in a test string or template from becoming code findings.
function executable(line, state, python, js) {
  const output = Array(line.length).fill(' ');
  for (let i = 0; i < line.length; ) {
    if (state.end) {
      if (line.startsWith(state.end, i)) {
        i += state.end.length;
        state.end = '';
      } else if (line[i] === '\\' && state.end !== '*/') i += 2;
      else i++;
      continue;
    }
    if (js && line.startsWith('/*', i)) {
      state.end = '*/';
      i += 2;
      continue;
    }
    if ((python && line[i] === '#') || (js && line.startsWith('//', i))) break;
    const char = line[i];
    if (char === '"' || char === "'" || (js && char.charCodeAt(0) === 96)) {
      state.end = python && line.slice(i, i + 3) === char.repeat(3) ? char.repeat(3) : char;
      i += state.end.length;
      continue;
    }
    output[i] = char;
    i++;
  }
  if ((state.end === '"' || state.end === "'") && !line.endsWith('\\')) state.end = '';
  return output.join('');
}

function fileMatches(file) {
  const isDeploymentConfig = /(?:^|\/)vercel\.json$/i.test(file.path);
  const python = /\.py$/i.test(file.path),
    js = /\.[cm]?[jt]sx?$/i.test(file.path);
  const config = !python && !js;
  const requirements = /(?:^|\/)requirements(?:[-.][\w-]+)?\.txt$/i.test(file.path);
  const matches = isDeploymentConfig ? policyFindings(file) : [],
    counts = new Map(),
    state = { end: '' };
  const lines = file.content.split(/\r?\n/);
  for (const [i, line] of lines.entries()) {
    if (line.length > 12000) continue;
    const code = config ? line : executable(line, state, python, js);
    if (/^\s*(?:#|\/\/)/.test(code) || !code.trim()) continue;
    function add(rule, signature, fields) {
      const key = rule + '/' + signature;
      const index = (counts.get(key) || 0) + 1;
      counts.set(key, index);
      matches.push(makeFinding(rule, file.path, i + 1, signature + '#' + index, fields));
    }
    for (const [rule, word, literal, updated] of [
      ['CFG-01', 'debug', 'true', 'false'],
      ['TLS-01', 'verify', 'false', 'true'],
    ]) {
      const pattern = new RegExp('\\b' + word + '\\s*[=:]\\s*' + literal + '\\b', 'i');
      const configKey = new RegExp('^\\s*["\']?' + word + '["\']?\\s*[=:]\\s*' + literal + '\\b', 'i');
      const match = config ? configKey.exec(code) : pattern.exec(code);
      if (!match) continue;
      const plain = /^\s*[\w]+\s*[=:]\s*(true|false)\s*,?\s*$/i.test(line);
      const replacement = line.replace(new RegExp(literal, 'i'), (a) =>
        a === a.toUpperCase()
          ? updated.toUpperCase()
          : a[0] === a[0].toUpperCase()
            ? updated[0].toUpperCase() + updated.slice(1)
            : updated
      );
      add(rule, word, {
        evidence: plain ? line.trim() : 'Matched setting: ' + word + ' = ' + literal,
        patch: plain ? patchLine(file.path, i + 1, line, replacement) : '',
      });
    }
    const secret =
      /\b(api[_-]?key|secret[_-]?key|access[_-]?token|password)["']?\s*[=:]\s*["'][^"'\s]{8,}["']/i.exec(
        line
      );
    if (secret && (config || /\w/.test(code[secret.index] || ' ')))
      add('SEC-01', secret[1].toLowerCase(), { evidence: '[Credential value redacted]' });
    if (python && /\bpickle\.loads?\s*\(/.test(code))
      add('PY-01', 'pickle', { evidence: 'pickle.load / loads call' });
    if (js && /\.innerHTML\s*=(?!=)/.test(code))
      add('WEB-01', 'innerHTML', { evidence: 'Assignment to innerHTML' });
    const query = /\.execute\s*\(\s*(?:f["']|\x60)/i.exec(line);
    if ((python || js) && query && code[query.index] === '.')
      add('SQL-01', 'execute', { evidence: 'Interpolated query passed to execute' });
    if (
      requirements &&
      /^\s*[\w.-]+(?:\[[\w,.-]+\])?\s*(?:(?:>=|<=|~=|!=|>|<)[^#;]+)?\s*(?:#.*)?$/.test(line)
    ) {
      const pkg = line.trim().match(/^[\w.-]+/)[0];
      add('DEP-01', pkg.toLowerCase(), { evidence: pkg + ' · version is not exactly pinned' });
    }
  }
  return matches;
}

export function summarize(findings) {
  const counts = Object.fromEntries(levels.map((level) => [level, 0]));
  let deduction = 0;
  for (const f of findings) {
    counts[f.level]++;
    deduction += weights[f.level] + (f.rule === 'SEC-01' ? 15 : 0);
  }
  findings.sort((a, b) => weights[b.level] - weights[a.level]);
  return {
    findings: findings.slice(0, 300),
    totalFindings: findings.length,
    limited: findings.length > 300,
    counts,
    score: Math.max(0, 100 - deduction),
  };
}

export function scan(files) {
  const eligible = files.filter((f) => supported(f.path));
  return { ...summarize(eligible.flatMap(fileMatches)), paths: eligible.map((f) => f.path) };
}

export function compareEvidence(before, after) {
  const oldPaths = new Set(before.paths ?? before.findings.map((f) => f.path));
  const newPaths = new Set(after.paths ?? after.findings.map((f) => f.path));
  const checkedPackages = (s) =>
    ['complete', 'no-pins'].includes(s.audit?.status) && !(s.audit.unpinned || s.audit.invalid);
  const comparable = (f) =>
    oldPaths.has(f.path) &&
    newPaths.has(f.path) &&
    (f.rule !== 'OSV-01' || [before, after].every(checkedPackages));
  const old = new Map(before.findings.filter(comparable).map((f) => [f.id, f]));
  const next = new Map(after.findings.filter(comparable).map((f) => [f.id, f]));
  const changedCoverage =
    [...oldPaths].some((p) => !newPaths.has(p)) || [...newPaths].some((p) => !oldPaths.has(p));
  const hasAdvisories = [...before.findings, ...after.findings].some((f) => f.rule === 'OSV-01');
  const incomplete = Boolean(
    (hasAdvisories && ![before, after].every(checkedPackages)) ||
      before.limited ||
      after.limited ||
      ['unavailable', 'partial'].includes(before.audit?.status) ||
      ['unavailable', 'partial'].includes(after.audit?.status)
  );
  return {
    fixed: [...old.values()].filter((f) => !next.has(f.id)),
    remaining: [...next.values()].filter((f) => old.has(f.id)),
    introduced: [...next.values()].filter((f) => !old.has(f.id)),
    changedCoverage,
    incomplete,
    delta: after.score - before.score,
  };
}

export function compare(before, after) {
  const c = compareEvidence(before, after);
  return {
    fixed: c.fixed.length,
    remaining: c.remaining.length,
    introduced: c.introduced.length,
    delta: c.delta,
  };
}
