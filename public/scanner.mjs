const rules = [
  { id: 'CFG-01', level: 'high', title: 'Debug mode enabled', pattern: /\bdebug\s*[=:]\s*(?:true|True)\b/, fix: 'Disable debug mode in production configuration, then confirm error responses hide stack traces.', replace: line => line.replace(/(\bdebug\s*[=:]\s*)(true|True)\b/, (_, prefix, value) => prefix + (value === 'True' ? 'False' : 'false')) },
  { id: 'TLS-01', level: 'high', title: 'TLS certificate verification disabled', pattern: /\bverify\s*=\s*False\b/, fix: 'Enable certificate verification and configure a trusted CA bundle for internal services.', replace: line => line.replace(/(\bverify\s*=\s*)False\b/, '$1True') },
  { id: 'SEC-01', level: 'critical', title: 'Possible embedded credential', pattern: /\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|password)\s*[=:]\s*["'][^"'\s]{8,}["']/i, fix: 'Rotate the credential if active, remove it from source, and load the replacement from a secret manager.', redact: true },
  { id: 'PY-01', level: 'high', title: 'Review unsafe pickle deserialization', pattern: /\bpickle\.loads?\s*\(/, fix: 'Replace pickle at untrusted input boundaries with a data-only format and validate the parsed schema.', redact: true },
  { id: 'WEB-01', level: 'medium', title: 'Review HTML insertion', pattern: /\.innerHTML\s*=(?!=)/, fix: 'Use textContent for plain text. Where HTML is required, sanitize it with a maintained library.', redact: true },
  { id: 'SQL-01', level: 'high', title: 'Review interpolated SQL', pattern: /\.execute\s*\(\s*(?:f["']|`)/, fix: 'Use the database driver’s parameter binding. Test that the query logic is unchanged across valid input values.', redact: true },
  { id: 'DEP-01', level: 'low', title: 'Dependency version needs review', pattern: /^[\w.-]+(?:\[[\w,.-]+\])?(?:\s*(?:[<>~!]=?|=)[^=].*)?$/, file: /(?:^|\/)requirements\.txt$/, fix: 'Record a reproducible lockfile and check resolved versions against an advisory database.', redact: true },
];
const weights = { critical: 18, high: 10, medium: 4, low: 1 };

export function scan(files) {
  const findings = [];
  const occurrences = new Map();
  for (const {path, content} of files) {
    if (!/\.(py|[cm]?js|tsx?|json|env|ya?ml|txt|toml|ini|cfg)$/i.test(path)) continue;
    content.split(/\r?\n/).forEach((line, i) => {
      if (/^\s*(?:#|\/\/)/.test(line)) return;
      for (const rule of rules) {
        if (rule.file && !rule.file.test(path)) continue;
        if (!rule.pattern.test(line)) continue;
        const key = JSON.stringify([path, rule.id]);
        const count = (occurrences.get(key) || 0) + 1;
        occurrences.set(key, count);
        const replacement = rule.replace?.(line);
        const plain = !rule.redact && /^[\s\w.:=,-]{1,240}$/.test(line);
        const patch = plain && replacement && !/[\r\n\t]/.test(path)
          ? ['--- a/' + path, '+++ b/' + path, '@@ -' + (i+1) + ',1 +' + (i+1) + ',1 @@', '-' + line, '+' + replacement, ''].join('\n')
          : '';
        findings.push({ id: JSON.stringify([path, rule.id, count]), rule: rule.id, level: rule.level, title: rule.title, path, line: i + 1, evidence: plain ? line.trim() : rule.redact && rule.id === 'SEC-01' ? '[Credential value redacted]' : '[Source omitted. Review this line in the repository.]', fix: rule.fix, patch });
      }
    });
  }
  findings.sort((a,b) => weights[b.level] - weights[a.level]);
  return { findings, score: Math.max(0, 100 - findings.reduce((n,f) => n + weights[f.level] + (f.rule === 'SEC-01' ? 15 : 0), 0)) };
}

export function compare(before, after) {
  const prior = new Set(before.findings.map(f => f.id));
  const next = new Set(after.findings.map(f => f.id));
  return {
    fixed: before.findings.filter(f => !next.has(f.id)).length,
    remaining: after.findings.filter(f => prior.has(f.id)).length,
    introduced: after.findings.filter(f => !prior.has(f.id)).length,
    delta: after.score - before.score,
  };
}
