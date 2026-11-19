import { makeFinding, summarize } from './scanner.mjs';

export const maxPackages = 32;
export const packageKey = (p) => [p.ecosystem, p.name, p.version].join('|');

export function validPin(p) {
  if (
    !p ||
    typeof p.name !== 'string' ||
    typeof p.version !== 'string' ||
    p.name.length > 160 ||
    p.version.length > 60
  )
    return false;
  if (p.ecosystem === 'npm')
    return (
      /^(?:@[a-z\d][a-z\d._-]*\/)?[a-z\d][a-z\d._-]*$/i.test(p.name) &&
      /^\d+\.\d+\.\d+(?:[-+][\w.+-]+)?$/.test(p.version)
    );
  return (
    p.ecosystem === 'PyPI' &&
    /^[a-z\d][\w.-]*$/i.test(p.name) &&
    /^\d[\w.+!-]*$/.test(p.version) &&
    !/[*/]/.test(p.version)
  );
}

export function inventory(files) {
  const pins = new Map();
  let unpinned = 0,
    invalid = 0,
    manifests = 0;
  const locks = new Set();
  const ordered = [...files].sort(
    (a, b) => Number(b.path.endsWith('package-lock.json')) - Number(a.path.endsWith('package-lock.json'))
  );
  for (const file of ordered) {
    const base = file.path.split('/').pop();
    if (!/^(?:package(?:-lock)?\.json|requirements(?:[-.][\w-]+)?\.txt)$/.test(base)) continue;
    manifests++;
    const lines = file.content.split(/\r?\n/);
    function record(ecosystem, name, version, line) {
      const item = { ecosystem, name, version };
      if (!validPin(item)) {
        unpinned++;
        return;
      }
      const key = packageKey(item);
      if (!pins.has(key)) pins.set(key, { ...item, path: file.path, line });
    }
    const positions = new Map();
    if (base.endsWith('.json')) {
      for (const [i, line] of lines.entries()) {
        const match = /^\s*"([@\w./+-]+)"\s*:/.exec(line);
        if (match) positions.set(match[1], positions.has(match[1]) ? null : i + 1);
      }
    }
    const lineFor = (key) => positions.get(key) ?? null;
    if (base.endsWith('.txt')) {
      for (const [i, raw] of lines.entries()) {
        const entry = raw.split('#')[0].trim();
        if (!entry) continue;
        const match = /^([\w.-]+)(?:\[[\w.,-]+\])?\s*==\s*([\w.+!-]+)$/.exec(entry);
        if (match) record('PyPI', match[1].toLowerCase().replace(/[-_.]+/g, '-'), match[2], i + 1);
        else unpinned++;
      }
      continue;
    }
    let parsed;
    try {
      parsed = JSON.parse(file.content);
    } catch {
      invalid++;
      continue;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      invalid++;
      continue;
    }
    const folder = file.path.slice(0, -base.length);
    if (base === 'package-lock.json') {
      if (!parsed.packages || typeof parsed.packages !== 'object') {
        invalid++;
        continue;
      }
      locks.add(folder);
      for (const [key, entry] of Object.entries(parsed.packages)) {
        if (!key.includes('node_modules/') || !entry || entry.link) continue;
        record('npm', entry.name || key.split('node_modules/').at(-1), entry.version, lineFor(key));
      }
    } else if (!locks.has(folder)) {
      const dependencies = {
        ...parsed.dependencies,
        ...parsed.devDependencies,
        ...parsed.optionalDependencies,
        ...parsed.peerDependencies,
      };
      for (const [name, version] of Object.entries(dependencies))
        record('npm', name, version, lineFor(name));
    }
  }
  return { pins: [...pins.values()], manifests, unpinned, invalid };
}

export function withAudit(base, inventory, audit) {
  const pinMap = new Map(inventory.pins.map((p) => [packageKey(p), p]));
  const identified = new Map();
  for (const result of audit.results || []) {
    const p = pinMap.get(packageKey(result));
    if (!p) continue;
    for (const a of result.advisories) {
      const id = JSON.stringify([p.path, 'OSV-01', p.ecosystem, p.name, a.id]);
      if (identified.has(id)) {
        identified.get(id).evidence += ', ' + p.version;
        continue;
      }
      identified.set(
        id,
        makeFinding('OSV-01', p.path, p.line, id, {
          id,
          level: a.level,
          title: p.name + ' · ' + a.id,
          evidence: p.ecosystem + ' / ' + p.name + '@' + p.version,
          reference: 'https://osv.dev/vulnerability/' + encodeURIComponent(a.id),
          advisory: a.id,
        })
      );
    }
  }
  const extra = [...identified.values()];
  // Preserve the full base score/counts when the display limit was hit.
  const merged = summarize([...base.findings, ...extra]);
  if (base.limited) {
    const additions = summarize(extra);
    merged.score = Math.max(0, base.score - (100 - additions.score));
    for (const level of Object.keys(base.counts))
      merged.counts[level] = base.counts[level] + additions.counts[level];
    merged.totalFindings = base.totalFindings + extra.length;
    merged.limited = true;
  }
  return {
    ...merged,
    paths: base.paths,
    audit: {
      status:
        inventory.invalid && ['complete', 'no-pins'].includes(audit.status) ? 'partial' : audit.status,
      checked: audit.checked,
      total: inventory.pins.length,
      manifests: inventory.manifests,
      unpinned: inventory.unpinned,
      invalid: inventory.invalid,
      limited: Math.max(0, inventory.pins.length - audit.checked),
      advisoryCount: extra.length,
    },
  };
}
