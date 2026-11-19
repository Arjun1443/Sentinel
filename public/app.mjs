import { answerQuestion } from './assistant.mjs';
import { scan, compareEvidence, supported } from './scanner.mjs';
import { inventory, maxPackages, withAudit } from './dependencies.mjs';
import { markdown, sarif, sourceUrl } from './report.mjs';
import { levels } from './rules.mjs';
import { importSarif } from './import-sarif.mjs';

const $ = (id) => document.getElementById(id);
const sample = [
  { path: 'settings.py', content: 'debug = True\n' },
  { path: 'client.py', content: 'verify = False\n' },
  { path: 'requirements.txt', content: 'example-package>=1\n' },
];
const revised = [
  { path: 'settings.py', content: 'debug = False\n' },
  { path: 'client.py', content: 'verify = True\n' },
  sample[2],
];
const baselines = new Map();
const cache = new Map();
let current,
  busy = false;
const historyKey = 'sentinel.public-scans.v2';
const now = () => new Date().toISOString();
const signed = (n) => (n >= 0 ? '+' : '') + n;

function add(parent, tag, value, cls) {
  const node = document.createElement(tag);
  if (value !== undefined) node.textContent = value;
  if (cls) node.className = cls;
  parent.append(node);
  return node;
}
function link(parent, title, url, cls) {
  const el = add(parent, 'a', title, cls);
  el.href = url;
  el.target = '_blank';
  el.rel = 'noopener noreferrer';
  return el;
}
function button(parent, title, fn) {
  const el = add(parent, 'button', title, 'secondary');
  el.type = 'button';
  el.onclick = fn;
  return el;
}
function download(name, value, type = 'text/plain;charset=utf-8') {
  const url = URL.createObjectURL(new Blob([value], { type }));
  const anchor = Object.assign(document.createElement('a'), { href: url, download: name });
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
function setMode(mode) {
  for (const el of document.querySelectorAll('[data-mode]'))
    el.setAttribute('aria-pressed', String(el.dataset.mode === mode));
  for (const el of document.querySelectorAll('[data-pane]')) el.hidden = el.dataset.pane !== mode;
}
for (const el of document.querySelectorAll('[data-mode]')) el.onclick = () => setMode(el.dataset.mode);
function status(value, err = false) {
  $('status').textContent = value;
  $('status').dataset.error = String(err);
}
async function run(progress, work) {
  if (busy) return;
  busy = true;
  const controls = ['case', 'scan-repo', 'demo', 'revised', 'audit-demo', 'files', 'sarif-file'];
  for (const id of controls) $(id).disabled = true;
  status(progress);
  try {
    await work();
  } catch (e) {
    status(e.message || 'Scan unavailable. Please try again.', true);
  } finally {
    busy = false;
    for (const id of controls) $(id).disabled = false;
  }
}
async function json(url, options) {
  const res = await fetch(url, options);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw Error(body.error || 'The service returned ' + res.status + '. Please try again.');
  return body;
}
function history() {
  try {
    const rows = JSON.parse(localStorage.getItem(historyKey) || '[]');
    return Array.isArray(rows)
      ? rows
          .filter(
            (r) =>
              typeof r?.repo === 'string' &&
              /^[\w.-]+\/[\w.-]+$/.test(r.repo) &&
              /^[a-f\d]{40}$/i.test(r.sha)
          )
          .slice(0, 8)
      : [];
  } catch {
    return [];
  }
}
function saveHistory(view) {
  try {
    const entry = { repo: view.repo, sha: view.sha, score: view.output.score, time: view.time };
    const rows = history().filter((r) => r.repo !== entry.repo || r.sha !== entry.sha);
    localStorage.setItem(historyKey, JSON.stringify([entry, ...rows].slice(0, 8)));
  } catch {
    /* Storage is optional in private browsing. */
  }
  renderHistory();
}
function renderHistory() {
  const root = $('history-list');
  root.replaceChildren();
  const rows = history();
  $('clear-history').hidden = !rows.length;
  if (!rows.length) add(root, 'p', 'Your first public repository scan will appear here.', 'empty');
  for (const r of rows) {
    const row = add(root, 'div', undefined, 'history-row');
    add(row, 'strong', r.repo);
    add(
      row,
      'span',
      r.sha.slice(0, 8) + ' · ' + r.score + '/100 · ' + new Date(r.time).toLocaleDateString()
    );
    button(row, 'Use as baseline', () => {
      setMode('github');
      $('repo').value = 'https://github.com/' + r.repo;
      $('baseline').value = r.sha;
      $('revision').value = '';
      $('revision-options').open = true;
      $('workbench').scrollIntoView();
      $('scan-repo').focus({ preventScroll: true });
    });
  }
}
$('clear-history').onclick = () => {
  try {
    localStorage.removeItem(historyKey);
  } catch {}
  renderHistory();
};
renderHistory();

function guidance(parent, brief, label) {
  parent.replaceChildren();
  add(parent, 'small', label);
  for (const [key, heading] of [
    ['impact', 'Why it matters'],
    ['fix', 'Suggested action'],
    ['verify', 'How to verify'],
  ]) {
    const p = add(parent, 'p');
    add(p, 'strong', heading + ' · ');
    p.append(document.createTextNode(brief[key]));
  }
}
async function openBrief(f, target, control) {
  control.disabled = true;
  target.hidden = false;
  target.textContent = 'Preparing the finding brief…';
  try {
    if (!cache.has(f.rule))
      cache.set(
        f.rule,
        json('/api/brief?rule=' + encodeURIComponent(f.rule)).catch((e) => {
          cache.delete(f.rule);
          throw e;
        })
      );
    const a = await cache.get(f.rule);
    if (a.mode !== 'model') cache.delete(f.rule);
    guidance(
      target,
      a.brief,
      a.mode === 'model'
        ? 'AI explanation · ' + a.provider + ' / ' + a.model
        : 'Rule guidance · live model unavailable'
    );
  } catch {
    guidance(target, f, 'Rule guidance · live model unavailable');
  } finally {
    control.disabled = false;
  }
}
function renderFindings() {
  const target = $('findings');
  target.replaceChildren();
  const choice = $('view-filter').value;
  const list = choice === 'current' ? current.output.findings : current.change[choice];
  const filtered = list.filter((f) => !$('filter').value || f.level === $('filter').value);
  if (!filtered.length) add(target, 'p', 'No matches in this view.', 'empty');
  for (const f of filtered) {
    const card = add(target, 'article', undefined, 'finding');
    add(card, 'span', f.level === 'review' ? 'Ungraded' : f.level, 'badge ' + f.level);
    add(card, 'span', f.rule + ' / ' + f.group, 'rule-code');
    add(card, 'h3', f.title);
    const location = f.path + (f.line ? ':' + f.line : ' · manifest');
    const href = sourceUrl(choice === 'fixed' ? current.priorLink : current.link, f);
    if (href) link(card, location, href, 'location');
    else add(card, 'span', location, 'location');
    add(card, 'pre', f.evidence);
    add(card, 'p', f.impact);
    add(card, 'p', f.fix);
    if (f.reference)
      link(
        card,
        f.advisory ? 'Read ' + f.advisory + ' on OSV ↗' : 'Technical reference ↗',
        f.reference,
        'reference'
      );
    if (f.patch) {
      const d = add(card, 'details', undefined, 'options');
      add(d, 'summary', 'Review suggested patch');
      add(d, 'pre', f.patch);
      button(d, 'Download patch', () => download('sentinel-' + f.rule + '.patch', f.patch));
    }
    const actions = add(card, 'div', undefined, 'controls');
    const brief = add(card, 'div', undefined, 'brief');
    brief.hidden = true;
    const control = button(actions, 'Explain this finding', () => openBrief(f, brief, control));
    button(actions, 'Validation step', () => {
      brief.hidden = false;
      brief.replaceChildren();
      add(brief, 'small', 'Developer check');
      add(brief, 'p', f.verify);
    });
  }
}
$('filter').onchange = renderFindings;
$('view-filter').onchange = renderFindings;
function auditCaption(a) {
  if (!a) return 'Static rules only.';
  const labels = {
    complete: 'OSV lookup complete',
    'no-pins': 'No exact package versions to query',
    partial: 'Partial OSV coverage',
    unavailable: 'OSV unavailable · review incomplete',
    skipped: 'OSV lookup skipped',
  };
  return (
    (labels[a.status] || 'Dependency check') +
    ' · ' +
    a.checked +
    '/' +
    a.total +
    ' exact versions checked' +
    (a.unpinned ? ' · ' + a.unpinned + ' unresolved declaration(s)' : '') +
    (a.invalid ? ' · ' + a.invalid + ' unreadable manifest(s)' : '') +
    '.'
  );
}
function show(view, previous) {
  current = {
    ...view,
    priorLink: previous?.link,
    priorPartial: previous?.partial,
    change: previous ? compareEvidence(previous.output, view.output) : null,
  };
  $('answer').hidden = true;
  $('answer').replaceChildren();
  $('question').value = '';
  $('source').textContent = view.name;
  $('result-title').textContent = view.title || 'Review results';
  $('metadata').textContent = view.coverage;
  $('results').hidden = false;
  $('proof').hidden = true;
  $('metrics').replaceChildren();
  for (const [label, value] of [
    ['score / 100', view.output.score],
    ...levels
      .filter((l) => l !== 'review' || view.output.counts.review)
      .map((l) => [l === 'review' ? 'ungraded' : l, view.output.counts[l]]),
  ]) {
    const m = add($('metrics'), 'div', undefined, 'metric' + (label === 'score / 100' ? ' score' : ''));
    add(m, 'strong', value);
    add(m, 'span', label);
  }
  $('audit-state').textContent =
    auditCaption(view.output.audit) + (view.output.limited ? ' First 300 findings shown.' : '');
  const c = current.change;
  const comparison = $('comparison');
  comparison.hidden = !c;
  comparison.replaceChildren();
  const select = $('view-filter');
  select.replaceChildren();
  function option(key, label) {
    const opt = add(select, 'option', label);
    opt.value = key;
  }
  option('current', 'Current findings (' + view.output.totalFindings + ')');
  if (c) {
    const comparability = c.changedCoverage || c.incomplete || view.partial || previous.partial;
    add(
      comparison,
      'strong',
      'Score ' +
        signed(c.delta) +
        ' · ' +
        c.fixed.length +
        ' gone · ' +
        c.remaining.length +
        ' remaining · ' +
        c.introduced.length +
        ' new'
    );
    add(
      comparison,
      'p',
      comparability
        ? 'Scope or advisory coverage is partial. Counts describe observed matches in shared files.'
        : 'Compared the same file scope across both scans.'
    );
    for (const [key, label] of [
      ['fixed', 'Gone since baseline'],
      ['introduced', 'New'],
      ['remaining', 'Remaining'],
    ])
      option(key, label + ' (' + c[key].length + ')');
    if (view.output.totalFindings === 0 && c.fixed.length) select.value = 'fixed';
  }
  $('filter').value = '';
  renderFindings();
  $('results').focus({ preventScroll: true });
  $('results').scrollIntoView({ block: 'start' });
}
function fromRepo(data) {
  return {
    repo: data.name,
    name: data.name,
    sha: data.sha,
    link: data.link,
    time: now(),
    output: data.output,
    partial: data.count < data.eligible || data.unavailable > 0 || data.truncated,
    coverage: [
      data.branch,
      data.sha.slice(0, 8),
      data.language,
      data.count + ' of ' + data.eligible + ' eligible files scanned',
      data.total + ' listed',
      data.unavailable ? data.unavailable + ' unreadable' : '',
      data.truncated ? 'partial tree' : '',
    ]
      .filter(Boolean)
      .join(' · '),
  };
}
function fetchRepo(url, ref) {
  const q = new URLSearchParams({ url });
  if (ref) q.set('ref', ref);
  return json('/api/repository?' + q).then(fromRepo);
}
$('repo-form').onsubmit = (event) => {
  event.preventDefault();
  run('Reading commit-pinned source and checking exact dependency versions…', async () => {
    const url = $('repo').value.trim(),
      base = $('baseline').value.trim(),
      revision = $('revision').value.trim();
    const [view, prior] = await Promise.all([
      fetchRepo(url, revision),
      base ? fetchRepo(url, base) : Promise.resolve(null),
    ]);
    const key = 'repo:' + view.repo.toLowerCase();
    show(view, prior || baselines.get(key));
    baselines.set(key, view);
    saveHistory(view);
    status('Repository scan complete.');
  });
};
async function localView(files, name, lookup, scope) {
  const eligible = files.filter((f) => supported(f.path));
  if (!eligible.length) throw Error('Choose at least one supported source or manifest file.');
  const idx = inventory(eligible);
  let audit = { status: idx.pins.length ? 'skipped' : 'no-pins', checked: 0, results: [] };
  if (lookup && idx.pins.length) {
    const packages = idx.pins
      .slice(0, maxPackages)
      .map(({ ecosystem, name, version }) => ({ ecosystem, name, version }));
    try {
      audit = await json('/api/advisories', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ packages }),
      });
      if (idx.pins.length > maxPackages && audit.status === 'complete') audit.status = 'partial';
    } catch {
      audit = { status: 'unavailable', checked: 0, results: [] };
    }
  }
  return {
    name,
    coverage: scope + ' · ' + eligible.length + ' of ' + files.length + ' files scanned',
    time: now(),
    output: withAudit(scan(eligible), idx, audit),
  };
}
$('files').onchange = () => {
  const selected = Array.from($('files').files);
  $('files').value = '';
  if (!selected.length) return;
  run('Reviewing local files…', async () => {
    if (
      selected.length > 60 ||
      selected.some((f) => f.size > 524288) ||
      selected.reduce((sum, f) => sum + f.size, 0) > 3000000
    )
      throw Error('Select up to 60 files, at most 512 KiB each and 3 MB total.');
    const files = await Promise.all(selected.map(async (f) => ({ path: f.name, content: await f.text() })));
    if (new Set(files.map((f) => f.path)).size !== files.length)
      throw Error('Select files with unique names so the evidence can identify each file.');
    const key = 'local:' + JSON.stringify(files.map((f) => f.path).sort());
    const view = await localView(files, 'Local files', $('allow-osv').checked, 'Browser session');
    show(view, baselines.get(key));
    baselines.set(key, view);
    status('Local review complete.');
  });
};
$('sarif-file').onchange = () => {
  const file = $('sarif-file').files[0];
  $('sarif-file').value = '';
  if (!file) return;
  run('Reading the SARIF report in your browser…', async () => {
    if (file.size > 3000000) throw Error('Choose a SARIF report under 3 MB.');
    const report = importSarif(JSON.parse(await file.text()));
    show({
      name: 'Local SARIF report',
      time: now(),
      output: report.output,
      coverage:
        report.origins.join(', ') +
        ' · imported results only · ' +
        report.omitted +
        ' unsupported locations skipped',
    });
    status('Imported the scanner evidence. Source snippets stay out of the review.');
  });
};
$('demo').onclick = () =>
  run('Scanning the built-in sample…', async () => {
    const v = await localView(sample, 'Configuration sample', false, 'Sample baseline');
    baselines.set('sample', v);
    show(v);
    $('revised').hidden = false;
    status('Sample baseline ready. Scan the revised sample to compare.');
  });
$('revised').onclick = () =>
  run('Scanning revised sample…', async () => {
    const view = await localView(revised, 'Configuration sample', false, 'Revised sample');
    show(view, baselines.get('sample'));
    status('Revised sample complete.');
  });
$('audit-demo').onclick = () =>
  run('Looking up the exact npm version with OSV…', async () => {
    const files = [
      {
        path: 'package.json',
        content: JSON.stringify({ dependencies: { 'ansi-regex': '5.0.0' } }, null, 2),
      },
    ];
    const view = await localView(files, 'Dependency sample', true, 'Manifest-only example');
    show(view);
    status(
      view.output.audit.status === 'unavailable'
        ? 'OSV unavailable. The audit is marked incomplete.'
        : 'Dependency lookup complete.'
    );
  });
async function blobDigest(content) {
  const bytes = new TextEncoder().encode(content);
  const head = new TextEncoder().encode('blob ' + bytes.byteLength + '\0');
  const joined = new Uint8Array(head.length + bytes.length);
  joined.set(head);
  joined.set(bytes, head.length);
  const hash = await crypto.subtle.digest('SHA-1', joined);
  return Array.from(new Uint8Array(hash), (b) => b.toString(16).padStart(2, '0')).join('');
}
function replay() {
  return run('Checking the two commit snapshots and rescanning vercel.json…', async () => {
    const record = await json('/verified-case.json');
    const repo = 'Arjun1443/Sentinel';
    const root = 'https://github.com/' + repo;
    async function view(revision) {
      if ((await blobDigest(revision.content)) !== revision.blob)
        throw Error('Snapshot integrity check failed. Reload the case.');
      return {
        repo,
        name: repo + ' / verified case',
        sha: revision.sha,
        link: root + '/blob/' + revision.sha,
        time: now(),
        title: 'One browser policy fixed',
        coverage: 'vercel.json only · two pinned Git commits · both file digests checked',
        output: scan([{ path: record.path, content: revision.content }]),
      };
    }
    const [before, after] = await Promise.all([view(record.before), view(record.after)]);
    show(after, before);
    const panel = $('proof');
    panel.replaceChildren();
    panel.hidden = false;
    add(panel, 'h3', 'Verified case · form submissions restricted to this origin');
    const note = add(
      panel,
      'p',
      'Baseline ' +
        before.output.score +
        ' → revised ' +
        after.output.score +
        ' / 100 for vercel.json. Checking the live response header…'
    );
    const refs = add(panel, 'div', undefined, 'proof-links');
    link(refs, 'Before ' + before.sha.slice(0, 8) + ' ↗', before.link + '/' + record.path);
    link(refs, 'After ' + after.sha.slice(0, 8) + ' ↗', after.link + '/' + record.path);
    link(refs, 'GitHub diff ↗', root + '/compare/' + before.sha + '...' + after.sha);
    link(refs, 'Regression test ↗', after.link + '/test/headers.test.mjs');
    link(refs, 'Passing CI run ↗', 'https://github.com/Arjun1443/Sentinel/actions/runs/44478067576');
    const receipts = add(panel, 'div', undefined, 'proof-links');
    add(receipts, 'span', 'Semgrep CE · 1 → 0 matches');
    for (const [label, file] of [
      ['Baseline SARIF', 'before'],
      ['Revised SARIF', 'after'],
    ]) {
      const a = add(receipts, 'a', label + ' ↓');
      a.href = '/evidence/' + file + '.sarif';
      a.download = 'sentinel-' + file + '.sarif';
    }
    try {
      const res = await fetch('/', { method: 'HEAD', cache: 'no-store' });
      const directives = (res.headers.get('Content-Security-Policy') || '').split(';').map((d) => d.trim());
      const confirmed = directives.includes("form-action 'self'");
      note.textContent =
        'File score ' +
        before.output.score +
        ' → ' +
        after.output.score +
        '/100. ' +
        (confirmed
          ? 'The live response also contains the same-origin form policy.'
          : 'Live response policy could not be confirmed here.');
    } catch {
      note.textContent =
        'File score ' +
        before.output.score +
        ' → ' +
        after.output.score +
        '/100. Live response header unavailable.';
    }
    status('Verified both Git file digests and rescanned the original and revised configuration.');
  });
}
$('case').onclick = replay;
$('export').onclick = () => download('sentinel-security-review.md', markdown(current));
$('sarif').onclick = () =>
  download('sentinel-security-review.sarif', JSON.stringify(sarif(current), null, 2), 'application/json');
let intentModel;
async function ask(question) {
  const view = current,
    target = $('answer');
  target.hidden = false;
  target.textContent = 'Reading this scan…';
  try {
    if (!intentModel)
      intentModel = json('/intent-model.json').catch((err) => {
        intentModel = null;
        throw err;
      });
    const a = answerQuestion(question, await intentModel, view);
    if (view !== current) return;
    target.replaceChildren();
    add(target, 'small', 'On-device answer' + (a.intent ? ' · ' + a.intent : ''));
    add(target, 'p', a.text);
    for (const { f, side } of a.citations) {
      const text =
        f.rule + ' · ' + f.path + (f.line ? ':' + f.line : '') + (side === 'fixed' ? ' (baseline)' : '');
      const url = sourceUrl(side === 'fixed' ? view.priorLink : view.link, f);
      if (url) link(target, text, url, 'location');
      else add(target, 'span', text, 'location');
    }
  } catch {
    if (view === current) target.textContent = 'The on-device model could not load. Try again.';
  }
}
$('ask-form').onsubmit = (e) => {
  e.preventDefault();
  const q = $('question').value.trim();
  if (q) ask(q);
};
for (const b of document.querySelectorAll('[data-question]'))
  b.onclick = () => {
    const q = b.dataset.question;
    $('question').value = q;
    ask(q);
  };
if (new URLSearchParams(location.search).get('case') === 'verified') replay();
