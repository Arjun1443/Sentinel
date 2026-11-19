import {scan, compare} from './scanner.mjs';

const $ = id => document.getElementById(id);
const levels = ['critical', 'high', 'medium', 'low'];
const demo = [{path:'settings.py', content:'debug = True\n'}, {path:'client.py', content:'verify = False\n'}, {path:'requirements.txt', content:'example-package>=1\n'}];
const revised = [{path:'settings.py', content:'debug = False\n'}, {path:'client.py', content:'verify = True\n'}, demo[2]];
const baselines = new Map();
let current;
let busy = false;

function add(parent, tag, value, className) {
  const node = document.createElement(tag);
  node.textContent = value;
  if (className) node.className = className;
  parent.append(node);
  return node;
}

function download(name, value) {
  const url = URL.createObjectURL(new Blob([value], {type:'text/plain;charset=utf-8'}));
  const link = Object.assign(document.createElement('a'), {href:url, download:name});
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function show(output, key, name, coverage, link) {
  const previous = baselines.get(key);
  const comparison = previous && compare(previous, output);
  baselines.set(key, output);
  current = { ...output, name, coverage, link, comparison };
  $('source').textContent = name;
  $('metadata').textContent = coverage;
  $('metrics').replaceChildren();
  for (const [label, value] of [['Score / 100', output.score], ...levels.map(level => [level, output.findings.filter(f => f.level === level).length])]) {
    const metric = add($('metrics'), 'div', '', 'metric');
    add(metric, 'strong', value);
    add(metric, 'span', label);
  }
  $('comparison').hidden = !comparison;
  if (comparison) $('comparison').textContent = `Score ${comparison.delta >= 0 ? '+' : ''}${comparison.delta} · ${comparison.fixed} fewer matches · ${comparison.remaining} remaining · ${comparison.introduced} new`;
  $('results').hidden = false;
  render();
}

function render() {
  const target = $('findings');
  target.replaceChildren();
  const level = $('filter').value;
  const findings = current.findings.filter(f => !level || f.level === level);
  if (!findings.length) add(target, 'p', 'No rule matches in this view.');
  for (const f of findings) {
    const card = add(target, 'article', '', 'finding');
    add(card, 'span', f.level.toUpperCase() + ' · ' + f.rule, 'badge ' + f.level);
    add(card, 'h3', f.title);
    const location = add(card, current.link ? 'a' : 'p', f.path + ':' + f.line, 'location');
    if (current.link) location.href = current.link + '/' + f.path.split('/').map(encodeURIComponent).join('/') + '#L' + f.line;
    add(card, 'pre', f.evidence);
    add(card, 'p', f.fix);
    if (f.patch) {
      const details = add(card, 'details', '');
      add(details, 'summary', 'Review suggested patch');
      add(details, 'pre', f.patch);
      const button = add(details, 'button', 'Download patch', 'secondary');
      button.onclick = () => download('sentinel-' + f.rule + '.patch', f.patch);
    }
  }
}

$('filter').onchange = render;
$('demo').onclick = () => {
  baselines.delete('demo');
  show(scan(demo), 'demo', 'Built-in demo', '3 sample files · configuration and dependency review');
  $('revised').hidden = false;
};
$('revised').onclick = () => show(scan(revised), 'demo', 'Revised demo', '3 sample files · revised configuration');
$('files').onchange = async () => {
  const selection = Array.from($('files').files);
  $('files').value = '';
  if (!selection.length) return;
  if (selection.length > 60 || selection.some(f => f.size > 80000)) {
    $('status').textContent = 'Choose up to 60 text files, each under 80 KB.';
    return;
  }
  try {
    const files = await Promise.all(selection.map(async f => ({path:f.name, content:await f.text()})));
    if (new Set(files.map(f => f.path)).size !== files.length) throw Error('Select files with unique names for local comparison.');
    const key = JSON.stringify(files.map(f => f.path).sort());
    show(scan(files), key, 'Local file review', `${files.length} selected files · ${new Date().toLocaleString()}`);
    $('status').textContent = 'Local scan complete. Select the same filenames again to compare changes.';
  } catch (error) { $('status').textContent = error.message; }
};
$('repo-form').onsubmit = async event => {
  event.preventDefault();
  if (busy) return;
  busy = true;
  $('scan-repo').disabled = true;
  $('status').textContent = 'Fetching a bounded set of repository files…';
  try {
    const response = await fetch('/api/repository?url=' + encodeURIComponent($('repo').value));
    const data = await response.json();
    if (!response.ok) throw Error(data.error || 'Repository scan failed.');
    show(data.output, data.name.toLowerCase(), data.name, `${data.branch} · ${data.language} · ${data.count} scanned files of ${data.total} listed files${data.truncated ? ' (partial listing)' : ''} · ${new Date().toLocaleString()}`, data.link);
    $('status').textContent = 'Repository scan complete.';
  } catch (error) { $('status').textContent = error.message; }
  finally {
    busy = false;
    $('scan-repo').disabled = false;
  }
};
$('export').onclick = () => {
  const {name, coverage, score, findings, comparison} = current;
  const literal = value => String(value).replace(/[<>\[\]`\r\n]/g, ' ');
  const body = findings.map(f => `### ${f.level.toUpperCase()} · ${f.title}\n\n${literal(f.path)} line ${f.line} · ${f.rule}\n\n${f.fix}`).join('\n\n');
  download('sentinel-security-review.md', `# Sentinel security review\n\n${literal(name)}\n\n${literal(coverage)}\n\nScore: ${score}/100\n\n${comparison ? `Score change: ${comparison.delta}. Fewer matches: ${comparison.fixed}. Remaining: ${comparison.remaining}. New: ${comparison.introduced}.\n\n` : ''}${body || 'No rule matches.'}\n\nScope: static rule matches require developer review.\n`);
};
