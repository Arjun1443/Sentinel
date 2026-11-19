import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { scan, compare } from '../public/scanner.mjs';
import { importSarif } from '../public/import-sarif.mjs';
import { markdown, sarif } from '../public/report.mjs';
import { explain, parseBrief } from '../lib/brief.mjs';
import { selectFiles } from '../api/repository.js';

const read = (p) => JSON.parse(readFileSync(new URL('../public/' + p, import.meta.url)));
const record = read('verified-case.json');
test('built-in case verifies Git blob hashes and agrees with independent Semgrep reports', () => {
  const results = [];
  for (const stage of ['before', 'after']) {
    const s = record[stage],
      bytes = Buffer.from(s.content);
    assert.equal(
      createHash('sha1')
        .update('blob ' + bytes.length + '\0')
        .update(bytes)
        .digest('hex'),
      s.blob
    );
    const input = read('evidence/' + stage + '.sarif');
    assert.equal(input.runs[0].versionControlProvenance[0].revisionId, s.sha);
    const imported = importSarif(input).output;
    const output = scan([{ path: record.path, content: s.content }]);
    assert.deepEqual(
      imported.findings.map((f) => [f.rule, f.line]),
      output.findings.map((f) => [f.rule, f.line])
    );
    results.push(output);
  }
  assert.deepEqual(compare(...results), { fixed: 1, remaining: 0, introduced: 0, delta: 4 });
});
test('untrusted SARIF source text is excluded and unsupported file URIs are skipped', () => {
  const input = read('evidence/before.sarif');
  const row = input.runs[0].results[0];
  row.message.text = 'untrusted source text';
  row.locations[0].physicalLocation.region.snippet.text = 'untrusted source text';
  assert.doesNotMatch(JSON.stringify(importSarif(input)), /untrusted source text/);
  row.locations[0].physicalLocation.artifactLocation.uri = 'file:///outside';
  assert.equal(importSarif(input).omitted, 1);
});
test('Markdown and SARIF exports carry line evidence and the correct revision', () => {
  const output = scan([{ path: record.path, content: record.before.content }]);
  const v = {
    repo: record.repo,
    name: record.repo,
    sha: record.before.sha,
    link: 'https://github.com/' + record.repo + '/blob/' + record.before.sha,
    coverage: 'vercel.json',
    time: 'test',
    output,
  };
  assert.match(markdown(v), new RegExp(record.before.sha + '/vercel.json#L8'));
  const r = sarif(v).runs[0];
  assert.equal(r.versionControlProvenance[0].revisionId, record.before.sha);
  assert.equal(r.results[0].locations[0].physicalLocation.region.startLine, 8);
});
test('rule briefs validate provider output and identify provider outages', async () => {
  assert.equal(parseBrief('{"fix":"missing fields"}'), null);
  const ok = {
    impact: 'A form needs a defined destination.',
    fix: 'Restrict forms to the intended origin.',
    verify: 'Read the deployed response header.',
  };
  let payload;
  const good = await explain('CSP-01', { GROQ_API_KEY: 'test-only' }, async (url, opt) => {
    payload = JSON.parse(opt.body);
    return Response.json({ choices: [{ message: { content: JSON.stringify(ok) } }] });
  });
  assert.equal(good.mode, 'model');
  assert.deepEqual(good.brief, ok);
  assert.doesNotMatch(JSON.stringify(payload), /Arjun1443|vercel\.json/);
  const fallback = await explain('CSP-01', {}, async () => {
    throw Error('unexpected network request');
  });
  assert.equal(fallback.mode, 'catalog');
});
test('sampling prioritizes manifests and excludes vendored files and oversized content', () => {
  const files = [
    ...Array.from({ length: 50 }, (_, i) => ({ path: 'src/' + i + '.js', size: 200, mode: '100644' })),
    { path: 'package-lock.json', size: 250000 },
    { path: 'node_modules/test.js', size: 50 },
    { path: 'large.py', size: 500000 },
  ];
  const { selected, eligible } = selectFiles(files);
  assert.equal(eligible, 51);
  assert.equal(selected.length, 40);
  assert.equal(selected[0].path, 'package-lock.json');
});
