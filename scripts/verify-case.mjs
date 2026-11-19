import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { scan, compare } from '../public/scanner.mjs';

const cwd = fileURLToPath(new URL('..', import.meta.url));
const git = (...args) => execFileSync('git', args, { cwd, encoding: 'utf8' });
const repo = 'Arjun1443/Sentinel',
  path = 'vercel.json';
const beforeSha = '042bb9ea0a170b254297b8d72b682682da3c9f17';
const afterSha = '16654c9e991ccf5eba76ae65f95214c20410563a';
assert.equal(git('rev-parse', afterSha + '^').trim(), beforeSha);
function snapshot(sha) {
  const content = git('show', sha + ':' + path);
  const blob = git('rev-parse', sha + ':' + path).trim();
  const raw = Buffer.from(content);
  assert.equal(
    createHash('sha1')
      .update('blob ' + raw.length + '\0')
      .update(raw)
      .digest('hex'),
    blob
  );
  return { sha, blob, content };
}
const record = { repo, path, before: snapshot(beforeSha), after: snapshot(afterSha) };
const result = (name) => scan([{ path, content: record[name].content }]);
const before = result('before'),
  after = result('after');
assert.equal(before.findings[0]?.rule, 'CSP-01');
assert.deepEqual(compare(before, after), { fixed: 1, remaining: 0, introduced: 0, delta: 4 });
assert.ok(before.findings[0].patch);
const file = cwd + '/public/verified-case.json';
if (process.argv.includes('--write')) writeFileSync(file, JSON.stringify(record, null, 2) + '\n');
else assert.deepEqual(JSON.parse(readFileSync(file, 'utf8')), record);
console.log(
  'Verified both commit blobs, the fix, and the scored file: ' + before.score + ' -> ' + after.score + '.'
);
