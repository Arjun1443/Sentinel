import test from 'node:test';
import assert from 'node:assert/strict';
import {scan, compare} from '../public/scanner.mjs';

test('demo comparison verifies two configuration changes', () => {
  const requirements = {path:'requirements.txt', content:'example-package>=1\n'};
  const before = scan([{path:'settings.py', content:'debug = True'}, {path:'client.py', content:'verify = False'}, requirements]);
  const after = scan([{path:'settings.py', content:'debug = False'}, {path:'client.py', content:'verify = True'}, requirements]);
  assert.equal(before.score, 79);
  assert.equal(after.score, 99);
  assert.deepEqual(compare(before,after), {fixed:2,remaining:1,introduced:0,delta:20});
  assert.match(before.findings[0].patch, /\+debug = False/);
});

test('possible credentials are redacted and receive the additional deduction', () => {
  const output = scan([{path:'settings.py',content:'password = "fixture-placeholder"'}]);
  assert.equal(output.score, 67);
  assert.match(output.findings[0].evidence, /redacted/);
  assert.equal(output.findings[0].patch, '');
});

test('unsupported files and commented settings are ignored', () => {
  assert.equal(scan([{path:'example.md',content:'debug = True'}, {path:'settings.py', content:'# debug = True'}]).score,100);
});
