import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';

test('the production form policy permits same-origin submissions only', () => {
  const config = JSON.parse(readFileSync(new URL('../vercel.json', import.meta.url), 'utf8'));
  const allRoutes = config.headers.find(route => route.source === '/(.*)');
  const policy = allRoutes.headers.find(header => header.key.toLowerCase() === 'content-security-policy');
  const directives = policy.value.split(';').map(value => value.trim().split(/\s+/));
  assert.deepEqual(directives.find(([name]) => name === 'form-action'), ['form-action', "'self'"]);
});
