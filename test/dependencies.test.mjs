import assert from 'node:assert/strict';
import test from 'node:test';
import { inventory, withAudit, maxPackages } from '../public/dependencies.mjs';
import { scan, compareEvidence } from '../public/scanner.mjs';
import { queryAdvisories } from '../lib/osv.mjs';

const fixture = {
  path: 'requirements.txt',
  content: 'demo_dist==1.0.0\nrange>=2\nconditional==1.1.0; python_version < "3.11"\n',
};
const npm = {
  path: 'package.json',
  content: JSON.stringify({ dependencies: { 'demo-js': '1.0.0', 'range-js': '^2.0.0' } }, null, 2),
};
test('only exact, simple pins reach advisory lookup', () => {
  const inv = inventory([fixture, npm]);
  assert.deepEqual(
    inv.pins.map((p) => [p.ecosystem, p.name, p.line]),
    [
      ['PyPI', 'demo-dist', 1],
      ['npm', 'demo-js', 3],
    ]
  );
  assert.equal(inv.unpinned, 3);
});
test('lockfile takes precedence and preserves nested versions', () => {
  const lock = {
    path: 'package-lock.json',
    content: JSON.stringify(
      {
        packages: {
          'node_modules/demo-js': { version: '1.0.1' },
          'node_modules/demo-js/node_modules/@scope/sub': { version: '2.0.0' },
        },
      },
      null,
      2
    ),
  };
  const result = inventory([npm, lock]);
  assert.deepEqual(
    result.pins.map((p) => [p.name, p.version, p.path]),
    [
      ['demo-js', '1.0.1', lock.path],
      ['@scope/sub', '2.0.0', lock.path],
    ]
  );
});
test('OSV results map to the exact file and expose a canonical evidence link', async () => {
  const files = [fixture];
  const inv = inventory(files);
  const calls = [];
  const fetcher = async (url, opts) => {
    calls.push([url, opts]);
    return Response.json(
      url.endsWith('querybatch')
        ? { results: [{ vulns: [{ id: 'GHSA-example' }] }] }
        : { database_specific: { severity: 'HIGH' } }
    );
  };
  const audit = await queryAdvisories(inv.pins, fetcher);
  assert.equal(calls.length, 2);
  const payload = JSON.parse(calls[0][1].body);
  assert.deepEqual(payload.queries, [
    { package: { ecosystem: 'PyPI', name: 'demo-dist' }, version: '1.0.0' },
  ]);
  const f = withAudit(scan(files), inv, audit).findings.find((f) => f.rule === 'OSV-01');
  assert.equal(f.line, 1);
  assert.equal(f.level, 'high');
  assert.equal(f.reference, 'https://osv.dev/vulnerability/GHSA-example');
});
test('outage cannot mark an advisory fixed on a rescan', async () => {
  const files = [fixture],
    inv = inventory(files);
  const after = await queryAdvisories(inv.pins, async () => Response.json({}, { status: 503 }));
  assert.equal(after.status, 'unavailable');
  const before = withAudit(scan(files), inv, {
    status: 'complete',
    checked: 1,
    results: [{ ...inv.pins[0], advisories: [{ id: 'TEST-1', level: 'high' }] }],
  });
  const comparison = compareEvidence(before, withAudit(scan(files), inv, after));
  assert.equal(comparison.fixed.length, 0);
  assert.equal(comparison.incomplete, true);
});
test('same advisory on two resolved versions counts once and stays open when one is upgraded', () => {
  const versions = ['1.0.0', '1.0.1'].map((version) => ({
    name: 'example',
    ecosystem: 'npm',
    version,
    path: 'package-lock.json',
    line: 4,
  }));
  const base = scan([{ path: 'package-lock.json', content: '{}' }]);
  const view = (pins) =>
    withAudit(
      base,
      { pins, manifests: 1, unpinned: 0, invalid: 0 },
      {
        status: 'complete',
        checked: pins.length,
        results: pins.map((p) => ({ ...p, advisories: [{ id: 'TEST-1', level: 'medium' }] })),
      }
    );
  assert.equal(view(versions).findings.length, 1);
  assert.equal(compareEvidence(view(versions), view(versions.slice(1))).remaining.length, 1);
});
test('unsupported manifests, limited inventory and pending OSV pages are visible', async () => {
  const malformed = inventory([{ path: 'package.json', content: '{' }]);
  assert.equal(withAudit(scan([]), malformed, { status: 'no-pins', checked: 0 }).audit.status, 'partial');
  const pins = Array.from({ length: maxPackages + 1 }, (_, i) => ({
    name: 'example-' + i,
    ecosystem: 'npm',
    version: '1.0.1',
  }));
  const audit = await queryAdvisories(pins, async () =>
    Response.json({ results: pins.slice(0, maxPackages).map(() => ({ next_page_token: 'test' })) })
  );
  assert.equal(audit.status, 'partial');
  assert.equal(audit.checked, maxPackages);
});
