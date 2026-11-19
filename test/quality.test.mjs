import assert from 'node:assert/strict';
import test from 'node:test';
import { scan, compareEvidence } from '../public/scanner.mjs';

const examples = [
  ['debug setting', 'settings.py', 'debug = True', 'CFG-01'],
  ['debug off', 'settings.py', 'debug = False', null],
  ['debug in documentation string', 'module.py', 'example = "debug = True"', null],
  ['debug in block comment', 'module.js', '/* doc\ndebug = true\n*/', null],
  [
    'debug in template string',
    'module.js',
    'const s = ' + String.fromCharCode(96) + 'debug = true' + String.fromCharCode(96),
    null,
  ],
  ['debug in Python docstring', 'module.py', '"""example\ndebug = True\n"""', null],
  ['debug in JSON', 'config.json', '  "debug": true,', 'CFG-01'],
  ['debug in YAML', 'config.yml', 'debug: true', 'CFG-01'],
  ['verify disabled', 'client.py', 'verify = False', 'TLS-01'],
  ['verify enabled', 'client.py', 'verify = True', null],
  ['verify in request', 'client.py', 'requests.get(url, verify=False)', 'TLS-01'],
  ['verify in inline comment', 'client.py', 'pass # verify = False', null],
  ['credential literal', 'settings.py', 'api_key = "demonstration-value"', 'SEC-01'],
  ['credential from environment', 'settings.py', 'api_key = os.getenv("KEY")', null],
  ['credential as test text', 'source.js', 'fixture = \'password = "placeholder-only"\' ', null],
  ['property text insertion', 'view.js', 'element.textContent = message', null],
  ['property HTML insertion', 'view.js', 'element.innerHTML = message', 'WEB-01'],
  ['HTML comment example', 'view.ts', '// element.innerHTML = name', null],
  ['pickle call', 'data.py', 'item = pickle.load(stream)', 'PY-01'],
  ['data-only call', 'data.py', 'item = json.load(stream)', null],
  ['database bound parameter', 'data.py', 'db.execute(statement, arguments)', null],
  ['dependency range', 'requirements.txt', 'demo-package>=1.1', 'DEP-01'],
  ['dependency pin', 'requirements.txt', 'demo-package==1.1.0', null],
  ['unsupported document', 'notes.md', 'debug = True', null],
];
for (const [label, path, content, expected] of examples) {
  test('scan fixture · ' + label, () => {
    assert.deepEqual(
      scan([{ path, content }]).findings.map((f) => f.rule),
      expected ? [expected] : []
    );
  });
}
test('a file omitted on the second scan is marked as a coverage difference', () => {
  const left = scan([{ path: 'settings.py', content: 'debug = True' }]);
  const right = scan([{ path: 'other.py', content: 'pass' }]);
  const c = compareEvidence(left, right);
  assert.equal(c.fixed.length, 0);
  assert.equal(c.changedCoverage, true);
});
