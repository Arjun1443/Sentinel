import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { classify, answerQuestion } from '../public/assistant.mjs';
import { scan, compareEvidence } from '../public/scanner.mjs';
const model = JSON.parse(readFileSync(new URL('../public/intent-model.json', import.meta.url)));
const examples = [
  ['priority', 'Which alert should receive attention first?'],
  ['priority', 'What is our top issue before shipping?'],
  ['priority', 'Rank my open findings by urgency'],
  ['impact', 'Why is the browser policy important?'],
  ['impact', 'Explain the consequence for a user'],
  ['impact', 'What impact could the warning have?'],
  ['fix', 'Which edit resolves this configuration problem?'],
  ['fix', 'How should I patch the certificate setting?'],
  ['fix', 'Tell me the remediation for this warning'],
  ['verify', 'How can a regression test verify the header?'],
  ['verify', 'How do we confirm the repair worked?'],
  ['verify', 'Give me a validation check for TLS'],
  ['change', 'What did the second commit resolve compared with the baseline?'],
  ['change', 'Did any new warnings appear after rescanning?'],
  ['change', 'What is different between revisions?'],
  ['scope', 'How many source files did the scanner inspect?'],
  ['scope', 'Did OSV check the package versions?'],
  ['scope', 'Are there any limits to coverage?'],
];
test('classifies at least 15 of 18 held-out phrasing examples', (t) => {
  const correct = examples.filter(([want, q]) => classify(q, model) === want).length;
  t.diagnostic(correct + '/' + examples.length + ' held-out questions matched the intended category.');
  assert.ok(correct >= 15);
});
test('unrecognized questions abstain', () =>
  assert.equal(classify('Orbiting purple satellites', model), null));
test('assistant cites the actual file and revision when answering a comparison', () => {
  const record = JSON.parse(readFileSync(new URL('../public/verified-case.json', import.meta.url)));
  const run = (rev) => scan([{ path: record.path, content: record[rev].content }]);
  const before = run('before'),
    after = run('after');
  const answer = answerQuestion('Compare before and after', model, {
    output: after,
    change: compareEvidence(before, after),
  });
  assert.match(answer.text, /96 to 100/);
  assert.equal(answer.citations[0].f.line, 8);
  assert.equal(answer.citations[0].side, 'fixed');
});
test('finding retrieval selects a named setting even when it is second in the list', () => {
  const output = scan([
    { path: 'settings.py', content: 'debug = True' },
    { path: 'client.py', content: 'verify = False' },
  ]);
  const answer = answerQuestion('How do I validate the certificate change?', model, {
    output,
    change: null,
  });
  assert.equal(answer.citations[0].f.rule, 'TLS-01');
});
