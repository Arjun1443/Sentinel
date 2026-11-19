import { readFileSync, writeFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { features } from '../public/assistant.mjs';

const corpus = JSON.parse(readFileSync(new URL('./intent-corpus.json', import.meta.url)));
const classes = Object.keys(corpus);
const totals = classes.map(() => 0),
  terms = Object.create(null);
classes.forEach((name, i) => {
  for (const phrase of corpus[name])
    for (const t of features(phrase)) {
      if (!terms[t]) terms[t] = classes.map(() => 0);
      terms[t][i]++;
      totals[i]++;
    }
});
const model = { algorithm: 'multinomial-naive-bayes', alpha: 0.4, classes, totals, terms };
const path = new URL('../public/intent-model.json', import.meta.url);
if (process.argv.includes('--write')) writeFileSync(path, JSON.stringify(model) + '\n');
else assert.deepEqual(JSON.parse(readFileSync(path)), JSON.parse(JSON.stringify(model)));
console.log(
  Object.values(corpus).flat().length + ' labeled training phrases, ' + classes.length + ' intents.'
);
