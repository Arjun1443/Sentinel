const stop = new Set(
  'a an and are as at be by can could do does for from give how i in is it me my of on our please should show tell the their these this to we what which will with would you your'.split(
    ' '
  )
);
function words(text) {
  return (
    String(text)
      .toLowerCase()
      .match(/[a-z0-9]+/g)
      ?.filter((w) => !stop.has(w))
      .map((w) => (w.length > 4 ? w.replace(/(?:ies|s)$/g, (end) => (end === 'ies' ? 'y' : '')) : w)) || []
  );
}
export function features(text) {
  const tokens = words(text);
  return [...tokens, ...tokens.slice(1).map((w, i) => tokens[i] + ' ' + w)];
}
export function classify(question, model) {
  const known = features(question).filter((t) => Object.hasOwn(model.terms, t));
  if (!known.length) return null;
  const scores = model.classes
    .map((name, i) => {
      const norm = model.totals[i] + model.alpha * Object.keys(model.terms).length;
      return {
        name,
        score: known.reduce((s, t) => s + Math.log((model.terms[t][i] + model.alpha) / norm), 0),
      };
    })
    .sort((a, b) => b.score - a.score);
  return scores[0].score - scores[1].score >= 0.65 ? scores[0].name : null;
}

function closest(question, rows) {
  const tokens = new Set(words(question));
  if (!rows.length) return null;
  const docs = rows.map((f) => new Set(words([f.rule, f.group, f.title, f.path, f.evidence].join(' '))));
  const df = new Map();
  for (const doc of docs) for (const w of doc) df.set(w, (df.get(w) || 0) + 1);
  let best = 0,
    bestScore = 0;
  docs.forEach((doc, i) => {
    const score = [...tokens].reduce(
      (n, t) => n + (doc.has(t) ? 1 + Math.log((docs.length + 1) / ((df.get(t) || 0) + 1)) : 0),
      0
    );
    if (score > bestScore) {
      best = i;
      bestScore = score;
    }
  });
  return rows[best];
}
export function answerQuestion(question, model, view) {
  const intent = classify(question, model);
  const response = (text, citations = []) => ({ intent, text, citations });
  if (!intent)
    return response(
      'I can answer questions about priority, impact, fixes, validation, scan coverage or changes between revisions. Try “What should I fix first?”'
    );
  const c = view.change,
    o = view.output;
  if (intent === 'scope') {
    const a = o.audit;
    return response(
      view.coverage +
        '. ' +
        (a
          ? 'Dependency lookup: ' +
            a.status +
            '; ' +
            a.checked +
            ' of ' +
            a.total +
            ' exact versions checked.'
          : 'This review covers the source and rules shown above.')
    );
  }
  if (intent === 'change') {
    if (!c)
      return response(
        'This scan has no baseline yet. Enter a baseline commit or select an earlier public scan from History.'
      );
    const refs = [
      ...c.fixed.slice(0, 2).map((f) => ({ f, side: 'fixed' })),
      ...c.introduced.slice(0, 2).map((f) => ({ f, side: 'current' })),
    ];
    return response(
      'The score moved from ' +
        (o.score - c.delta) +
        ' to ' +
        o.score +
        '. In shared files, ' +
        c.fixed.length +
        ' match(es) disappeared, ' +
        c.remaining.length +
        ' remain, and ' +
        c.introduced.length +
        ' are new.' +
        (view.partial || view.priorPartial || c.incomplete || c.changedCoverage
          ? ' Coverage is partial, so interpret the difference within the observed scope.'
          : ''),
      refs
    );
  }
  const baselineOnly = !o.findings.length && c?.fixed?.length && intent !== 'priority';
  const rows = baselineOnly ? c.fixed : o.findings;
  const selected = intent === 'priority' ? rows[0] : closest(question, rows);
  if (!selected)
    return response(
      'The selected rules found no current matches in this scope. Check the file and advisory coverage before deciding whether the review is complete.'
    );
  const prefix = baselineOnly
    ? 'In the baseline, ' + selected.rule + ' flagged ' + selected.path + '. '
    : '';
  const body =
    intent === 'priority'
      ? selected.title + ' is the highest-ranked current finding (' + selected.level + '). ' + selected.fix
      : { impact: selected.impact, fix: selected.fix, verify: selected.verify }[intent];
  return response(prefix + body, [{ f: selected, side: baselineOnly ? 'fixed' : 'current' }]);
}
