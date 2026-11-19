import { scan, supported } from '../public/scanner.mjs';
import { inventory, withAudit } from '../public/dependencies.mjs';
import { queryAdvisories } from '../lib/osv.mjs';

const skip = /(?:^|\/)(?:\.git|node_modules|vendor|dist|build|coverage|\.venv|__pycache__)(?:\/|$)/;
const fullSha = /^[a-f0-9]{40}$/i;
function priority(path) {
  if (/(?:^|\/)(?:package(?:-lock)?\.json|requirements(?:[-.][\w-]+)?\.txt|vercel\.json)$/.test(path))
    return 0;
  if (/(?:^|\/)(?:settings|config|app|server|main)\./i.test(path)) return 1;
  if (/(?:^|\/)(?:test|tests|examples|fixtures)(?:\/|$)/i.test(path)) return 3;
  return 2;
}
export function selectFiles(blobs) {
  const eligible = blobs
    .filter(
      (e) =>
        e.mode !== '120000' &&
        supported(e.path) &&
        !skip.test(e.path) &&
        e.size <= (e.path.endsWith('package-lock.json') ? 524288 : 160000)
    )
    .sort((a, b) => priority(a.path) - priority(b.path) || a.path.localeCompare(b.path));
  const selected = [];
  let bytes = 0;
  for (const e of eligible) {
    if (selected.length === 40) break;
    if (bytes + e.size <= 2000000) {
      bytes += e.size;
      selected.push(e);
    }
  }
  return { selected, eligible: eligible.length };
}
export default async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).json({ error: 'Use GET.' });
  const match =
    typeof req.query.url === 'string' &&
    /^https:\/\/github\.com\/([a-z\d][a-z\d-]{0,38})\/([\w.-]{1,100})\/?$/i.exec(req.query.url);
  const name = match && match[2].replace(/\.git$/i, '');
  if (!name || name === '.' || name === '..')
    return res.status(400).json({ error: 'Enter a public GitHub repository URL.' });
  const ref = req.query.ref;
  if (ref !== undefined && (typeof ref !== 'string' || !fullSha.test(ref)))
    return res.status(400).json({ error: 'A revision must be a full 40-character commit SHA.' });
  const repo = match[1] + '/' + name;
  const signal = AbortSignal.timeout(16000);
  const get = async (path) => {
    const response = await fetch('https://api.github.com/repos/' + repo + path, {
      signal,
      redirect: 'error',
      headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'Sentinel-Review' },
    });
    if (response.status === 403 || response.status === 429)
      throw Error('GitHub rate limit reached. Try the verified case or local files.');
    if (response.status === 404 || response.status === 409)
      throw Error('Repository or revision unavailable. Use a public repository with commits.');
    if (!response.ok) throw Error('GitHub could not load the repository.');
    return response.json();
  };
  try {
    const meta = await get('');
    if (meta.private) return res.status(404).json({ error: 'Use a public repository.' });
    const commit = await get('/commits/' + encodeURIComponent(ref || meta.default_branch));
    if (!fullSha.test(commit.sha) || !fullSha.test(commit.commit?.tree?.sha))
      throw Error('Invalid GitHub commit metadata.');
    const tree = await get('/git/trees/' + commit.commit.tree.sha + '?recursive=1');
    const blobs = tree.tree.filter((e) => e.type === 'blob');
    const { selected, eligible } = selectFiles(blobs);
    const files = [];
    for (let i = 0; i < selected.length; i += 8) {
      const chunk = await Promise.all(
        selected.slice(i, i + 8).map(async (entry) => {
          try {
            const path = entry.path.split('/').map(encodeURIComponent).join('/');
            const response = await fetch(
              'https://raw.githubusercontent.com/' + repo + '/' + commit.sha + '/' + path,
              { signal, redirect: 'error' }
            );
            if (!response.ok) return null;
            const bytes = Buffer.from(await response.arrayBuffer());
            if (bytes.length !== entry.size || bytes.includes(0)) return null;
            return { path: entry.path, content: new TextDecoder('utf-8', { fatal: true }).decode(bytes) };
          } catch {
            return null;
          }
        })
      );
      files.push(...chunk.filter(Boolean));
    }
    if (!files.length)
      return res
        .status(422)
        .json({
          error: selected.length
            ? 'GitHub source could not be read. Retry or select local files.'
            : 'No supported text files in this revision.',
        });
    const packages = inventory(files);
    const output = withAudit(scan(files), packages, await queryAdvisories(packages.pins));
    const unavailable = selected.length - files.length;
    if (!unavailable && output.audit.status !== 'unavailable')
      res.setHeader('Cache-Control', 'public, s-maxage=45');
    return res
      .status(200)
      .json({
        name: meta.full_name,
        branch: meta.default_branch,
        sha: commit.sha,
        language: meta.language || 'Unspecified',
        count: files.length,
        total: blobs.length,
        eligible,
        unavailable,
        truncated: Boolean(tree.truncated),
        link: 'https://github.com/' + repo + '/blob/' + commit.sha,
        output,
      });
  } catch (error) {
    const detail = /^(?:GitHub |Repository or |Invalid GitHub)/.test(error.message)
      ? error.message
      : 'GitHub request timed out or was unavailable. Try the verified case or local files.';
    return res.status(502).json({ error: detail });
  }
}
