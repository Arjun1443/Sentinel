import { scan } from '../public/scanner.mjs';

const supported = /\.(py|[cm]?js|tsx?|json|env|ya?ml|txt|toml|ini|cfg)$/i;
const excluded = /(?:^|\/)(?:node_modules|vendor|dist|package-lock\.json|pnpm-lock\.yaml)(?:\/|$)/;
const maxFiles = 24;

function repository(value) {
  const match = /^https:\/\/github\.com\/([a-z\d][a-z\d-]{0,38})\/([a-z\d_.-]{1,100})\/?$/i.exec(value);
  if (!match) return null;
  const name = match[2].replace(/\.git$/i, '');
  if (!name || name === '.' || name === '..') return null;
  return match[1] + '/' + name;
}

export default async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).json({error:'Use GET.'});
  const name = typeof req.query.url === 'string' && repository(req.query.url);
  if (!name) return res.status(400).json({error:'Enter a public GitHub repository URL.'});
  const signal = AbortSignal.timeout(9000);
  const root = 'https://api.github.com/repos/' + name;
  const get = async path => {
    const response = await fetch(root + path, {
      signal, redirect:'error',
      headers:{Accept:'application/vnd.github+json','User-Agent':'Sentinel-Review'},
    });
    if (response.status === 403 || response.status === 429) throw Error('GitHub rate limit reached. Try again later or select local files.');
    if (response.status === 404 || response.status === 409) throw Error('Repository is unavailable, private, or empty.');
    if (!response.ok) throw Error('GitHub could not load repository data.');
    return response.json();
  };
  try {
    const meta = await get('');
    if (meta.private) return res.status(404).json({error:'Select a public GitHub repository.'});
    const commit = await get('/commits/' + encodeURIComponent(meta.default_branch));
    const sha = commit.sha;
    if (!/^[a-f0-9]{40}$/.test(sha)) throw Error('GitHub returned an invalid commit.');
    const snapshot = await get('/git/trees/' + sha + '?recursive=1');
    const blobs = snapshot.tree.filter(entry => entry.type === 'blob');
    const selected = blobs.filter(entry => entry.mode !== '120000' && entry.size <= 80000 && supported.test(entry.path) && !excluded.test(entry.path) && /^[a-f0-9]{40}$/.test(entry.sha))
      .sort((a,b) => a.path.localeCompare(b.path)).slice(0,maxFiles);
    const files = [];
    for (let i = 0; i < selected.length; i += 6) {
      files.push(...await Promise.all(selected.slice(i,i+6).map(async entry => {
        const blob = await get('/git/blobs/' + entry.sha);
        if (blob.encoding !== 'base64') throw Error('GitHub returned an unsupported file encoding.');
        return {path:entry.path, content:Buffer.from(blob.content,'base64').toString('utf8')};
      })));
    }
    if (!files.length) return res.status(422).json({error:'No supported source files were found in the repository sample.'});
    return res.status(200).json({
      name, branch:meta.default_branch, language:meta.language || 'Language unspecified',
      count:files.length, total:blobs.length, truncated:snapshot.truncated,
      link:'https://github.com/' + name + '/blob/' + sha, output:scan(files),
    });
  } catch (error) {
    const message = error.name === 'TimeoutError' ? 'GitHub request timed out. Try again or select local files.' : error.message;
    return res.status(502).json({error:message});
  }
}
