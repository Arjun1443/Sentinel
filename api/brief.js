import { getVercelOidcTokenSync } from '@vercel/oidc';
import { explain } from '../lib/brief.mjs';
import { rules } from '../public/rules.mjs';

export default async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).json({ error: 'Use GET.' });
  const id = req.query.rule;
  if (typeof id !== 'string' || !Object.hasOwn(rules, id))
    return res.status(400).json({ error: 'Choose a supported rule.' });
  let token;
  if (process.env.VERCEL) {
    try {
      token = getVercelOidcTokenSync();
    } catch {
      /* No request identity on this deployment. */
    }
  }
  const answer = await explain(id, {
    GROQ_API_KEY: process.env.GROQ_API_KEY,
    GROQ_MODEL: process.env.GROQ_MODEL,
    VERCEL_OIDC_TOKEN: token || process.env.VERCEL_OIDC_TOKEN,
    AI_GATEWAY_API_KEY: process.env.AI_GATEWAY_API_KEY,
  });
  res.setHeader(
    'Cache-Control',
    answer.mode === 'model' ? 'public, s-maxage=86400, stale-while-revalidate=3600' : 'public, s-maxage=30'
  );
  return res.status(200).json(answer);
}
