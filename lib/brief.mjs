import { rules } from '../public/rules.mjs';

const gatewayModel = 'nvidia/nemotron-3.5-lightning-free';
const catalog = (id) => ({ impact: rules[id].impact, fix: rules[id].fix, verify: rules[id].verify });

export function parseBrief(content) {
  if (typeof content !== 'string') return null;
  try {
    const value = JSON.parse(content.trim().replace(/^\x60{3}(?:json)?\s*|\s*\x60{3}$/gi, ''));
    const fields = ['impact', 'fix', 'verify'];
    if (
      !value ||
      fields.some(
        (k) =>
          typeof value[k] !== 'string' ||
          value[k].trim().length < 12 ||
          value[k].length > 520 ||
          /https?:\/\/|[<>\x60]/.test(value[k])
      )
    )
      return null;
    return Object.fromEntries(fields.map((k) => [k, value[k].trim()]));
  } catch {
    return null;
  }
}

export async function explain(id, env = process.env, fetcher = fetch) {
  const providers = [];
  if (env.GROQ_API_KEY)
    providers.push({
      name: 'Groq',
      url: 'https://api.groq.com/openai/v1/chat/completions',
      token: env.GROQ_API_KEY,
      model: env.GROQ_MODEL || 'llama-3.3-70b-versatile',
    });
  const gatewayToken = env.VERCEL_OIDC_TOKEN || env.AI_GATEWAY_API_KEY;
  if (gatewayToken)
    providers.push({
      name: 'Vercel AI Gateway',
      url: 'https://ai-gateway.vercel.sh/v1/chat/completions',
      token: gatewayToken,
      model: gatewayModel,
    });
  let reason = 'no-provider';
  for (const provider of providers) {
    try {
      const response = await fetcher(provider.url, {
        method: 'POST',
        redirect: 'error',
        signal: AbortSignal.timeout(12500),
        headers: { Authorization: 'Bearer ' + provider.token, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: provider.model,
          temperature: 0.15,
          max_tokens: 1000,
          response_format: { type: 'json_object' },
          messages: [
            {
              role: 'system',
              content:
                'Write a defensive code-review note for a junior developer. Paraphrase only the supplied approved guidance. Reply as a JSON object with impact, fix and verify string fields, each one or two short sentences. Distinguish possible risk from observed facts. Do not give attacks, test payloads, commands, code, links or unsupported claims.',
            },
            {
              role: 'user',
              content: JSON.stringify({ rule: id, title: rules[id].title, guidance: catalog(id) }),
            },
          ],
        }),
      });
      if (!response.ok) {
        const result = await response.json().catch(() => ({}));
        const issue = result.error?.type || result.error?.code;
        reason =
          'provider-http-' +
          response.status +
          (typeof issue === 'string' && /^[a-z_]{1,60}$/i.test(issue) ? '/' + issue : '');
        continue;
      }
      const data = await response.json();
      const brief = parseBrief(data.choices?.[0]?.message?.content);
      if (brief) return { rule: id, mode: 'model', provider: provider.name, model: provider.model, brief };
      reason = 'output-format';
    } catch (err) {
      reason = err.name === 'TimeoutError' ? 'provider-timeout' : 'provider-unavailable';
    }
  }
  return {
    rule: id,
    mode: 'catalog',
    provider: 'Sentinel rule catalog',
    model: null,
    reason,
    brief: catalog(id),
  };
}
