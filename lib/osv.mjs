import { maxPackages, packageKey, validPin } from '../public/dependencies.mjs';

export async function queryAdvisories(input, fetcher = fetch) {
  const pins = [...new Map(input.filter(validPin).map((p) => [packageKey(p), p])).values()];
  const selected = pins.slice(0, maxPackages);
  if (!selected.length) return { status: 'no-pins', checked: 0, results: [] };
  const api = 'https://api.osv.dev/v1';
  const signal = AbortSignal.timeout(8000);
  const request = async (url, init = {}) => {
    const response = await fetcher(url, { ...init, signal, redirect: 'error' });
    if (!response.ok) throw Error('OSV request failed');
    return response.json();
  };
  try {
    const batch = await request(api + '/querybatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        queries: selected.map(({ ecosystem, name, version }) => ({
          package: { ecosystem, name },
          version,
        })),
      }),
    });
    if (
      !Array.isArray(batch.results) ||
      batch.results.length !== selected.length ||
      batch.results.some((row) => !row || (row.vulns !== undefined && !Array.isArray(row.vulns)))
    )
      throw Error('Incomplete OSV response');
    let partial = pins.length > selected.length;
    const groups = batch.results.map((row) => {
      if (row.next_page_token || row.vulns?.length > 16) partial = true;
      return (row.vulns || [])
        .slice(0, 16)
        .map((v) => v.id)
        .filter((id) => typeof id === 'string' && /^[A-Za-z0-9_.-]{1,100}$/.test(id));
    });
    const ids = [...new Set(groups.flat())];
    const levels = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' };
    const details = new Map(
      await Promise.all(
        ids.slice(0, 10).map(async (id) => {
          try {
            const record = await request(api + '/vulns/' + encodeURIComponent(id));
            if (record.withdrawn) return [id, 'withdrawn'];
            return [id, levels[String(record.database_specific?.severity).toUpperCase()] || 'review'];
          } catch {
            return [id, 'review'];
          }
        })
      )
    );
    return {
      status: partial ? 'partial' : 'complete',
      checked: selected.length,
      results: selected.map(({ ecosystem, name, version }, i) => ({
        ecosystem,
        name,
        version,
        advisories: groups[i]
          .filter((id) => details.get(id) !== 'withdrawn')
          .map((id) => ({ id, level: details.get(id) || 'review' })),
      })),
    };
  } catch {
    return { status: 'unavailable', checked: 0, results: [] };
  }
}
