import { queryAdvisories } from '../lib/osv.mjs';
import { maxPackages, validPin } from '../public/dependencies.mjs';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Use POST.' });
  const pins = req.body?.packages;
  if (!Array.isArray(pins) || pins.length > maxPackages || !pins.every(validPin))
    return res
      .status(400)
      .json({ error: 'Provide up to ' + maxPackages + ' exact npm or PyPI package versions.' });
  res.setHeader('Cache-Control', 'no-store');
  return res.status(200).json(await queryAdvisories(pins));
}
