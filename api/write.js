const crypto = require('crypto');
const { encryptString } = require('./_crypto');

function isValidToken(token, secret) {
  if (!token || !secret) return false;
  const dot = token.lastIndexOf('.');
  if (dot === -1) return false;
  const payload = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  const a = Buffer.from(expected, 'hex');
  const b = Buffer.from(sig.length === expected.length ? sig : expected, 'hex');
  return crypto.timingSafeEqual(a, b) && sig.length === expected.length;
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-session-token');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const { GITHUB_PAT, GITHUB_OWNER, GITHUB_REPO, INTEGTRACK_SECRET, INTEGTRACK_ENC_KEY } = process.env;

  const token = req.headers['x-session-token'];
  if (!isValidToken(token, INTEGTRACK_SECRET)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { path, content, sha, message } = req.body || {};
  if (!path || content === undefined) {
    return res.status(400).json({ error: 'path and content required' });
  }

  if (!GITHUB_PAT || !GITHUB_OWNER || !GITHUB_REPO || !INTEGTRACK_ENC_KEY) {
    return res.status(500).json({ error: 'Server misconfigured: missing env vars' });
  }

  try {
    const plaintext = typeof content === 'string' ? content : JSON.stringify(content, null, 2);
    const encryptedB64 = encryptString(plaintext, INTEGTRACK_ENC_KEY);

    const url = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${path}`;
    const body = {
      message: message || `Update ${path}`,
      content: Buffer.from(encryptedB64).toString('base64'),
    };
    if (sha) body.sha = sha;

    const r = await fetch(url, {
      method: 'PUT',
      headers: {
        Authorization: `token ${GITHUB_PAT}`,
        Accept: 'application/vnd.github.v3+json',
        'Content-Type': 'application/json',
        'User-Agent': 'IntegTrack-Kognoz',
      },
      body: JSON.stringify(body),
    });

    const data = await r.json();
    if (!r.ok) return res.status(r.status).json({ error: data.message || 'GitHub error', detail: data });
    return res.status(200).json({ sha: data.content.sha });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};
