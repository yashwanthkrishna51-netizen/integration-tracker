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

  const { path, content, message } = req.body || {};
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
    const ghHeaders = {
      Authorization: `token ${GITHUB_PAT}`,
      Accept: 'application/vnd.github.v3+json',
      'Content-Type': 'application/json',
      'User-Agent': 'IntegTrack-Kognoz',
    };

    // Always fetch the current SHA from GitHub right before writing.
    // This eliminates the "SHA does not match" 422 error that occurs when
    // multiple users have the app open simultaneously: each user's in-memory
    // SHA becomes stale as soon as any other user saves, but by fetching here
    // we always use the true current SHA regardless of what the client sent.
    let currentSha = null;
    const getRes = await fetch(url, { headers: ghHeaders });
    if (getRes.ok) {
      const getData = await getRes.json();
      currentSha = getData.sha;
    } else if (getRes.status !== 404) {
      // 404 means file doesn't exist yet (first-time create) — no SHA needed.
      // Any other status is a genuine GitHub error.
      const errData = await getRes.json();
      return res.status(getRes.status).json({ error: errData.message || 'Failed to fetch current file SHA from GitHub' });
    }

    const body = {
      message: message || `Update ${path}`,
      content: Buffer.from(encryptedB64).toString('base64'),
    };
    if (currentSha) body.sha = currentSha;

    const putRes = await fetch(url, {
      method: 'PUT',
      headers: ghHeaders,
      body: JSON.stringify(body),
    });

    const putData = await putRes.json();
    if (!putRes.ok) return res.status(putRes.status).json({ error: putData.message || 'GitHub error', detail: putData });
    return res.status(200).json({ sha: putData.content.sha });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};
