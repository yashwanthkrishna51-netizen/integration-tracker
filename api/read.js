const crypto = require('crypto');
const { decryptString } = require('./_crypto');

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
  res.setHeader('Access-Control-Allow-Methods', 'GET');

  const { GITHUB_PAT, GITHUB_OWNER, GITHUB_REPO, INTEGTRACK_SECRET, INTEGTRACK_ENC_KEY } = process.env;

  const token = req.headers['x-session-token'];
  if (!isValidToken(token, INTEGTRACK_SECRET)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { path } = req.query;
  if (!path) return res.status(400).json({ error: 'path required' });

  if (!GITHUB_PAT || !GITHUB_OWNER || !GITHUB_REPO || !INTEGTRACK_ENC_KEY) {
    return res.status(500).json({ error: 'Server misconfigured: missing env vars' });
  }

  try {
    const url = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${path}`;
    const r = await fetch(url, {
      headers: {
        Authorization: `token ${GITHUB_PAT}`,
        Accept: 'application/vnd.github.v3+json',
        'User-Agent': 'IntegTrack-Kognoz',
      },
    });
    const data = await r.json();

    // Pass through GitHub errors (404, rate limit, etc.) unchanged
    if (!r.ok) return res.status(r.status).json(data);
    if (!data.content) return res.status(502).json({ error: 'Unexpected GitHub response' });

    // data.content is base64 of our encrypted blob (a base64 string stored as the file's text)
    const encryptedB64 = Buffer.from(data.content.replace(/\n/g, ''), 'base64').toString('utf8');

    let plaintext;
    try {
      plaintext = decryptString(encryptedB64, INTEGTRACK_ENC_KEY);
    } catch (e) {
      return res.status(500).json({ error: 'Decryption failed. Check INTEGTRACK_ENC_KEY matches the key used to encrypt this file.' });
    }

    // Re-package as base64(plaintext) so the frontend's existing JSON.parse(atob(...)) logic needs no changes
    return res.json({ content: Buffer.from(plaintext, 'utf8').toString('base64'), sha: data.sha });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};
