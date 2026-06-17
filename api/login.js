const crypto = require('crypto');
const { decryptString } = require('./_crypto');

function sign(secret, payload) {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const { username, passwordHash } = req.body || {};
  if (!username || !passwordHash) return res.status(400).json({ error: 'Missing fields' });

  const { GITHUB_PAT, GITHUB_OWNER, GITHUB_REPO, INTEGTRACK_SECRET, INTEGTRACK_ENC_KEY } = process.env;
  if (!GITHUB_PAT || !GITHUB_OWNER || !GITHUB_REPO || !INTEGTRACK_SECRET || !INTEGTRACK_ENC_KEY) {
    return res.status(500).json({ error: 'Server misconfigured: missing env vars' });
  }

  try {
    const url = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/data/users.json`;
    const r = await fetch(url, {
      headers: {
        Authorization: `token ${GITHUB_PAT}`,
        Accept: 'application/vnd.github.v3+json',
        'User-Agent': 'IntegTrack-Kognoz',
      },
    });
    if (!r.ok) return res.status(502).json({ error: 'Could not reach GitHub' });

    const data = await r.json();
    if (!data.content) return res.status(502).json({ error: 'Unexpected GitHub response' });

    const encryptedB64 = Buffer.from(data.content.replace(/\n/g, ''), 'base64').toString('utf8');

    let plaintext;
    try {
      plaintext = decryptString(encryptedB64, INTEGTRACK_ENC_KEY);
    } catch (e) {
      return res.status(500).json({ error: 'Decryption failed. Check INTEGTRACK_ENC_KEY.' });
    }

    const users = JSON.parse(plaintext);

    const user = users.find(u => u.username === username && u.passwordHash === passwordHash);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const payload = Buffer.from(`${username}:${passwordHash}`).toString('base64url');
    const token = `${payload}.${sign(INTEGTRACK_SECRET, payload)}`;

    return res.json({
      token,
      user: { id: user.id, name: user.name, role: user.role, username: user.username },
      usersSha: data.sha,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};
