const crypto = require('crypto');

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

  const { GITHUB_PAT, GITHUB_OWNER, GITHUB_REPO, INTEGTRACK_SECRET } = process.env;
  if (!GITHUB_PAT || !GITHUB_OWNER || !GITHUB_REPO || !INTEGTRACK_SECRET) {
    return res.status(500).json({ error: 'Server misconfigured: missing env vars (INTEGTRACK_SECRET required)' });
  }

  try {
    // Fetch users from GitHub (only the server can do this — PAT never leaves server)
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

    const users = JSON.parse(
      Buffer.from(data.content.replace(/\n/g, ''), 'base64').toString('utf8')
    );

    // Validate credentials
    const user = users.find(u => u.username === username && u.passwordHash === passwordHash);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    // Issue signed session token: base64url(username:passwordHash).hmac
    // Server can revalidate this without storing state — just re-sign and compare
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
