module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const { path, content, sha, message } = req.body || {};
  if (!path || content === undefined) {
    return res.status(400).json({ error: 'path and content required' });
  }

  const { GITHUB_PAT, GITHUB_OWNER, GITHUB_REPO } = process.env;
  if (!GITHUB_PAT || !GITHUB_OWNER || !GITHUB_REPO) {
    return res.status(500).json({ error: 'Server misconfigured: missing env vars' });
  }

  try {
    const url = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${path}`;
    const body = {
      message: message || `Update ${path}`,
      content: Buffer.from(typeof content === 'string' ? content : JSON.stringify(content, null, 2)).toString('base64'),
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
    return res.status(200).json({ content: { sha: data.content.sha }, sha: data.content.sha });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};
