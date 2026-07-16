const crypto = require('crypto');

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

function welcomeEmailHtml({ name, username, password, appUrl }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Welcome to IntegTrack</title>
</head>
<body style="margin:0;padding:0;background:#f5f9fa;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f5f9fa;padding:40px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">

        <!-- Header -->
        <tr>
          <td style="background:#0d3d4f;padding:32px 40px;">
            <div style="font-size:28px;font-weight:800;color:#ffffff;letter-spacing:-0.5px;">kognoz</div>
            <div style="font-size:11px;font-weight:600;color:#67d9f0;letter-spacing:2px;margin-top:2px;">INTEGTRACK</div>
          </td>
        </tr>

        <!-- Body -->
        <tr>
          <td style="padding:40px;">
            <p style="margin:0 0 8px;font-size:22px;font-weight:700;color:#0d3d4f;">Welcome, ${name}!</p>
            <p style="margin:0 0 28px;font-size:15px;color:#64748b;line-height:1.6;">
              Your IntegTrack account has been created. Use the details below to log in and start tracking your projects.
            </p>

            <!-- Login Box -->
            <table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f7f9;border-radius:12px;margin-bottom:28px;">
              <tr>
                <td style="padding:24px;">
                  <p style="margin:0 0 16px;font-size:11px;font-weight:700;color:#0e7490;letter-spacing:1px;text-transform:uppercase;">Your Login Details</p>
                  <table cellpadding="0" cellspacing="0" width="100%">
                    <tr>
                      <td style="padding:6px 0;font-size:13px;color:#64748b;width:120px;">Application</td>
                      <td style="padding:6px 0;font-size:13px;"><a href="${appUrl}" style="color:#0e7490;font-weight:600;text-decoration:none;">${appUrl}</a></td>
                    </tr>
                    <tr>
                      <td style="padding:6px 0;font-size:13px;color:#64748b;">Username</td>
                      <td style="padding:6px 0;font-size:14px;font-weight:700;color:#0d3d4f;font-family:monospace;">${username}</td>
                    </tr>
                    <tr>
                      <td style="padding:6px 0;font-size:13px;color:#64748b;">Password</td>
                      <td style="padding:6px 0;font-size:14px;font-weight:700;color:#0d3d4f;font-family:monospace;">${password}</td>
                    </tr>
                  </table>
                  <div style="margin-top:20px;">
                    <a href="${appUrl}" style="display:inline-block;background:#0e7490;color:#ffffff;font-weight:600;font-size:14px;padding:12px 24px;border-radius:10px;text-decoration:none;">
                      Log in to IntegTrack →
                    </a>
                  </div>
                </td>
              </tr>
            </table>

            <!-- Instructions -->
            <p style="margin:0 0 12px;font-size:13px;font-weight:700;color:#0d3d4f;">Getting started</p>
            <table cellpadding="0" cellspacing="0" width="100%">
              ${[
                ['📊', 'Dashboard', 'See your portfolio health — overdue items, at-risk projects, and AMS alerts at a glance.'],
                ['⚡', 'Integrations', 'Track each client integration with status, assignee, due date, and a full update timeline.'],
                ['🏗️', 'Implementations', 'Monitor phase-by-phase progress across modules using the phase matrix.'],
                ['🎧', 'AMS & Support', 'Log support hours, track query status, and view billing summaries.'],
                ['⌘K', 'Quick Search', 'Press Cmd+K (or Ctrl+K) from anywhere to instantly jump to any client or record.'],
              ].map(([icon, title, desc]) => `
              <tr>
                <td style="padding:6px 0;vertical-align:top;width:28px;font-size:18px;">${icon}</td>
                <td style="padding:6px 0 6px 8px;vertical-align:top;">
                  <span style="font-weight:600;font-size:13px;color:#0d3d4f;">${title}</span>
                  <span style="font-size:13px;color:#64748b;"> — ${desc}</span>
                </td>
              </tr>`).join('')}
            </table>

            <!-- Password reminder -->
            <div style="margin-top:28px;padding:14px 16px;background:#fffbeb;border-radius:10px;border-left:4px solid #f59e0b;">
              <p style="margin:0;font-size:13px;color:#92400e;">
                <strong>Important:</strong> Please change your password after your first login.
                Click your name in the bottom-left corner of the app → <strong>My Profile</strong> → Change Password.
              </p>
            </div>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="padding:24px 40px;border-top:1px solid #e2e8f0;">
            <p style="margin:0;font-size:12px;color:#94a3b8;">
              This email was sent by your administrator at Kognoz. If you were not expecting this, please disregard it.
            </p>
            <p style="margin:8px 0 0;font-size:12px;color:#cbd5e1;">
              Kognoz Consulting Pvt. Ltd. · IntegTrack
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>`;
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-session-token');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const { RESEND_API_KEY, RESEND_FROM_EMAIL, INTEGTRACK_SECRET } = process.env;

  if (!RESEND_API_KEY) {
    return res.status(500).json({ error: 'RESEND_API_KEY not configured in environment variables.' });
  }

  const token = req.headers['x-session-token'];
  if (!isValidToken(token, INTEGTRACK_SECRET)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Decode token payload to check role
  const dot = token.lastIndexOf('.');
  const payload = JSON.parse(Buffer.from(token.slice(0, dot), 'base64url').toString());
  if (payload.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }

  const { to, name, username, password, appUrl } = req.body || {};
  if (!to || !name || !username || !password || !appUrl) {
    return res.status(400).json({ error: 'Missing required fields: to, name, username, password, appUrl' });
  }

  const fromEmail = RESEND_FROM_EMAIL || 'IntegTrack <noreply@kognoz.in>';

  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: fromEmail,
        to: [to],
        subject: `Welcome to IntegTrack, ${name}!`,
        html: welcomeEmailHtml({ name, username, password, appUrl }),
      }),
    });

    const data = await response.json();
    if (!response.ok) {
      return res.status(response.status).json({ error: data.message || 'Resend API error', detail: data });
    }
    return res.status(200).json({ id: data.id, success: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};
