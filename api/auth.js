// api/auth.js
// Server-side auth proxy using Supabase Admin API.
// This bypasses the "email signups disabled" restriction in Supabase's Auth settings
// because the Admin API (service_role key) can create/manage users regardless.
//
// Required env vars (set in Vercel dashboard):
//   SUPABASE_URL          — e.g. https://xxxx.supabase.co
//   SUPABASE_SERVICE_KEY  — service_role key (secret, never sent to browser)

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SERVICE_KEY  = process.env.SUPABASE_SERVICE_KEY;

  if (!SUPABASE_URL || !SERVICE_KEY) {
    return res.status(503).json({
      error: 'Server not configured. Set SUPABASE_URL and SUPABASE_SERVICE_KEY in Vercel environment variables.'
    });
  }

  const adminHeaders = {
    'apikey':        SERVICE_KEY,
    'Authorization': `Bearer ${SERVICE_KEY}`,
    'Content-Type':  'application/json',
  };

  let body;
  try { body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body; }
  catch { return res.status(400).json({ error: 'Invalid JSON body' }); }

  const { action, username, password } = body || {};

  if (!action || !username || !password) {
    return res.status(400).json({ error: 'Missing required fields: action, username, password' });
  }

  // Validate username
  if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) {
    return res.status(400).json({ error: 'Invalid username. Use 3-30 letters, numbers, or underscores.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }

  // Internal email — never actually sent anywhere
  const email = `${username.toLowerCase()}@pokevault.app`;

  // ── SIGN UP ──────────────────────────────────────────────────────────────
  if (action === 'signup') {
    // Use Admin API to create user — bypasses email auth settings entirely
    const createRes = await fetch(`${SUPABASE_URL}/auth/v1/admin/users`, {
      method:  'POST',
      headers: adminHeaders,
      body: JSON.stringify({
        email,
        password,
        email_confirm: true,          // mark as already confirmed — no email sent
        user_metadata: { username },
      }),
    });

    const createData = await createRes.json();

    if (!createRes.ok) {
      // Map Supabase errors to friendly messages
      const detail = createData?.message || createData?.msg || JSON.stringify(createData);
      if (detail.toLowerCase().includes('already registered') || detail.toLowerCase().includes('already exists')) {
        return res.status(409).json({ error: 'That username is already taken. Try another.' });
      }
      return res.status(createRes.status).json({ error: detail });
    }

    // Auto sign-in immediately after creating the account
    const signInRes = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
      method:  'POST',
      headers: {
        'apikey':       SERVICE_KEY,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password }),
    });

    const signInData = await signInRes.json();
    if (!signInRes.ok) {
      // Account created but sign-in failed — tell client to sign in manually
      return res.status(200).json({ created: true, autoSignIn: false });
    }

    return res.status(200).json({
      created:      true,
      autoSignIn:   true,
      access_token:  signInData.access_token,
      refresh_token: signInData.refresh_token,
      expires_in:    signInData.expires_in,
      user:          signInData.user,
    });
  }

  return res.status(400).json({ error: 'Invalid action. Use: signup' });
}
