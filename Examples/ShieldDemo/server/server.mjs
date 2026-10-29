// The demo app's backend: one fake login route that verifies the Shield
// session before it lets the user in. Node 18 or later, no dependencies.
//
//   SHIELD_SECRET_KEY=sec_xxx node server.mjs
//
// The secret key belongs on a server like this one, never in the app.
// Shield's answer here is the decision; the verdict the app received is advice.

import { createServer } from 'node:http';

const PORT = Number(process.env.PORT ?? 8787);
const SECRET_KEY = process.env.SHIELD_SECRET_KEY ?? '';
const VERIFY_URL = process.env.SHIELD_VERIFY_URL ?? 'https://shield.findip.net/v1/shield/sessions/verify';

if (!SECRET_KEY.startsWith('sec_')) {
  console.error('Set SHIELD_SECRET_KEY to the site\'s secret key (sec_...) from the Shield dashboard.');
  process.exit(1);
}

/** Shield's picture of the session, or null when Shield could not answer. */
async function verify(sessionId) {
  try {
    const res = await fetch(VERIFY_URL, {
      method: 'POST',
      headers: { Authorization: `Bearer ${SECRET_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: sessionId, event: 'login_attempt' }),
      signal: AbortSignal.timeout(3000),
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

/**
 * The decision for a login. A login can usually continue when Shield has no
 * answer, but it is logged: unknown is never the same as safe.
 */
function decide(result) {
  if (!result || !result.verified || result.risk_status !== 'available') {
    return { status: 200, decision: 'allow', note: 'Shield had no verdict for this session; allowed and logged for review.' };
  }
  switch (result.recommendation) {
    case 'block':
      // Neutral on purpose: never tell the client why.
      return { status: 403, decision: 'refuse', message: 'Could not complete the login. Try again later.' };
    case 'challenge':
      return result.challenge_passed
        ? { status: 200, decision: 'allow' }
        : { status: 200, decision: 'step_up', message: 'We sent you a code to confirm it is you.' };
    case 'monitor':
      return { status: 200, decision: 'allow', note: 'Allowed and logged for review.' };
    default:
      return { status: 200, decision: 'allow' };
  }
}

function send(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

const server = createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') return send(res, 200, { ok: true });
  if (req.method !== 'POST' || req.url !== '/login') return send(res, 404, { error: 'not_found' });

  const sessionId = String(req.headers['x-shield-session'] ?? '').slice(0, 128);
  if (!sessionId) return send(res, 400, { error: 'missing X-Shield-Session' });

  // A real backend checks the password here; the demo accepts any.
  const result = await verify(sessionId);
  const { status, ...answer } = decide(result);
  console.log(new Date().toISOString(), sessionId, result?.recommendation ?? 'no verdict', '->', answer.decision);
  // The Shield fields are returned only so the demo can show them. A real
  // backend keeps them to itself.
  send(res, status, {
    ...answer,
    shield: result?.verified ? { recommendation: result.recommendation, risk_status: result.risk_status, risk_score: result.risk_score ?? null, platform: result.session?.platform ?? null } : null,
  });
});

server.listen(PORT, () => console.log(`Demo backend on http://localhost:${PORT} (POST /login with X-Shield-Session)`));
