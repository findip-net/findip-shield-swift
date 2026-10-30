// A stand-in for Shield in the CI run of the demo app, so the run needs no
// account and no network. Answers track, verify and identity-key, and writes
// every request body to EVENTS_FILE for check-events.mjs. Not for real use.

import { appendFileSync } from 'node:fs';
import { createServer } from 'node:http';

const EVENTS_FILE = process.env.EVENTS_FILE ?? 'events.jsonl';

function send(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

createServer((req, res) => {
  let raw = '';
  req.on('data', (chunk) => (raw += chunk));
  req.on('end', () => {
    if (req.url === '/health') return send(res, 200, { ok: true });
    if (req.url === '/v1/shield/track') {
      appendFileSync(EVENTS_FILE, raw + '\n');
      const body = JSON.parse(raw);
      return send(res, 200, {
        request_id: 'req_ci',
        session_id: body.session.session_id,
        risk: { status: 'available', score: 5, level: 'low', recommendation: 'allow', reasons: [] },
        ip: { country: 'GB', asn: 1, asn_name: 'CI', is_vpn: false, is_proxy: false, is_tor: false, is_relay: false, is_hosting: false, is_malicious: false },
      });
    }
    if (req.url === '/v1/shield/sessions/verify') {
      return send(res, 200, { verified: true, risk_status: 'available', recommendation: 'allow' });
    }
    return send(res, 404, { error: 'not_found' });
  });
}).listen(8788, '0.0.0.0');
