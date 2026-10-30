// Checks what the demo app sent during the CI run: one session across a short
// trip to the background, its session_start, both logins, and nothing typed
// into the form.

import { readFileSync } from 'node:fs';

const [file, platform] = process.argv.slice(2);
const raw = readFileSync(file, 'utf8');
const events = raw.trim().split('\n').map((line) => JSON.parse(line));
const names = events.map((e) => e.event.name);
const count = (name) => names.filter((n) => n === name).length;

function need(ok, message) {
  if (!ok) {
    console.error(`${message}\nnames: ${names.join(', ')}`);
    process.exit(1);
  }
}

need(new Set(events.map((e) => e.session.session_id)).size === 1, 'a short trip to the background changed the session');
need(count('session_start') === 1, 'expected one session_start');
need(count('login_attempt') === 2, 'expected two login_attempt events');
need(count('login_success') === 2, 'expected two login_success events');
need(events.every((e) => e.sdk.integration === platform), `expected integration ${platform}`);
need(!raw.includes('ci-password-value'), 'the password reached Shield');
need(!raw.includes('ci-user@example.com'), 'the plain email reached Shield');
console.log(`ok: ${names.length} events, one session, nothing typed left the device`);
