// Upgrading from a version that kept the link in link.json must move it INTO the database and
// delete the file — without the user re-enrolling — and drop the fields we no longer persist
// (role, display name). No server needed: migration is purely local.
//
//   node scripts/link-migrate-smoke.mjs
import { mkdtempSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const dir = mkdtempSync(join(tmpdir(), 'magi-lmig-'));
process.env.MAGI_DATA_DIR = dir;
process.env.MAGI_DB = join(dir, 'magi.db');

const checks = [];
const check = (n, ok) => { checks.push([n, !!ok]); };

// a link.json exactly as an older client wrote it: token wrapped { enc:'none', data } (no keychain),
// and role / display_name / jwt_exp persisted alongside.
const payload = Buffer.from(JSON.stringify({ sub: 1, username: 'ana', role: 'editor', device_id: 'dev-123', exp: 9999999999 })).toString('base64url');
const token = 'eyJhbGciOiJIUzI1NiJ9.' + payload + '.c2ln';
const legacy = {
  server_url: 'https://srv.test:8443', fingerprint: 'AA:BB:CC', cert_pem: '-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n',
  device_id: 'dev-123', username: 'ana', display_name: 'Ana R.', role: 'editor',
  token: { enc: 'none', data: token }, jwt_exp: 9999999999, pass_verifier: 'scrypt$deadbeef',
  connected_at: '2026-01-01T00:00:00Z', stash_id: null, last_sync: null, last_ok: null, needs_reauth: 0,
};
const linkPath = join(dir, 'link.json');
writeFileSync(linkPath, JSON.stringify(legacy, null, 2));

const link = await import('../client-link.js');
const { db } = await import('../db.js');

const st = link.status();
check('a legacy link.json is recognized as a live link', st.linked === true && st.link?.username === 'ana');
check('the role is derived from the JWT after migration', st.link?.role === 'editor');
check('the display name falls back to the username (not persisted)', st.link?.display_name === 'ana');
check('the legacy link.json file is deleted', !existsSync(linkPath));

const row = db.prepare(`SELECT data FROM client_link WHERE id=1`).get();
const stored = row ? JSON.parse(row.data) : null;
check('the link now lives in the database', !!stored && stored.token === token);
check('role / display_name / jwt_exp are NOT persisted', stored && stored.role === undefined && stored.display_name === undefined && stored.jwt_exp === undefined);
check('the offline-login verifier survived the migration', stored?.pass_verifier === 'scrypt$deadbeef');
check('the device id and server url survived', stored?.device_id === 'dev-123' && stored?.server_url === 'https://srv.test:8443');

// offline login still works against the migrated verifier is not asserted here (no real scrypt hash);
// the point is the field carried across untouched.

let bad = 0;
for (const [n, ok] of checks) { console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${n}`); if (!ok) bad++; }
try { rmSync(dir, { recursive: true, force: true }); } catch {}
if (bad) { console.error(`\n  LINK MIGRATE SMOKE FAILED — ${bad} check(s)\n`); process.exit(1); }
console.log('\n  link-migrate smoke ok\n');
