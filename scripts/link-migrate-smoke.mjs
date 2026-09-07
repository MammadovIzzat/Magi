// Upgrading from a version that kept the link in link.json must move it INTO the database and
// delete the file — without losing the pinned server, the stash or the offline verifier — and drop
// the fields we no longer persist (role, display name).
//
// The fixture is a PRE-0.9.0 link — an operator/user token but no device token. v0.9.0 split the
// device credential from the operator account, so that old token can't authenticate any more. It
// must migrate to a `needs_reconnect` state (which guides a re-enrol, reusing the pinned server and
// the stash) with the dead token dropped — NOT report itself as a live link, which used to leave
// the user dead-ended at sign-in ("this device is not connected to the server"). A live v0.9.0 link
// (device token + operator) is exercised end-to-end by link-smoke / link-login-smoke.
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
// role / display_name / jwt_exp persisted alongside, and NO device_token (that concept is new).
const payload = Buffer.from(JSON.stringify({ sub: 1, username: 'ana', role: 'editor', device_id: 'dev-123', exp: 9999999999 })).toString('base64url');
const token = 'eyJhbGciOiJIUzI1NiJ9.' + payload + '.c2ln';
const legacy = {
  server_url: 'https://srv.test:8443', fingerprint: 'AA:BB:CC', cert_pem: '-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n',
  device_id: 'dev-123', username: 'ana', display_name: 'Ana R.', role: 'editor',
  token: { enc: 'none', data: token }, jwt_exp: 9999999999, pass_verifier: 'scrypt$deadbeef',
  connected_at: '2026-01-01T00:00:00Z', stash_id: 7, last_sync: null, last_ok: null, needs_reauth: 0,
};
const linkPath = join(dir, 'link.json');
writeFileSync(linkPath, JSON.stringify(legacy, null, 2));

const link = await import('../client-link.js');
const { db } = await import('../db.js');

const st = link.status();
check('a pre-0.9.0 link migrates to needs_reconnect, not a live link', st.linked === false && st.needs_reconnect === true);
check('the operator name is still shown (for the reconnect card)', st.link?.username === 'ana');
check('the legacy link.json file is deleted', !existsSync(linkPath));

const row = db.prepare(`SELECT data FROM client_link WHERE id=1`).get();
const stored = row ? JSON.parse(row.data) : null;
check('the link now lives in the database', !!stored);
check('the dead operator token is dropped', stored && stored.token === undefined);
check('needs_reconnect is persisted (so it is not recomputed every load)', stored?.needs_reconnect === 1);
check('role / display_name / jwt_exp are NOT persisted', stored && stored.role === undefined && stored.display_name === undefined && stored.jwt_exp === undefined);
check('the offline-login verifier survived the migration', stored?.pass_verifier === 'scrypt$deadbeef');
check('the pinned server, device id and stash survived', stored?.device_id === 'dev-123' && stored?.server_url === 'https://srv.test:8443' && stored?.stash_id === 7);

let bad = 0;
for (const [n, ok] of checks) { console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${n}`); if (!ok) bad++; }
try { rmSync(dir, { recursive: true, force: true }); } catch {}
if (bad) { console.error(`\n  LINK MIGRATE SMOKE FAILED — ${bad} check(s)\n`); process.exit(1); }
console.log('\n  link-migrate smoke ok\n');
