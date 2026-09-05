// Tests the CLIENT side of the link (client-link.js) against a real spawned server.
//
//   node scripts/link-smoke.mjs
//
// Proves: fingerprint pinning (a wrong fingerprint is refused as MITM), enrollment from
// the client, the token stored ENCRYPTED at rest when a keychain is present (and never
// left in plaintext), authenticated requests, heartbeat, and clean disconnect.
import { spawn } from 'node:child_process';
import { rmSync, existsSync, readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import https from 'node:https';

const PORT = 48444;
const serverDir = mkdtempSync(join(tmpdir(), 'magi-lsrv-'));
const clientDir = mkdtempSync(join(tmpdir(), 'magi-lcli-'));
const PASS = 'a-strong-admin-passphrase';
const CRT = join(serverDir, 'server', 'server.crt');
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const checks = [];
const check = (name, ok) => { checks.push([name, !!ok]); return !!ok; };

// point THIS process (the client) at its own data dir before importing client-link -> db.js
process.env.MAGI_DATA_DIR = clientDir;
process.env.MAGI_DB = join(clientDir, 'magi.db');

let child, agent, stderr = '';
function cleanup() {
  try { child?.kill(); } catch {}
  try { agent?.destroy(); } catch {}
  for (const d of [serverDir, clientDir]) { try { rmSync(d, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch {} }
}
function die(msg) {
  console.error(`\n  LINK SMOKE FAILED: ${msg}`);
  if (stderr.trim()) console.error('  server stderr:\n' + stderr.split('\n').map(l => '   ' + l).join('\n'));
  cleanup(); process.exit(1);
}
// Never leave a stray server holding the port, even if a check throws unexpectedly.
process.on('exit', () => { try { child?.kill(); } catch {} });
process.on('uncaughtException', (e) => die('uncaught: ' + (e?.stack || e?.message || e)));
function req(method, path, { token, body } = {}) {
  const data = body != null ? JSON.stringify(body) : null;
  const headers = { 'content-type': 'application/json' };
  if (token) headers.authorization = `Bearer ${token}`;
  if (data) headers['content-length'] = Buffer.byteLength(data);
  return new Promise((resolve, reject) => {
    const r = https.request({ host: '127.0.0.1', port: PORT, method, path, agent, headers }, res => {
      let b = ''; res.on('data', d => b += d);
      res.on('end', () => { let j = null; try { j = b ? JSON.parse(b) : null; } catch {} resolve({ status: res.statusCode, json: j, headers: res.headers }); });
    });
    r.on('error', reject); if (data) r.write(data); r.end();
  });
}

// boot the server
child = spawn(process.execPath, ['server.js'], {
  env: { ...process.env, MAGI_DATA_DIR: serverDir, MAGI_DB: join(serverDir, 'magi.db'),
    MAGI_SERVER: '1', MAGI_MFA: 'off', MAGI_HOST: '127.0.0.1', MAGI_PORT: String(PORT), MAGI_PASS: PASS, MAGI_USER: 'admin' },
  stdio: ['ignore', 'ignore', 'pipe'],
});
child.stderr.on('data', d => { stderr += d; });

let cert;
for (let i = 0; i < 100 && !cert; i++) { if (existsSync(CRT)) { try { cert = readFileSync(CRT); } catch {} } if (child.exitCode != null) die('server exited early'); if (!cert) await sleep(150); }
if (!cert) die('server never wrote its cert');
agent = new https.Agent({ ca: cert, checkServerIdentity: () => undefined });
for (let i = 0; i < 60; i++) { try { const r = await req('GET', '/api/me'); if (r.status) break; } catch {} await sleep(150); }

const serverUrl = `https://127.0.0.1:${PORT}`;
const fingerprint = new (await import('node:crypto')).X509Certificate(cert).fingerprint256;

// admin logs in and mints a device code (device codes are role-agnostic now — the admin creates the
// operator account separately, and picks its role there).
const login = await req('POST', '/api/auth/login', { body: { username: 'admin', password: PASS } });
const adminTok = login.json?.token;
const code1 = (await req('POST', '/api/admin/enroll-codes', { token: adminTok })).json?.code;

// The client runs an ENCRYPTED workspace, so the tokens are protected at rest by the same passphrase
// (there is no separate link file any more). Set the key BEFORE importing the module that opens the DB.
process.env.MAGI_DB_KEY = 'client-workspace-passphrase-9';
const link = await import('../client-link.js');
const { db: clientDb } = await import('../db.js');

// 1) a wrong fingerprint must be refused (MITM defence) — code stays unused
const bad = await link.connect({ server_url: serverUrl, fingerprint: 'AA:BB:CC', code: code1, device_name: 'x' });
check('wrong fingerprint is refused as MITM', bad.ok === false && /fingerprint/i.test(bad.error || ''));

// 2) the DEVICE connects (code only) -> pending; an admin accepts -> the device is connected. Its
// token is stored inside the encrypted workspace database, not a plaintext file.
const reqres = await link.connect({ server_url: serverUrl, code: code1, device_name: 'ana-laptop' });
if (!reqres.ok) die('connect() failed: ' + reqres.error);
check('connect is pending until an admin accepts', reqres.ok === true && reqres.pending === true && link.status().pending === true);
const pending = (await req('GET', '/api/admin/requests', { token: adminTok })).json;
const rid = pending.find(r => r.device_name === 'ana-laptop')?.id;
check('the device request is visible to the admin', !!rid);
await req('POST', `/api/admin/requests/${rid}/approve`, { token: adminTok });
await link.pollApproval();
link.stopApprovalPoll();
check('device connects once accepted (awaiting operator login)', !link.status().pending && link.status().needs_login === true && link.status().connected === true);

// 3) admin creates the operator account, then the operator signs in on the connected device
await req('POST', '/api/admin/users', { token: adminTok, body: { username: 'ana', password: 'ana-secret-8', role: 'admin' } });
const lg = await link.login({ username: 'ana', password: 'ana-secret-8' });
link.stopSyncLoop(); // login started the sync loop; stop it so the test drives things
check('the operator signs in on the connected device', lg.ok === true && link.status().linked === true && link.status().link?.username === 'ana');
check('the role comes from the signed token, not client storage', link.status().link?.role === 'admin');
check('link reports the token encrypted at rest', link.status().link?.token_at_rest === 'encrypted');

// the link is one row in the DB; the operator token + device token are kept, role/display are NOT
const stored = JSON.parse(clientDb.prepare(`SELECT data FROM client_link WHERE id=1`).get().data);
const token = stored.token;
check('the operator + device tokens are stored in the workspace database', typeof token === 'string' && token.length > 20 && typeof stored.device_token === 'string');
check('role and display name are NOT persisted (derived from the JWT / server)', stored.role === undefined && stored.display_name === undefined);
check('no plaintext link.json is left on disk', !existsSync(link.LINK_PATH));
const rawDb = readFileSync(join(clientDir, 'magi.db'));
const rawWal = existsSync(join(clientDir, 'magi.db-wal')) ? readFileSync(join(clientDir, 'magi.db-wal')) : Buffer.alloc(0);
check('the workspace file is genuinely encrypted (not a plaintext SQLite header)', rawDb.slice(0, 15).toString() !== 'SQLite format 3');
check('the raw tokens never appear on disk in the clear', !rawDb.includes(Buffer.from(token)) && !rawWal.includes(Buffer.from(token)) && !rawDb.includes(Buffer.from(stored.device_token)));

// 4) authenticated requests work through the link
const created = await link.remoteFetch('/api/projects', { method: 'POST', body: { name: 'Linked Project' } });
check('authenticated request via link works', created.status === 201);
const hb = await link.heartbeat();
check('heartbeat reports online', hb.online === true && hb.who?.username === 'ana');

// 5) an admin resets the password -> epoch bump -> token dies -> re-auth; offline still works
const anaId = (await req('GET', '/api/admin/users', { token: adminTok })).json.find(u => u.username === 'ana').id;
await req('POST', `/api/admin/users/${anaId}/reset-password`, { token: adminTok, body: { password: 'ana-new-pass-9' } });
const syncDead = await link.syncOnce();
check('a bumped epoch forces the client to re-authenticate', syncDead.needs_reauth === true && link.status().link?.needs_reauth === true);
check('offline login still accepts the cached (old) password', link.offlineLogin('ana', 'ana-secret-8').ok === true && link.offlineLogin('ana', 'wrong').ok === false);
const relog = await link.login({ username: 'ana', password: 'ana-new-pass-9' });
link.stopSyncLoop();
check('logging in with the new password clears re-auth and refreshes the token', relog.ok === true && link.status().link?.needs_reauth === false);
check('the cached verifier now matches the new password', link.offlineLogin('ana', 'ana-new-pass-9').ok === true && link.offlineLogin('ana', 'ana-secret-8').ok === false);
const afterRelog = await link.remoteFetch('/api/me', {});
check('sync works again after re-authentication', afterRelog.status === 200 && afterRelog.json?.username === 'ana');

// 6) the code was consumed on accept — connecting again with it is refused
const reuse = await link.connect({ server_url: serverUrl, code: code1, device_name: 'z' });
check('the code was single-use (reuse refused)', reuse.ok === false);

// 5) disconnect clears the local link
link.disconnect();
check('disconnect removes the stored link', !clientDb.prepare(`SELECT 1 FROM client_link WHERE id=1`).get() && link.status().linked === false);

let bad2 = 0;
for (const [name, okk] of checks) { console.log(`  ${okk ? 'ok  ' : 'FAIL'}  ${name}`); if (!okk) bad2++; }
cleanup();
if (bad2) { console.error(`\n  LINK SMOKE FAILED — ${bad2} check(s)\n`); process.exit(1); }
console.log('\n  link smoke ok\n');
