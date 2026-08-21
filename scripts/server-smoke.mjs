// End-to-end test of team-server mode. No browser: this script IS a pinned client.
//
//   node scripts/server-smoke.mjs
//
// It proves the security-critical properties of the multi-user foundation:
//   - HTTPS with a self-signed cert the client PINS (wrong cert would not connect)
//   - single-use enrollment codes (a reused code is refused)
//   - device-bound tokens (a token replayed from another device id is refused)
//   - role gating (a worker cannot reach the admin surface)
//   - durability: restart reuses the SAME identity and the SAME tokens keep working
//     (the hard constraint — "when it runs again don't do setup again")
import { spawn } from 'node:child_process';
import { rmSync, existsSync, readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import https from 'node:https';

const PORT = 48443;
const DIR = mkdtempSync(join(tmpdir(), 'magi-srv-'));
const DB = join(DIR, 'magi.db');
const PASS = 'a-strong-admin-passphrase';
const CRT = join(DIR, 'server', 'server.crt');

const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const checks = [];
const check = (name, ok) => { checks.push([name, !!ok]); return !!ok; };

let child, agent, stderr = '';
function boot() {
  const c = spawn(process.execPath, ['server.js'], {
    env: { ...process.env, MAGI_SERVER: '1', MAGI_HOST: '127.0.0.1', MAGI_PORT: String(PORT),
      MAGI_DB: DB, MAGI_DATA_DIR: DIR, MAGI_PASS: PASS, MAGI_USER: 'admin' },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  c.stderr.on('data', d => { stderr += d; });
  return c;
}
function cleanup() {
  try { child?.kill(); } catch {}
  try { agent?.destroy(); } catch {}
  try { rmSync(DIR, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch {}
}
function die(msg) {
  console.error(`\n  SERVER SMOKE FAILED: ${msg}`);
  if (stderr.trim()) console.error('\n  --- server stderr ---\n' + stderr.split('\n').map(l => '  ' + l).join('\n'));
  cleanup();
  process.exit(1);
}

// One pinned HTTPS request. Trusts exactly the server's own cert as the CA and skips the
// hostname check — the fingerprint pin is the trust anchor, which is the correct model for
// a self-signed internal server.
function req(method, path, { token, device, cookie, body } = {}) {
  const data = body != null ? JSON.stringify(body) : null;
  const headers = { 'content-type': 'application/json' };
  if (token) headers.authorization = `Bearer ${token}`;
  if (device) headers['x-magi-device'] = device;
  if (cookie) headers.cookie = cookie;
  if (data) headers['content-length'] = Buffer.byteLength(data);
  return new Promise((resolve, reject) => {
    const r = https.request({ host: '127.0.0.1', port: PORT, method, path, agent, headers }, res => {
      let b = ''; res.on('data', d => b += d);
      res.on('end', () => { let j = null; try { j = b ? JSON.parse(b) : null; } catch {} resolve({ status: res.statusCode, json: j, headers: res.headers, raw: b }); });
    });
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}
async function waitUp() {
  for (let i = 0; i < 100; i++) {
    if (existsSync(CRT)) { try { return readFileSync(CRT); } catch {} }
    if (child.exitCode != null) die(`server exited early (code ${child.exitCode})`);
    await sleep(150);
  }
  die('server never wrote its certificate');
}
async function waitAnswering() {
  for (let i = 0; i < 60; i++) {
    try { const r = await req('GET', '/api/me'); if (r.status) return; } catch {}
    await sleep(150);
  }
  die('server never answered over HTTPS');
}

// ---- run ----
child = boot();
const cert1 = await waitUp();
agent = new https.Agent({ ca: cert1, checkServerIdentity: () => undefined, keepAlive: false });
await waitAnswering();

// a non-pinned client (system CAs only) must be rejected — proves TLS is real, not plaintext
const bareOk = await new Promise(res => {
  const r = https.request({ host: '127.0.0.1', port: PORT, method: 'GET', path: '/api/me' },
    resp => { resp.resume(); res(true); });
  r.on('error', () => res(false)); r.end();
});
check('unpinned TLS client is rejected', bareOk === false);

// admin logs in with the password (session cookie) to mint codes
const login = await req('POST', '/api/auth/login', { body: { username: 'admin', password: PASS } });
const cookie = (login.headers['set-cookie'] || []).map(c => c.split(';')[0]).join('; ');
check('admin login works', login.status === 200 && cookie.includes('sid='));

const mk = await req('POST', '/api/admin/enroll-codes', { cookie, body: { role: 'worker', note: 'test laptop' } });
check('admin mints a worker code', mk.status === 201 && typeof mk.json?.code === 'string');
const workerCode = mk.json?.code;

// enroll a worker device
const dev1 = 'aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa';
const enroll = await req('POST', '/api/enroll', { body: { code: workerCode, username: 'ana', display_name: 'Ana R.', device_id: dev1 } });
check('worker enrolls and gets a token', enroll.status === 201 && typeof enroll.json?.token === 'string' && enroll.json?.role === 'worker');
const workerToken = enroll.json?.token;

// the token authorizes API use...
const list = await req('GET', '/api/projects', { token: workerToken, device: dev1 });
check('device token authorizes API', list.status === 200 && Array.isArray(list.json));
const made = await req('POST', '/api/projects', { token: workerToken, device: dev1, body: { name: 'Acme Q3' } });
check('worker can create a project', made.status === 201 && made.json?.id);

// ...and the negatives
const reuse = await req('POST', '/api/enroll', { body: { code: workerCode, username: 'eve', display_name: 'Eve', device_id: 'bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb' } });
check('a reused enrollment code is refused', reuse.status === 403);

const wrongDev = await req('GET', '/api/projects', { token: workerToken, device: 'cccccccc-3333-4333-8333-cccccccccccc' });
check('token replayed from another device is refused', wrongDev.status === 401);

const noDev = await req('GET', '/api/projects', { token: workerToken });
check('token with NO device header is refused', noDev.status === 401);

const bogus = await req('GET', '/api/projects', { token: 'deadbeef'.repeat(8), device: dev1 });
check('a bogus token is unauthorized', bogus.status === 401);

// a valid session with an unrelated malformed cookie must not 500 the whole request
const badCookie = await req('GET', '/api/projects', { cookie: cookie + '; junk=%zz' });
check('a malformed cookie does not break auth (no 500)', badCookie.status === 200);

const climb = await req('GET', '/api/admin/users', { token: workerToken, device: dev1 });
check('worker is blocked from the admin surface', climb.status === 403);

// an admin-role enrollee CAN reach the admin surface
const mkA = await req('POST', '/api/admin/enroll-codes', { cookie, body: { role: 'admin' } });
const dev2 = 'dddddddd-4444-4444-8444-dddddddddddd';
const enrollA = await req('POST', '/api/enroll', { body: { code: mkA.json?.code, username: 'lead', display_name: 'Team Lead', device_id: dev2 } });
const adminUsers = await req('GET', '/api/admin/users', { token: enrollA.json?.token, device: dev2 });
check('admin-role device reaches the admin surface', adminUsers.status === 200 && adminUsers.json?.length >= 3);

// attribution: the worker's project creation is in the audit log under their display name
const audit = await req('GET', '/api/admin/audit', { token: enrollA.json?.token, device: dev2 });
check('audit log attributes the write to the worker', audit.status === 200
  && audit.json?.some(r => r.display_name === 'Ana R.' && r.path === '/api/projects'));

// ---- durability: restart must reuse identity + keep tokens valid ----
const fp1 = new (await import('node:crypto')).X509Certificate(cert1).fingerprint256;
child.kill();
await new Promise(r => child.once('exit', r));
await sleep(400);
stderr = '';
child = boot();
const cert2 = await waitUp();
await waitAnswering();
const fp2 = new (await import('node:crypto')).X509Certificate(cert2).fingerprint256;
check('restart reuses the SAME certificate identity', fp1 === fp2);

const afterRestart = await req('GET', '/api/projects', { token: workerToken, device: dev1 });
check('tokens still work after a restart', afterRestart.status === 200 && afterRestart.json?.some(p => p.name === 'Acme Q3'));

// ---- report ----
let bad = 0;
for (const [name, ok] of checks) { console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${name}`); if (!ok) bad++; }
cleanup();
if (bad) { console.error(`\n  SERVER SMOKE FAILED — ${bad} check(s)\n`); process.exit(1); }
console.log('\n  server smoke ok\n');
