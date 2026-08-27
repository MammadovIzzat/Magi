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
    env: { ...process.env, MAGI_SERVER: '1', MAGI_MFA: 'off', MAGI_HOST: '127.0.0.1', MAGI_PORT: String(PORT),
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

// request -> admin approves -> client polls the token
async function enrollApprove(code, username, display_name, device_id) {
  const rq = await req('POST', '/api/enroll', { body: { code, username, display_name, device_id } });
  if (rq.status !== 202 || !rq.json?.request_id) return { ok: false, rq };
  const appr = await req('POST', `/api/admin/requests/${rq.json.request_id}/approve`, { cookie });
  const poll = await req('GET', `/api/enroll/poll?request_id=${rq.json.request_id}&device_id=${device_id}`);
  return { ok: appr.status === 200 && poll.json?.status === 'approved' && !!poll.json.token, token: poll.json?.token, role: poll.json?.role, rq };
}

// a join request first lands as PENDING (no token) and shows up for the admin
const dev1 = 'aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa';
const wreq = await req('POST', '/api/enroll', { body: { code: workerCode, username: 'ana', display_name: 'Ana R.', device_id: dev1 } });
check('a join request is pending, not an immediate token', wreq.status === 202 && wreq.json?.request_id && !wreq.json?.token);
const pend = await req('GET', '/api/admin/requests', { cookie });
check('admin sees the pending request', pend.status === 200 && pend.json.some(r => r.device_id === dev1 && r.display_name === 'Ana R.'));
const appr = await req('POST', `/api/admin/requests/${wreq.json.request_id}/approve`, { cookie });
check('admin approves the request', appr.status === 200);
const poll = await req('GET', `/api/enroll/poll?request_id=${wreq.json.request_id}&device_id=${dev1}`);
check('approved client polls and receives its token', poll.json?.status === 'approved' && typeof poll.json?.token === 'string' && poll.json?.role === 'worker');
const workerToken = poll.json?.token;
const poll2 = await req('GET', `/api/enroll/poll?request_id=${wreq.json.request_id}&device_id=${dev1}`);
check('the token is delivered only once', poll2.json?.status === 'approved' && !poll2.json?.token);

// the token authorizes API use...
const list = await req('GET', '/api/projects', { token: workerToken, device: dev1 });
check('device token authorizes API', list.status === 200 && Array.isArray(list.json));
// RBAC: engagement STRUCTURE + templates are admin-only; workers work checklists + findings.
const wProj = await req('POST', '/api/projects', { token: workerToken, device: dev1, body: { name: 'Acme Q3' } });
check('a worker cannot create an engagement', wProj.status === 403);
const made = await req('POST', '/api/projects', { cookie, body: { name: 'Acme Q3' } });
check('an admin can create an engagement', made.status === 201 && made.json?.id);
const wEdit = await req('PATCH', `/api/projects/${made.json.id}`, { token: workerToken, device: dev1, body: { client: 'Acme' } });
check('a worker cannot edit engagement details/scope', wEdit.status === 403);
const wTpl = await req('POST', '/api/templates/web/items', { token: workerToken, device: dev1, body: { title: 'x' } });
check('a worker cannot edit templates', wTpl.status === 403);
const aFinish = await req('PATCH', `/api/projects/${made.json.id}`, { cookie, body: { status: 'finished', client: 'Acme' } });
check('an admin can edit + finish an engagement', aFinish.status === 200 && aFinish.json?.status === 'finished' && aFinish.json?.end_date);

// findings: creation (the route the app posts to), attack-chain links, and the retest type
const extAsset = (await req('POST', `/api/projects/${made.json.id}/assets`, { cookie, body: { grp: 'external', label: 'Ext' } })).json;
const wAsset = await req('POST', `/api/projects/${made.json.id}/assets`, { token: workerToken, device: dev1, body: { grp: 'external', label: 'W' } });
check('a worker cannot add an asset', wAsset.status === 403);
const webT = (await req('POST', `/api/assets/${extAsset.id}/targets`, { cookie, body: { type: 'web', label: 'https://x.test' } })).json;
const wTarget = await req('POST', `/api/assets/${extAsset.id}/targets`, { token: workerToken, device: dev1, body: { type: 'web', label: 'https://w.test' } });
check('a worker cannot add a target', wTarget.status === 403);
// but a worker CAN record findings and tick checklist items
const wf = await req('POST', `/api/targets/${webT.id}/findings`, { token: workerToken, device: dev1, body: { title: 'Worker note', kind: 'note' } });
check('a worker can record a finding', wf.status === 201 && !!wf.json?.id);
const anItem = (await req('GET', `/api/targets/${webT.id}`, { cookie })).json.items[0];
const wTick = await req('PATCH', `/api/items/${anItem.id}`, { token: workerToken, device: dev1, body: { status: 'done' } });
check('a worker can tick a checklist item', wTick.status === 200 && wTick.json?.status === 'done');
const wItemEdit = await req('PATCH', `/api/items/${anItem.id}`, { token: workerToken, device: dev1, body: { title: 'hacked title' } });
check('a worker cannot edit a checklist item’s text', wItemEdit.status === 403);
const fA = await req('POST', `/api/targets/${webT.id}/findings`, { cookie, body: { title: 'Creds', kind: 'credential', body: 'a:b' } });
check('a finding can be created on a target', fA.status === 201 && !!fA.json?.id);
const aUid = (await req('GET', `/api/targets/${webT.id}`, { cookie })).json.findings.find(f => f.title === 'Creds').uid;
await req('POST', `/api/targets/${webT.id}/findings`, { cookie, body: { title: 'RCE', kind: 'vuln', severity: 'critical', refs: [aUid] } });
const withLinks = (await req('GET', `/api/targets/${webT.id}`, { cookie })).json.findings;
check('a finding chains to another (refs resolve to a title)', withLinks.some(f => (f.links || []).some(l => l.title === 'Creds')));
const cand = await req('GET', `/api/targets/${webT.id}/finding-candidates`, { cookie });
check('chain candidates list the engagement’s findings', cand.status === 200 && cand.json.length >= 2);
const rAsset = (await req('POST', `/api/projects/${made.json.id}/assets`, { cookie, body: { grp: 'retest', label: 'RT' } })).json;
const rT = await req('POST', `/api/assets/${rAsset.id}/targets`, { cookie, body: { type: 'retest', label: 'Remediation' } });
check('a retest target can be created', rT.status === 201 && !!rT.json?.id);
check('a retest target carries no checklist', (await req('GET', `/api/targets/${rT.json.id}`, { cookie })).json.items.length === 0);
const rf = await req('POST', `/api/targets/${rT.json.id}/findings`, { cookie, body: { title: 'ACME-1', kind: 'vuln', fix_status: 'half_fixed' } });
check('a retest finding stores its fix status', rf.status === 201 && rf.json?.fix_status === 'half_fixed');
const badFix = await req('POST', `/api/targets/${rT.json.id}/findings`, { cookie, body: { title: 'x', fix_status: 'nonsense' } });
check('an invalid fix status is rejected (stored null)', badFix.json?.fix_status === null);

// engagement -> target directly (the folder layer is auto-managed): a web target lands in an
// External group, a worker is refused (admin-only structure).
const dt = await req('POST', `/api/projects/${made.json.id}/targets`, { cookie, body: { type: 'web', label: 'https://direct.test' } });
check('a target can be added straight to an engagement', dt.status === 201 && !!dt.json?.id);
const detail = await req('GET', `/api/projects/${made.json.id}`, { cookie });
const extGroup = (detail.json.assets || []).find(f => f.grp === 'external');
check('the direct target lands in an auto External group with its checklist', !!extGroup && extGroup.items.some(t => t.label === 'https://direct.test' && t.total > 0));
const wDirect = await req('POST', `/api/projects/${made.json.id}/targets`, { token: workerToken, device: dev1, body: { type: 'web', label: 'https://nope.test' } });
check('a worker cannot add a target to an engagement', wDirect.status === 403);

// the code was consumed on approval — a new request with it is refused
const reuse = await req('POST', '/api/enroll', { body: { code: workerCode, username: 'eve', display_name: 'Eve', device_id: 'bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb' } });
check('the code is single-use (consumed on approval)', reuse.status === 403);

// a rejected request yields no token
const rc = (await req('POST', '/api/admin/enroll-codes', { cookie, body: { role: 'worker' } })).json.code;
const rdev = 'eeeeeeee-5555-4555-8555-eeeeeeeeeeee';
const rreq = await req('POST', '/api/enroll', { body: { code: rc, username: 'mallory', display_name: 'Mallory', device_id: rdev } });
await req('POST', `/api/admin/requests/${rreq.json.request_id}/reject`, { cookie });
const rpoll = await req('GET', `/api/enroll/poll?request_id=${rreq.json.request_id}&device_id=${rdev}`);
check('a rejected request yields no token', rpoll.json?.status === 'rejected' && !rpoll.json?.token);

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
const enrollA = await enrollApprove(mkA.json?.code, 'lead', 'Team Lead', dev2);
check('admin-role device enrolls via approval', enrollA.ok && enrollA.role === 'admin');
const adminUsers = await req('GET', '/api/admin/users', { token: enrollA.token, device: dev2 });
check('admin-role device reaches the admin surface', adminUsers.status === 200 && adminUsers.json?.length >= 3);

// attribution: the worker's finding write is in the audit log under their display name
const audit = await req('GET', '/api/admin/audit', { token: enrollA.token, device: dev2 });
check('audit log attributes the write to the worker', audit.status === 200
  && audit.json?.some(r => r.display_name === 'Ana R.' && (r.path || '').includes('/findings')));

// hard-delete removes a device, its orphaned account, AND that account's redeemed codes
const tdev = 'ffffffff-6666-4666-8666-ffffffffffff';
const tcode = (await req('POST', '/api/admin/enroll-codes', { cookie, body: { role: 'worker', note: 'temp code' } })).json.code;
await enrollApprove(tcode, 'temp', 'Temp User', tdev);
await req('DELETE', `/api/admin/devices/${tdev}`, { cookie });           // soft revoke
const purge = await req('DELETE', `/api/admin/devices/${tdev}?hard=1`, { cookie }); // hard delete
const devs = await req('GET', '/api/admin/devices', { cookie });
const users = await req('GET', '/api/admin/users', { cookie });
const codesPostPurge = await req('GET', '/api/admin/enroll-codes', { cookie });
check('hard-delete removes the device, its account and its redeemed code', purge.json?.deleted === true
  && !devs.json.some(d => d.id === tdev) && !users.json.some(u => u.username === 'temp')
  && !codesPostPurge.json.some(c => c.note === 'temp code'));

// killing an unused code removes it and makes it unredeemable
const kc = await req('POST', '/api/admin/enroll-codes', { cookie, body: { role: 'worker', note: 'to kill' } });
const kid = (await req('GET', '/api/admin/enroll-codes', { cookie })).json.find(c => c.note === 'to kill')?.id;
await req('DELETE', `/api/admin/enroll-codes/${kid}`, { cookie });
const codesAfter = await req('GET', '/api/admin/enroll-codes', { cookie });
const useKilled = await req('POST', '/api/enroll', { body: { code: kc.json.code, username: 'ghost', display_name: 'Ghost', device_id: '99999999-7777-4777-8777-999999999999' } });
check('a killed code is removed and cannot be redeemed', !codesAfter.json.some(c => c.id === kid) && useKilled.status === 403);

// clear-used drops redeemed/expired codes but keeps active ones
const keep = (await req('POST', '/api/admin/enroll-codes', { cookie, body: { role: 'worker', note: 'keep me' } })).json.code;
const before = (await req('GET', '/api/admin/enroll-codes', { cookie })).json;
const usedBefore = before.filter(c => c.used_at).length;
const cl = await req('DELETE', '/api/admin/enroll-codes?used=1', { cookie });
const codesLeft = (await req('GET', '/api/admin/enroll-codes', { cookie })).json;
check('clear-used drops redeemed codes but keeps active ones', usedBefore > 0 && cl.json?.cleared === usedBefore
  && !codesLeft.some(c => c.used_at) && codesLeft.some(c => c.note === 'keep me'));

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

// self-service username change (confirmed by password), then it becomes the login name
const login2 = await req('POST', '/api/auth/login', { body: { username: 'admin', password: PASS } });
const cookie2 = (login2.headers['set-cookie'] || []).map(c => c.split(';')[0]).join('; ');
const badPw = await req('POST', '/api/change-username', { cookie: cookie2, body: { username: 'memo', password: 'wrong' } });
check('change-username needs the right password', badPw.status === 400);
const rename = await req('POST', '/api/change-username', { cookie: cookie2, body: { username: 'memo', password: PASS } });
check('an account can change its own username', rename.status === 200 && rename.json?.username === 'memo');
const oldName = await req('POST', '/api/auth/login', { body: { username: 'admin', password: PASS } });
const newName = await req('POST', '/api/auth/login', { body: { username: 'memo', password: PASS } });
check('the new username is now the login name (old one gone)', oldName.status === 401 && newName.status === 200);

// ---- report ----
let bad = 0;
for (const [name, ok] of checks) { console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${name}`); if (!ok) bad++; }
cleanup();
if (bad) { console.error(`\n  SERVER SMOKE FAILED — ${bad} check(s)\n`); process.exit(1); }
console.log('\n  server smoke ok\n');
