// Tests the CLIENT side of the link (client-link.js) against a real spawned server.
//
//   node scripts/link-smoke.mjs
//
// Proves: fingerprint pinning (a wrong fingerprint is refused as MITM), enrollment from
// the client, the token stored ENCRYPTED at rest when a keychain is present (and never
// left in plaintext), authenticated requests, heartbeat, and clean disconnect.
import { spawn } from 'node:child_process';
import { rmSync, existsSync, readFileSync, mkdtempSync, statSync } from 'node:fs';
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
function req(method, path, { cookie, body } = {}) {
  const data = body != null ? JSON.stringify(body) : null;
  const headers = { 'content-type': 'application/json' };
  if (cookie) headers.cookie = cookie;
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

// admin logs in and mints codes: code1 is an admin code (so the linked device can exercise a
// structural write below — RBAC itself is covered in server-smoke), code2 for the mismatch path.
const login = await req('POST', '/api/auth/login', { body: { username: 'admin', password: PASS } });
const cookie = (login.headers['set-cookie'] || []).map(c => c.split(';')[0]).join('; ');
const code1 = (await req('POST', '/api/admin/enroll-codes', { cookie, body: { role: 'admin' } })).json?.code;
const code2 = (await req('POST', '/api/admin/enroll-codes', { cookie, body: { role: 'worker' } })).json?.code;

// now drive the CLIENT module
const link = await import('../client-link.js');

// 1) a wrong fingerprint must be refused (MITM defence) — code stays unused
const bad = await link.connect({ server_url: serverUrl, fingerprint: 'AA:BB:CC', code: code1, username: 'x', display_name: 'X', password: 'wrongfp-secret' });
check('wrong fingerprint is refused as MITM', bad.ok === false && /fingerprint/i.test(bad.error || ''));

// 2) request access -> pending; an admin approves -> the client links. Token is encrypted at
// rest and never written in plaintext. (No fingerprint needed: trusted on first connect.)
const secret = [];
link.setEncryptor({ available: true,
  encrypt: (s) => { secret.push(s); return 'ENC(' + Buffer.from(s).toString('base64') + ')'; },
  decrypt: (b) => Buffer.from(String(b).replace(/^ENC\(|\)$/g, ''), 'base64').toString() });
const reqres = await link.connect({ server_url: serverUrl, code: code1, username: 'ana', display_name: 'Ana R.', password: 'ana-secret-8' });
if (!reqres.ok) die('connect() failed: ' + reqres.error);
check('request is pending until an admin approves', reqres.ok === true && reqres.pending === true && link.status().pending === true);
const pending = (await req('GET', '/api/admin/requests', { cookie })).json;
const rid = pending.find(r => r.display_name === 'Ana R.')?.id;
check('the request is visible to the admin', !!rid);
await req('POST', `/api/admin/requests/${rid}/approve`, { cookie });
await link.pollApproval();
link.stopSyncLoop(); // finalize started the sync loop; stop it so the test drives things
check('client links once approved', link.status().linked === true && link.status().link?.username === 'ana');
check('link reports token encrypted at rest', link.status().link?.token_at_rest === 'encrypted');
const rawFile = readFileSync(link.LINK_PATH, 'utf8');
const token = secret[0];
check('raw token is NOT written to disk', token && !rawFile.includes(token));
check('link file is chmod 0600', (statSync(link.LINK_PATH).mode & 0o777) === 0o600);

// 3) authenticated requests work through the link, and are attributed to the display name
const created = await link.remoteFetch('/api/projects', { method: 'POST', body: { name: 'Linked Project' } });
check('authenticated request via link works', created.status === 201);
const hb = await link.heartbeat();
check('heartbeat reports online', hb.online === true && hb.who?.display_name === 'Ana R.');

// 3b) an admin resets the password -> epoch bump -> the token dies -> the client must re-auth,
// works offline against the cached verifier meanwhile, and logs back in with the new password.
const anaId = (await req('GET', '/api/admin/users', { cookie })).json.find(u => u.username === 'ana').id;
await req('POST', `/api/admin/users/${anaId}/reset-password`, { cookie, body: { password: 'ana-new-pass-9' } });
const syncDead = await link.syncOnce();
check('a bumped epoch forces the client to re-authenticate', syncDead.needs_reauth === true && link.status().link?.needs_reauth === true);
check('offline login still accepts the cached (old) password', link.offlineLogin('ana-secret-8').ok === true && link.offlineLogin('wrong').ok === false);
const relog = await link.login({ password: 'ana-new-pass-9' });
link.stopSyncLoop();
check('logging in with the new password clears re-auth and refreshes the token', relog.ok === true && link.status().link?.needs_reauth === false);
check('the cached verifier now matches the new password', link.offlineLogin('ana-new-pass-9').ok === true && link.offlineLogin('ana-secret-8').ok === false);
const afterRelog = await link.remoteFetch('/api/me', {});
check('sync works again after re-authentication', afterRelog.status === 200 && afterRelog.json?.username === 'ana');

// 4) the code was consumed on approval — requesting again with it is refused
const reuse = await link.connect({ server_url: serverUrl, code: code1, username: 'zzz', display_name: 'Z', password: 'zzz-secret-8' });
check('the code was single-use (reuse refused)', reuse.ok === false);

// 5) disconnect clears the local link
link.disconnect();
check('disconnect removes the stored link', !existsSync(link.LINK_PATH) && link.status().linked === false);

let bad2 = 0;
for (const [name, okk] of checks) { console.log(`  ${okk ? 'ok  ' : 'FAIL'}  ${name}`); if (!okk) bad2++; }
cleanup();
if (bad2) { console.error(`\n  LINK SMOKE FAILED — ${bad2} check(s)\n`); process.exit(1); }
console.log('\n  link smoke ok\n');
