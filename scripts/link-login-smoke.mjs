// Security regression: a device connected to a team server must open with the SERVER identity
// ONLY — never a leftover local account (e.g. the shipped admin/admin), which would otherwise
// expose the whole team's synced data. Runs a real client-mode server.js linked to a real team
// server and drives the actual /api/auth/login HTTP route.
//
//   node scripts/link-login-smoke.mjs
import { spawn } from 'node:child_process';
import { rmSync, existsSync, readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import http from 'node:http';
import https from 'node:https';
import { X509Certificate } from 'node:crypto';

const TEAM = 48446, CLIENT = 48447;
const teamDir = mkdtempSync(join(tmpdir(), 'magi-llsrv-'));
const cliDir = mkdtempSync(join(tmpdir(), 'magi-llcli-'));
const TEAM_PASS = 'a-strong-admin-passphrase';
const CRT = join(teamDir, 'server', 'server.crt');
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const checks = [];
const check = (name, ok) => { checks.push([name, !!ok]); if (!ok) console.error('   ^ FAILED: ' + name); return !!ok; };

let team, cli, teamErr = '', cliErr = '', agent;
function cleanup() {
  try { team?.kill(); } catch {} try { cli?.kill(); } catch {} try { agent?.destroy(); } catch {}
  for (const d of [teamDir, cliDir]) { try { rmSync(d, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch {} }
}
process.on('exit', () => { try { team?.kill(); } catch {} try { cli?.kill(); } catch {} });
function die(msg) {
  console.error(`\n  LINK-LOGIN SMOKE FAILED: ${msg}`);
  if (teamErr.trim()) console.error('  team stderr:\n' + teamErr.split('\n').map(l => '   ' + l).join('\n'));
  if (cliErr.trim()) console.error('  client stderr:\n' + cliErr.split('\n').map(l => '   ' + l).join('\n'));
  cleanup(); process.exit(1);
}
process.on('uncaughtException', (e) => die('uncaught: ' + (e?.stack || e?.message || e)));

// HTTPS to the team server (pinned cert), HTTP to the local client server.
function reqTeam(method, path, { token, body } = {}) { return doReq(https, TEAM, method, path, { token, body, agent }); }
function reqCli(method, path, { token, body } = {}) { return doReq(http, CLIENT, method, path, { token, body }); }
function doReq(mod, port, method, path, { token, body, agent } = {}) {
  const data = body != null ? JSON.stringify(body) : null;
  const headers = { 'content-type': 'application/json' };
  if (token) headers.authorization = `Bearer ${token}`;
  if (data) headers['content-length'] = Buffer.byteLength(data);
  return new Promise((resolve, reject) => {
    const r = mod.request({ host: '127.0.0.1', port, method, path, agent, headers }, res => {
      let b = ''; res.on('data', d => b += d);
      res.on('end', () => { let j = null; try { j = b ? JSON.parse(b) : null; } catch {} resolve({ status: res.statusCode, json: j }); });
    });
    r.on('error', reject); if (data) r.write(data); r.end();
  });
}

// ---- boot the team server (HTTPS) ----
team = spawn(process.execPath, ['server.js'], {
  env: { ...process.env, MAGI_DATA_DIR: teamDir, MAGI_DB: join(teamDir, 'magi.db'),
    MAGI_SERVER: '1', MAGI_MFA: 'off', MAGI_HOST: '127.0.0.1', MAGI_PORT: String(TEAM), MAGI_PASS: TEAM_PASS, MAGI_USER: 'admin' },
  stdio: ['ignore', 'ignore', 'pipe'],
});
team.stderr.on('data', d => { teamErr += d; });
let cert;
for (let i = 0; i < 120 && !cert; i++) { if (existsSync(CRT)) { try { cert = readFileSync(CRT); } catch {} } if (team.exitCode != null) die('team server exited early'); if (!cert) await sleep(150); }
if (!cert) die('team server never wrote its cert');
agent = new https.Agent({ ca: cert, checkServerIdentity: () => undefined });
for (let i = 0; i < 60; i++) { try { if ((await reqTeam('GET', '/api/me')).status) break; } catch {} await sleep(150); }
const fingerprint = new X509Certificate(cert).fingerprint256;

// ---- boot the client (plain HTTP, standalone; seeds the default admin/admin) ----
cli = spawn(process.execPath, ['server.js'], {
  env: { ...process.env, MAGI_DATA_DIR: cliDir, MAGI_DB: join(cliDir, 'magi.db'),
    MAGI_SERVER: '', MAGI_MFA: 'off', MAGI_HOST: '127.0.0.1', MAGI_PORT: String(CLIENT) },
  stdio: ['ignore', 'ignore', 'pipe'],
});
cli.stderr.on('data', d => { cliErr += d; });
for (let i = 0; i < 80; i++) { try { if ((await reqCli('GET', '/api/me')).status) break; } catch {} if (cli.exitCode != null) die('client exited early'); await sleep(150); }

// ---- team admin mints a device code + creates operator accounts ----
const adminTok = (await reqTeam('POST', '/api/auth/login', { body: { username: 'admin', password: TEAM_PASS } })).json?.token;
if (!adminTok) die('team admin login failed');
const code = (await reqTeam('POST', '/api/admin/enroll-codes', { token: adminTok })).json?.code;
await reqTeam('POST', '/api/admin/users', { token: adminTok, body: { username: 'ana', password: 'ana-secret-8', role: 'worker' } });
await reqTeam('POST', '/api/admin/users', { token: adminTok, body: { username: 'bob', password: 'bob-secret-8', role: 'editor' } });

// A) BEFORE connecting, the local admin/admin opens the standalone client.
const preLocal = await reqCli('POST', '/api/auth/login', { body: { username: 'admin', password: 'admin' } });
check('standalone: the local admin account can open the app', preLocal.status === 200 && !!preLocal.json?.token);
const localTok = preLocal.json.token;

// The DEVICE connects (code only, no account) — uses the local session to reach the gated route.
const conn = await reqCli('POST', '/api/link/connect', { token: localTok, body: { server_url: `https://127.0.0.1:${TEAM}`, fingerprint, code, device_name: 'ana-laptop' } });
check('device submits a connect request (pending)', conn.status === 201);
const pend = (await reqTeam('GET', '/api/admin/requests', { token: adminTok })).json || [];
const rid = pend.find(r => r.device_name === 'ana-laptop')?.id;
if (!rid) die('the connect request never reached the team server');
await reqTeam('POST', `/api/admin/requests/${rid}/approve`, { token: adminTok });

// Wait for the client's background poll to register the device — /api/me (unauth) then reports the
// device is connected (but no operator signed in yet).
for (let i = 0; i < 80; i++) {
  const anon = (await reqCli('GET', '/api/me')).json;
  if (anon?.link?.connected) break;
  if (cli.exitCode != null) die('client exited during connect');
  await sleep(200);
}
const anonConnected = await reqCli('GET', '/api/me');
check('connected device, no operator yet: login screen is told it is connected', anonConnected.status === 401 && anonConnected.json?.link?.connected === true && !anonConnected.json?.link?.username);

// An operator signs in on the connected device (online: device token + user password).
const anaLogin = await reqCli('POST', '/api/auth/login', { body: { username: 'ana', password: 'ana-secret-8' } });
const anaTok = anaLogin.json?.token || null;
check('an operator signs in on the connected device', anaLogin.status === 200 && !!anaTok);

// B) once connected, the leftover local admin/admin can NO LONGER open the device.
const postLocal = await reqCli('POST', '/api/auth/login', { body: { username: 'admin', password: 'admin' } });
check('connected: a local account (admin/admin) can no longer open the device', postLocal.status === 401);
const oldSession = await reqCli('GET', '/api/me', { token: localTok });
check('connected: the pre-connect local session is invalidated', oldSession.status === 401);

// The operator session resolves to the server identity + role (from the signed token).
const me = await reqCli('GET', '/api/me', { token: anaTok });
check('the operator session resolves to the server identity and role', me.status === 200 && me.json?.username === 'ana' && me.json?.role === 'worker');
// A wrong password is refused.
const wrong = await reqCli('POST', '/api/auth/login', { body: { username: 'ana', password: 'not-the-password' } });
check('connected: a wrong password is refused', wrong.status === 401);
// Shared portal: a DIFFERENT operator can sign in on the SAME device.
const bobLogin = await reqCli('POST', '/api/auth/login', { body: { username: 'bob', password: 'bob-secret-8' } });
check('shared portal: a different operator can sign in on the same device', bobLogin.status === 200 && (await reqCli('GET', '/api/me', { token: bobLogin.json.token })).json?.role === 'editor');
// sign ana back in for the password-change test below
await reqCli('POST', '/api/auth/login', { body: { username: 'ana', password: 'ana-secret-8' } });
const anaTok2 = (await reqCli('POST', '/api/auth/login', { body: { username: 'ana', password: 'ana-secret-8' } })).json.token;

// D) an operator can change their (server) password from the client. It changes on the server, the
// cached offline verifier is refreshed, the local app session survives, old password stops working
// and the new one opens the app.
const chg = await reqCli('POST', '/api/change-password', { token: anaTok2, body: { current: 'ana-secret-8', next: 'ana-fresh-pass-11' } });
check('an operator can change their password from the client', chg.status === 200 && chg.json?.ok === true);
check('the app session survives the password change', (await reqCli('GET', '/api/me', { token: anaTok2 })).status === 200);
check('the OLD password no longer opens the app', (await reqCli('POST', '/api/auth/login', { body: { username: 'ana', password: 'ana-secret-8' } })).status === 401);
const newPw = await reqCli('POST', '/api/auth/login', { body: { username: 'ana', password: 'ana-fresh-pass-11' } });
check('the NEW password opens the app', newPw.status === 200 && !!newPw.json?.token);
check('the password actually changed on the server', (await reqTeam('POST', '/api/auth/login', { body: { username: 'ana', password: 'ana-fresh-pass-11' } })).status === 200);

// C) after disconnect, the device is standalone again and the local admin works.
await reqCli('POST', '/api/link/disconnect', { token: newPw.json.token });
const backLocal = await reqCli('POST', '/api/auth/login', { body: { username: 'admin', password: 'admin' } });
check('after disconnect, the local admin account can open the app again', backLocal.status === 200 && !!backLocal.json?.token);
const anaGone = await reqCli('POST', '/api/auth/login', { body: { username: 'ana', password: 'ana-secret-8' } });
check('after disconnect, the former server identity can no longer log in', anaGone.status === 401);

let bad = 0;
for (const [name, ok] of checks) { console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${name}`); if (!ok) bad++; }
cleanup();
if (bad) { console.error(`\n  LINK-LOGIN SMOKE FAILED — ${bad} check(s)\n`); process.exit(1); }
console.log('\n  link-login smoke ok\n');
