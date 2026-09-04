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

// ---- team admin mints a worker enrollment code ----
const adminTok = (await reqTeam('POST', '/api/auth/login', { body: { username: 'admin', password: TEAM_PASS } })).json?.token;
if (!adminTok) die('team admin login failed');
const code = (await reqTeam('POST', '/api/admin/enroll-codes', { token: adminTok, body: { role: 'worker' } })).json?.code;

// A) BEFORE linking, the local admin/admin opens the standalone client.
const preLocal = await reqCli('POST', '/api/auth/login', { body: { username: 'admin', password: 'admin' } });
check('standalone: the local admin account can open the app', preLocal.status === 200 && !!preLocal.json?.token);
const localTok = preLocal.json.token;

// Link this client to the team server as "ana" (uses the local session to reach the gated route).
const conn = await reqCli('POST', '/api/link/connect', { token: localTok, body: { server_url: `https://127.0.0.1:${TEAM}`, fingerprint, code, username: 'ana', display_name: 'Ana R.', password: 'ana-secret-8' } });
check('client submits a join request (pending)', conn.status === 201);
const pend = (await reqTeam('GET', '/api/admin/requests', { token: adminTok })).json || [];
const rid = pend.find(r => r.display_name === 'Ana R.')?.id;
if (!rid) die('the join request never reached the team server');
await reqTeam('POST', `/api/admin/requests/${rid}/approve`, { token: adminTok, body: { role: 'worker' } });

// Wait for the client's background poll to finalize the link — signalled by /api/me (unauth)
// reporting the linked username. We poll THAT, not /api/auth/login, so the login throttle stays
// clean for the real sign-in attempt below.
for (let i = 0; i < 80; i++) {
  if ((await reqCli('GET', '/api/me')).json?.link?.username === 'ana') break;
  if (cli.exitCode != null) die('client exited during linking');
  await sleep(200);
}
const anaLogin = await reqCli('POST', '/api/auth/login', { body: { username: 'ana', password: 'ana-secret-8' } });
const anaTok = anaLogin.json?.token || null;
check('linked: the server user opens the app with their server password (offline verifier)', anaLogin.status === 200 && !!anaTok);

// B) THE FIX: once linked, the leftover local admin/admin can NO LONGER open the device.
const postLocal = await reqCli('POST', '/api/auth/login', { body: { username: 'admin', password: 'admin' } });
check('linked: a local account (admin/admin) can no longer open the device', postLocal.status === 401);
// and the old local session token is dead too
const oldSession = await reqCli('GET', '/api/me', { token: localTok });
check('linked: the pre-link local session is invalidated', oldSession.status === 401);

// The link session resolves to the SERVER identity + role (from the signed token).
const me = await reqCli('GET', '/api/me', { token: anaTok });
check('linked session resolves to the server identity and role', me.status === 200 && me.json?.username === 'ana' && me.json?.role === 'worker');
// The login screen is told who to sign in as.
const anon = await reqCli('GET', '/api/me');
check('the login screen is told the server username to use', anon.status === 401 && anon.json?.link?.username === 'ana');
// A wrong server password is refused (no fallback to any local account).
const wrong = await reqCli('POST', '/api/auth/login', { body: { username: 'ana', password: 'not-the-password' } });
check('linked: a wrong server password is refused', wrong.status === 401);

// C) after disconnect, the device is standalone again and the local admin works.
await reqCli('POST', '/api/link/disconnect', { token: anaTok });
const backLocal = await reqCli('POST', '/api/auth/login', { body: { username: 'admin', password: 'admin' } });
check('after disconnect, the local admin account can open the app again', backLocal.status === 200 && !!backLocal.json?.token);
const anaGone = await reqCli('POST', '/api/auth/login', { body: { username: 'ana', password: 'ana-secret-8' } });
check('after disconnect, the former server identity can no longer log in', anaGone.status === 401);

let bad = 0;
for (const [name, ok] of checks) { console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${name}`); if (!ok) bad++; }
cleanup();
if (bad) { console.error(`\n  LINK-LOGIN SMOKE FAILED — ${bad} check(s)\n`); process.exit(1); }
console.log('\n  link-login smoke ok\n');
