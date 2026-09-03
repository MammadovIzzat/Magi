// Multi-factor auth end-to-end, against a real server with MFA ENFORCED (the default).
//
//   node scripts/mfa-smoke.mjs
//
// Proves: password alone yields only a pending session (no access); first sign-in forces TOTP
// enrolment and returns recovery codes; a good code (or a one-time recovery code) completes the
// second factor; wrong codes and reused recovery codes are refused; an admin can reset a lost
// second factor. TOTP codes are computed with the shipped totp module (RFC 6238).
import { spawn } from 'node:child_process';
import { rmSync, existsSync, readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import https from 'node:https';
import * as totp from '../totp.js';

const PORT = 48449;
const DIR = mkdtempSync(join(tmpdir(), 'magi-mfa-'));
const PASS = 'a-strong-admin-passphrase';
const CRT = join(DIR, 'server', 'server.crt');
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const checks = [];
const check = (name, ok) => { checks.push([name, !!ok]); if (!ok) console.error('   ^ FAILED: ' + name); return !!ok; };

let child, agent, stderr = '';
function cleanup() { try { child?.kill(); } catch {} try { agent?.destroy(); } catch {} try { rmSync(DIR, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch {} }
process.on('exit', () => { try { child?.kill(); } catch {} });
process.on('uncaughtException', (e) => { console.error('\n  MFA SMOKE crashed:', e?.stack || e); if (stderr.trim()) console.error(stderr); cleanup(); process.exit(1); });
function die(msg) { console.error(`\n  MFA SMOKE FAILED: ${msg}`); if (stderr.trim()) console.error(stderr.split('\n').map(l => '   ' + l).join('\n')); cleanup(); process.exit(1); }

function req(method, path, { token, device, body } = {}) {
  const data = body != null ? JSON.stringify(body) : null;
  const headers = { 'content-type': 'application/json' };
  if (token) headers.authorization = `Bearer ${token}`;
  if (device) headers['x-magi-device'] = device;
  if (data) headers['content-length'] = Buffer.byteLength(data);
  return new Promise((resolve, reject) => {
    const r = https.request({ host: '127.0.0.1', port: PORT, method, path, agent, headers }, res => {
      let b = ''; res.on('data', d => b += d);
      res.on('end', () => { let j = null; try { j = b ? JSON.parse(b) : null; } catch {} resolve({ status: res.statusCode, json: j }); });
    });
    r.on('error', reject); if (data) r.write(data); r.end();
  });
}
async function waitUp() { for (let i = 0; i < 100; i++) { if (existsSync(CRT)) { try { return readFileSync(CRT); } catch {} } if (child.exitCode != null) die(`server exited early (${child.exitCode})`); await sleep(150); } die('no cert'); }
async function waitAnswering() { for (let i = 0; i < 60; i++) { try { const r = await req('GET', '/api/me'); if (r.status) return; } catch {} await sleep(150); } }
const login = () => req('POST', '/api/auth/login', { body: { username: 'admin', password: PASS } });

// ---- boot with MFA ENFORCED (no MAGI_MFA override) ----
child = spawn(process.execPath, ['server.js'], {
  env: { ...process.env, MAGI_SERVER: '1', MAGI_HOST: '127.0.0.1', MAGI_PORT: String(PORT), MAGI_DB: join(DIR, 'magi.db'), MAGI_DATA_DIR: DIR, MAGI_PASS: PASS, MAGI_USER: 'admin' },
  stdio: ['ignore', 'ignore', 'pipe'],
});
child.stderr.on('data', d => { stderr += d; });
const cert = await waitUp();
agent = new https.Agent({ ca: cert, checkServerIdentity: () => undefined, keepAlive: false });
await waitAnswering();

// The web UI logs in with password (+ OTP) in ONE call and gets a device-less JWT — no cookie.
const loginOtp = (otp) => req('POST', '/api/auth/login', { body: { username: 'admin', password: PASS, otp } });

// 1) password alone → a setup challenge, and NO token (can't reach the app yet)
const l1 = await login();
check('first login returns an MFA setup challenge', l1.status === 200 && l1.json?.mfa === 'setup' && typeof l1.json.secret === 'string' && l1.json.otpauth_uri?.startsWith('otpauth://'));
check('no token is issued before the second factor', !l1.json?.token);
const secret = l1.json.secret;

// 2) enrol: a wrong code is refused, the right code completes setup → a token + recovery codes
const badEnable = await loginOtp('000000');
check('setup rejects a wrong code', badEnable.status === 401 && !badEnable.json?.token);
const enable = await loginOtp(totp.currentCode(secret));
check('setup completes with the right code → a token + recovery codes', enable.status === 200 && typeof enable.json?.token === 'string' && Array.isArray(enable.json?.recovery_codes) && enable.json.recovery_codes.length === 10);
const recovery = enable.json.recovery_codes;
const meOk = await req('GET', '/api/me', { token: enable.json.token });
check('the token authenticates after enrolment', meOk.status === 200 && meOk.json?.username === 'admin');

// 3) re-login now requires the code (no more setup) and mints a token only WITH it
const l2 = await login();
check('a returning user is asked for a code, not setup', l2.status === 401 && l2.json?.mfa === 'required' && !l2.json?.token);
const wrong = await loginOtp('123456');
check('a wrong TOTP code is refused', wrong.status === 401 && !wrong.json?.token);
const right = await loginOtp(totp.currentCode(secret));
check('the correct TOTP code mints a token', right.status === 200 && typeof right.json?.token === 'string' && (await req('GET', '/api/me', { token: right.json.token })).json?.username === 'admin');

// 4) recovery code works once
const rc1 = await loginOtp(recovery[0]);
check('a recovery code completes the second factor', rc1.status === 200 && !!rc1.json?.token && rc1.json?.recovery_used === true && rc1.json?.recovery_left === 9);
const rcReuse = await loginOtp(recovery[0]);
check('a used recovery code cannot be reused', rcReuse.status === 401 && !rcReuse.json?.token);

// 4b) the CLIENT token endpoint (/api/auth/token) is MFA-gated too: a linked device mints a JWT
// only after the second factor — first a setup challenge, then a required code on later logins.
// (This is the path an app uses when it logs in to a server; issue: "not asked mfa" must not happen.)
const cAdmin = (await loginOtp(totp.currentCode(secret))).json.token;
const codeT = (await req('POST', '/api/admin/enroll-codes', { token: cAdmin, body: { note: 'tok' } })).json.code;
const devT = 'aa11bb22-cc33-4d44-8e55-ff66aa77bb88';
const enT = await req('POST', '/api/enroll', { body: { code: codeT, username: 'dana', display_name: 'Dana', device_id: devT, password: 'dana-secret-8' } });
await req('POST', `/api/admin/requests/${enT.json.request_id}/approve`, { token: cAdmin, body: { role: 'worker' } });

const tok0 = await req('POST', '/api/auth/token', { body: { username: 'dana', password: 'dana-secret-8', device_id: devT } });
check('a client login with no code is met with an MFA setup challenge (no token)', !tok0.json?.token && tok0.json?.mfa === 'setup' && typeof tok0.json?.secret === 'string');
const tSecret = tok0.json.secret;
const tokBad = await req('POST', '/api/auth/token', { body: { username: 'dana', password: 'dana-secret-8', device_id: devT, otp: '000000' } });
check('a wrong setup code mints no client token', tokBad.status === 401 && !tokBad.json?.token);
const tokOk = await req('POST', '/api/auth/token', { body: { username: 'dana', password: 'dana-secret-8', device_id: devT, otp: totp.currentCode(tSecret) } });
check('the right setup code mints a client JWT + recovery codes', tokOk.status === 200 && typeof tokOk.json?.token === 'string' && Array.isArray(tokOk.json?.recovery_codes));
const tokNoOtp = await req('POST', '/api/auth/token', { body: { username: 'dana', password: 'dana-secret-8', device_id: devT } });
check('once enrolled, a client login without a code is refused', tokNoOtp.status === 401 && tokNoOtp.json?.mfa === 'required' && !tokNoOtp.json?.token);
const tokReq = await req('POST', '/api/auth/token', { body: { username: 'dana', password: 'dana-secret-8', device_id: devT, otp: totp.currentCode(tSecret) } });
check('a returning client mints a JWT with its code', tokReq.status === 200 && typeof tokReq.json?.token === 'string');

// 5) admin reset clears MFA → the account is sent back into setup at next sign-in
const cAuthed = (await loginOtp(totp.currentCode(secret))).json.token;
const adminId = (await req('GET', '/api/admin/users', { token: cAuthed })).json.find(u => u.username === 'admin').id;
const reset = await req('POST', `/api/admin/users/${adminId}/reset-mfa`, { token: cAuthed });
check('admin can reset a user’s MFA', reset.status === 200);
const l5 = await login();
check('after reset, the account re-enrols', l5.json?.mfa === 'setup');

// 6) totp module sanity
check('verifyTOTP accepts a current code and rejects a bad one',
  totp.verifyTOTP(secret, totp.currentCode(secret)) === true && totp.verifyTOTP(secret, '000000') === false);

const failed = checks.filter(([, ok]) => !ok);
console.log(`\nmfa-smoke: ${checks.length - failed.length}/${checks.length} checks passed`);
if (failed.length) { console.error('FAILED:', failed.map(([n]) => n).join(', ')); cleanup(); process.exit(1); }
console.log('  ✓ TOTP enrolment, code + recovery sign-in, reuse refusal, admin reset');
cleanup();
