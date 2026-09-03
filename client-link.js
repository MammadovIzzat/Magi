// Client side of the team server: this local Magi becomes a *client* of a remote Magi
// server. It holds the link credentials (encrypted at rest), enrolls with a one-time code,
// pins the server's certificate by fingerprint, and makes authenticated requests.
//
// Design notes:
//   - Trust on first connect is anchored by the fingerprint the admin hands over out of
//     band: we open TLS, read the server's actual certificate, and refuse unless its
//     fingerprint matches. Only then do we pin that certificate for every later request.
//     A man-in-the-middle with a different cert cannot match the pasted fingerprint.
//   - The bearer token is the one real secret. It is encrypted at rest with the OS keychain
//     (Electron safeStorage) when the desktop app injects an encryptor; otherwise it is
//     written to a 0600 file and flagged as unencrypted so the UI can warn.
//   - The device id is a UUID generated here and kept; the server binds the token to it.
import { readFileSync, writeFileSync, existsSync, rmSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import https from 'node:https';
import tls from 'node:tls';
import { DATA_DIR, db, hashPassword, verifyPassword } from './db.js';
import * as sync from './sync.js';
import * as jwt from './jwt.js';
import { exportProject } from './projects-io.js';
import { importProject } from './projects-io.js';

// The password is held in memory only during connect→approval, so the background poll can log in
// for a token the moment an admin approves — without re-prompting and without persisting it. Lost
// on restart (the user just logs in), never written to disk.
let pendingSecret = null;

const LINK_FILE = join(DATA_DIR, 'link.json');
const TIMEOUT = 8000;

// Optional at-rest encryptor for the token, provided by the desktop main process (Electron
// safeStorage → OS keychain). It arrives via a global so it reaches this module whether or
// not the server is bundled. Without it, the token falls back to a 0600 file and the UI warns.
//   { available: boolean, encrypt(str)->base64, decrypt(base64)->str }
let encryptor = globalThis.__MAGI_ENCRYPTOR || null;
export function setEncryptor(e) { encryptor = e || null; }

const normFp = (s) => String(s || '').toUpperCase().replace(/[^0-9A-F]/g, '');
const derToPem = (der) => '-----BEGIN CERTIFICATE-----\n'
  + der.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----\n';

function saveLink(link) {
  const out = { ...link };
  if (link.token != null) {
    if (encryptor?.available) out.token = { enc: 'safeStorage', data: encryptor.encrypt(link.token) };
    else out.token = { enc: 'none', data: link.token };
  }
  writeFileSync(LINK_FILE, JSON.stringify(out, null, 2));
  try { chmodSync(LINK_FILE, 0o600); } catch { /* best effort on non-POSIX */ }
}

/** Load the stored link, decrypting the token if we can. Null when not linked. */
export function loadLink() {
  if (!existsSync(LINK_FILE)) return null;
  let raw;
  try { raw = JSON.parse(readFileSync(LINK_FILE, 'utf8')); } catch { return null; }
  if (raw.token && typeof raw.token === 'object') {
    if (raw.token.enc === 'safeStorage') {
      if (encryptor?.available) { try { raw.token = encryptor.decrypt(raw.token.data); } catch { raw.token = null; raw._locked = true; } }
      else { raw.token = null; raw._locked = true; } // encrypted by a keychain we can't reach here
    } else {
      raw.token = raw.token.data;
      raw._plaintext = true; // stored without a keychain — the UI warns
    }
  }
  return raw;
}

/**
 * Open TLS to the server and return its certificate. If a fingerprint is supplied it is
 * verified (pinning); otherwise the cert is trusted on first connect (TOFU) and then pinned
 * for every later request. Either way the connection is encrypted and pinned after this.
 */
export function fetchCert(serverUrl, expectedFingerprint) {
  const u = new URL(serverUrl);
  const port = Number(u.port) || 8443;
  // SNI may not be an IP literal; send it only for real hostnames.
  const opts = { host: u.hostname, port, rejectUnauthorized: false };
  if (!isIP(u.hostname)) opts.servername = u.hostname;
  return new Promise((resolve, reject) => {
    const socket = tls.connect(opts, () => {
      const cert = socket.getPeerCertificate(true);
      socket.end();
      if (!cert || !cert.raw) return reject(new Error('server presented no certificate'));
      if (expectedFingerprint && normFp(cert.fingerprint256) !== normFp(expectedFingerprint))
        return reject(new Error('certificate fingerprint does not match — refusing to connect (possible man-in-the-middle)'));
      resolve({ pem: derToPem(cert.raw), fingerprint: cert.fingerprint256 });
    });
    socket.on('error', reject);
    socket.setTimeout(TIMEOUT, () => socket.destroy(new Error('connection timed out')));
  });
}
export const fetchAndPinCert = fetchCert; // back-compat alias

function agentFor(link) {
  // Pin: trust exactly the server's own certificate (fetched/verified on connect).
  return new https.Agent({ ca: link.cert_pem, checkServerIdentity: () => undefined, keepAlive: false });
}

/**
 * One request to the linked server over the pinned cert. The bearer token + device header are
 * sent only when we have a token — so the pre-token handshake calls (enroll, poll) work too.
 * Rejects only on transport failure.
 */
export function remoteFetch(path, { method = 'GET', body, headers = {}, link } = {}) {
  link = link || loadLink();
  if (!link || !link.server_url || !link.cert_pem) return Promise.reject(new Error('not linked'));
  const u = new URL(link.server_url);
  const data = body != null ? (typeof body === 'string' ? body : JSON.stringify(body)) : null;
  return new Promise((resolve, reject) => {
    const r = https.request({
      host: u.hostname, port: Number(u.port) || 8443, path, method, agent: agentFor(link),
      headers: {
        'content-type': 'application/json',
        ...(link.token ? { authorization: `Bearer ${link.token}`, 'x-magi-device': link.device_id } : {}),
        ...headers, ...(data ? { 'content-length': Buffer.byteLength(data) } : {}),
      },
    }, res => {
      let b = ''; res.on('data', d => b += d);
      res.on('end', () => { let j = null; try { j = b ? JSON.parse(b) : null; } catch {} resolve({ status: res.statusCode, json: j, raw: b }); });
    });
    r.on('error', reject);
    r.setTimeout(TIMEOUT, () => r.destroy(new Error('request timed out')));
    if (data) r.write(data);
    r.end();
  });
}

/**
 * Ask a server to join it. The certificate is pinned (verified against `fingerprint` if one
 * is given, otherwise trusted on first connect), the one-time code + name are submitted, and
 * the server records a PENDING request an admin must approve. Returns { ok, pending, link } and
 * starts a background poll that finalizes the link once approved. Local data is only set aside
 * on approval, not now — so a request that is never approved changes nothing.
 */
export async function connect({ server_url, fingerprint, code, username, display_name, password }) {
  if (!server_url || !code || !username || !display_name || !password)
    return { ok: false, error: 'server address, code, username, display name and password are all required' };
  if (String(password).length < 8) return { ok: false, error: 'password must be at least 8 characters' };
  linkGen++; // invalidate any in-flight sync from a previous link state
  stopSyncLoop();
  let cert;
  try { cert = await fetchCert(server_url, fingerprint); }
  catch (e) { return { ok: false, error: e.message }; }

  const device_id = randomUUID();
  const pending = {
    server_url, fingerprint: cert.fingerprint, cert_pem: cert.pem, device_id,
    req_username: username, username, display_name, pending: true,
  };
  let res;
  try { res = await remoteFetch('/api/enroll', { method: 'POST', link: pending, body: { code, username, display_name, device_id, password } }); }
  catch (e) { return { ok: false, error: `could not reach the server: ${e.message}` }; }
  if (res.status !== 202 || res.json?.status !== 'pending')
    return { ok: false, error: res.json?.error || `could not request access (${res.status})` };

  pending.request_id = res.json.request_id;
  pending.requested_at = new Date().toISOString();
  saveLink(pending); // no token yet — the poll logs in for one once an admin approves
  pendingSecret = { username, password };
  startApprovalPoll();
  return { ok: true, pending: true, link: publicLink(pending) };
}

// Ask the server for a fresh access token with a password (+ optional OTP). Returns the raw
// response so callers can handle an MFA setup/required step.
async function requestToken(link, password, otp) {
  try {
    return await remoteFetch('/api/auth/token', { method: 'POST', link,
      body: { username: link.username || link.req_username, password, device_id: link.device_id, otp } });
  } catch (e) { return { status: 0, json: { error: e.message } }; }
}

// Persist a freshly-minted token and go fully linked. The password is used only to compute an
// offline-login verifier and is then discarded — the JWT and the verifier are what we keep.
function storeToken(link, password, loginJson) {
  const claims = jwt.decodeUnsafe(loginJson.token) || {};
  const full = {
    server_url: link.server_url, fingerprint: link.fingerprint, cert_pem: link.cert_pem,
    device_id: link.device_id, username: link.username || link.req_username, display_name: link.display_name,
    token: loginJson.token, jwt_exp: loginJson.exp || claims.exp || null, role: loginJson.role || claims.role || null,
    pass_verifier: hashPassword(String(password)),
    connected_at: link.connected_at || new Date().toISOString(), stash_id: link.stash_id ?? null,
    needs_reauth: 0,
  };
  linkGen++;
  stopApprovalPoll();
  saveLink(full);
  pendingSecret = null;
  startSyncLoop();
  return { ok: true, link: publicLink(full), recovery_codes: loginJson.recovery_codes };
}

// Log in for a token, storing it on success. Surfaces { mfa } when the server wants a second
// factor (first-time setup or a required code) so the UI can collect it and call again.
async function attemptLogin(link, password, otp) {
  const r = await requestToken(link, password, otp);
  if (r.status === 200 && r.json?.token) return storeToken(link, password, r.json);
  if (r.json?.mfa) return { ok: false, mfa: r.json.mfa, secret: r.json.secret, otpauth_uri: r.json.otpauth_uri };
  return { ok: false, error: r.json?.error || `login failed (${r.status})` };
}

// The UI calls this to finish a just-approved link (auto-login couldn't, e.g. it needs an OTP)
// or to re-authenticate after the token expired / was revoked (epoch bump). On success the
// mirror is untouched — we're already linked and only refreshing the token.
export async function login({ password, otp } = {}) {
  const link = loadLink();
  if (!link) return { ok: false, error: 'not linked' };
  if (!password) return { ok: false, error: 'a password is required' };
  return attemptLogin(link, password, otp);
}

// One poll of a pending request. On approval the device is registered server-side; we then log in
// (auto, using the in-memory password) for a token. rejected -> clears the pending link.
export async function pollApproval() {
  const link = loadLink();
  if (!link || !link.pending || !link.request_id) return { pending: false };
  let r;
  try { r = await remoteFetch(`/api/enroll/poll?request_id=${encodeURIComponent(link.request_id)}&device_id=${encodeURIComponent(link.device_id)}`, { link }); }
  catch { return { pending: true, waiting: true }; } // server unreachable — keep waiting
  if (r.status === 404) { stopApprovalPoll(); try { rmSync(LINK_FILE, { force: true }); } catch {} return { pending: false, gone: true }; }
  const st = r.json?.status;
  if (st === 'rejected') { stopApprovalPoll(); try { rmSync(LINK_FILE, { force: true }); } catch {} return { pending: false, rejected: true }; }
  if (st !== 'approved') return { pending: true };

  // Approved. Set local data aside once, move out of 'pending' into 'awaiting login', then try to
  // log in for a token (auto, using the in-memory password). If the server wants an OTP, or we
  // have no cached password, the link sits in needs_login and the UI collects credentials.
  if (link.stash_id === undefined) {
    try { link.stash_id = stashLocalProjects() ?? null; } catch (e) { return { pending: true, error: `could not set local data aside: ${e.message}` }; }
    sync.setWatermarks(db, { pull: '', push: '' });
  }
  link.pending = false; link.needs_login = true; saveLink(link);
  stopApprovalPoll();
  if (!pendingSecret?.password) return { approved: true, needs_login: true };
  const res = await attemptLogin(loadLink(), pendingSecret.password);
  if (res.ok) return { approved: true, linked: true };
  return { approved: true, ...res }; // mfa or error → UI completes via login()
}

let approvalTimer = null;
export function startApprovalPoll(intervalMs = 3000) {
  stopApprovalPoll();
  if (!loadLink()?.pending) return;
  const tick = () => { pollApproval().catch(() => {}); };
  tick();
  approvalTimer = setInterval(tick, intervalMs);
  if (approvalTimer.unref) approvalTimer.unref();
}
export function stopApprovalPoll() { if (approvalTimer) { clearInterval(approvalTimer); approvalTimer = null; } }

// ---- replication ----
const payloadMax = (p) => {
  let m = '';
  for (const r of p.rows || []) if (r.hlc > m) m = r.hlc;
  for (const t of p.tombstones || []) if (t.hlc > m) m = t.hlc;
  return m;
};

let syncing = false;
let linkGen = 0; // bumped by connect()/disconnect() so an in-flight sync can't write after the link changes

// The token expired or was revoked (epoch bump). Pause syncing and flag it so the UI prompts for
// a fresh login; local work continues offline meanwhile.
function markNeedsReauth() {
  stopSyncLoop();
  const link = loadLink();
  if (link && !link.pending && !link.needs_reauth) { link.needs_reauth = 1; saveLink(link); }
}

/** Offline identity check against the cached verifier — lets a linked user open the app while the
 *  server is unreachable. Grants no token; sync stays paused until an online login refreshes it. */
export function offlineLogin(password) {
  const link = loadLink();
  if (!link || link.pending) return { ok: false, error: 'not linked' };
  if (!link.pass_verifier) return { ok: false, error: 'no cached credential — log in once while online' };
  if (!verifyPassword(String(password || ''), link.pass_verifier)) return { ok: false, error: 'wrong password' };
  return { ok: true, link: publicLink(link) };
}

/** One push+pull cycle against the linked server. Safe to call often; self-serialises. */
export async function syncOnce() {
  const link = loadLink();
  if (!link?.token) return { ok: false, error: 'not linked' };
  if (syncing) return { ok: false, error: 'busy' };
  syncing = true;
  const gen = linkGen;
  // The loop runs in the same process that serves /api/link/disconnect, so a disconnect can
  // land while we are parked on an await. Never touch the db or the link file if the link
  // changed underneath us — otherwise we'd resurrect a mirror the user just cleared.
  const stale = () => gen !== linkGen || !loadLink()?.token;
  try {
    const wm = sync.watermarks(db);
    // push our own changes (rows this node authored, newer than what we've pushed)
    const local = sync.collectChanges(db, wm.push, { onlyLocal: true });
    if (local.rows.length || local.tombstones.length) {
      const r = await remoteFetch('/api/sync/push', { method: 'POST', link, body: local });
      if (stale()) return { ok: false, error: 'link changed' };
      if (r.status === 401) { markNeedsReauth(); return { ok: false, needs_reauth: true }; }
      if (r.status !== 200) return { ok: false, error: r.json?.error || `push failed (${r.status})` };
      // Advance the push watermark — but never past a row the server had to defer (parent not
      // yet present), or that row would never be re-sent. Stop just below the earliest deferred.
      const deferred = Array.isArray(r.json?.deferred) ? r.json.deferred : [];
      let pm = payloadMax(local);
      if (deferred.length) {
        const minDef = deferred.map(d => d.hlc).sort()[0];
        const below = [...local.rows, ...local.tombstones].map(x => x.hlc).filter(h => h < minDef).sort();
        pm = below.length ? below[below.length - 1] : wm.push;
      }
      if (pm && pm > wm.push) sync.setWatermarks(db, { push: pm });
    }
    // pull everything newer than our pull watermark, merge locally
    const pr = await remoteFetch('/api/sync/pull?since=' + encodeURIComponent(wm.pull), { link });
    if (stale()) return { ok: false, error: 'link changed' };
    if (pr.status === 401) { markNeedsReauth(); return { ok: false, needs_reauth: true }; }
    if (pr.status !== 200) return { ok: false, error: pr.json?.error || `pull failed (${pr.status})` };
    const merged = sync.applyChanges(db, pr.json);
    const pm = payloadMax(pr.json);
    if (pm && pm > wm.pull) sync.setWatermarks(db, { pull: pm });
    const now = new Date().toISOString();
    link.last_sync = now; link.last_ok = now; saveLink(link);
    return { ok: true, pushed: local.rows.length + local.tombstones.length, applied: merged.applied, deleted: merged.deleted, deferred: (merged.deferred || []).length };
  } catch (e) {
    return { ok: false, error: e.message };
  } finally {
    syncing = false;
  }
}

let loopTimer = null;
export function startSyncLoop(intervalMs = 5000) {
  stopSyncLoop();
  const link = loadLink();
  if (!link?.token || link.needs_reauth) return; // no token, or waiting for the user to re-authenticate
  const tick = () => { syncOnce().catch(() => {}); };
  tick();
  loopTimer = setInterval(tick, intervalMs);
  if (loopTimer.unref) loopTimer.unref(); // never keep the process alive just to sync
}
export function stopSyncLoop() { if (loopTimer) { clearInterval(loopTimer); loopTimer = null; } }

// ---- non-destructive stash of local (personal) engagements ----
// Connecting to a server sets your local projects aside; disconnecting restores them. The
// stash lives IN the database as a blob so the export and the delete are ONE atomic
// transaction — a single durability domain, so a crash can never lose the projects or leave
// the stash and the deletion out of step. The deletes are muted (no tombstones), so the
// removal never reaches the server; the blob is never synced (not a SPEC table).
// Returns the stash row id, or null if there was nothing to stash.
function stashLocalProjects() {
  const ids = db.prepare(`SELECT id FROM projects`).all().map(r => r.id);
  if (!ids.length) return null;
  const blob = JSON.stringify({ projects: ids.map(id => exportProject(id, new Date().toISOString())).filter(Boolean) });
  db.prepare('BEGIN IMMEDIATE').run();
  db.prepare(`INSERT INTO _sync_mute (x) VALUES (1)`).run();
  try {
    const sid = db.prepare(`INSERT INTO stash_blobs (data) VALUES (?)`).run(blob).lastInsertRowid;
    for (const id of ids) db.prepare(`DELETE FROM projects WHERE id=?`).run(id);
    db.prepare(`DELETE FROM _sync_mute`).run();
    db.prepare('COMMIT').run();
    return Number(sid); // plain number — it is JSON-stringified into link.json
  } catch (e) {
    db.prepare(`DELETE FROM _sync_mute`).run();
    db.prepare('ROLLBACK').run();
    throw e; // projects untouched — the whole txn rolled back
  }
}
// Re-import a stashed blob. On full success the blob is dropped; if some bundles fail to
// import, the blob is trimmed to just those and marked failed=1 so it is preserved for
// recovery but never auto-restored again (which would duplicate the ones that succeeded).
function restoreStash(sid) {
  if (sid == null) return 0;
  const row = db.prepare(`SELECT data FROM stash_blobs WHERE id=?`).get(sid);
  if (!row) return 0;
  let data; try { data = JSON.parse(row.data); } catch { db.prepare(`UPDATE stash_blobs SET failed=1 WHERE id=?`).run(sid); return 0; }
  const failed = [];
  let n = 0;
  sync.mutedRun(db, () => { for (const b of data.projects || []) { try { importProject(b); n++; } catch { failed.push(b); } } });
  if (failed.length) db.prepare(`UPDATE stash_blobs SET data=?, failed=1 WHERE id=?`).run(JSON.stringify({ projects: failed }), sid);
  else db.prepare(`DELETE FROM stash_blobs WHERE id=?`).run(sid);
  return n;
}
// On boot, if NOT linked, restore any stash blob left by a connect whose enrolment never
// finished (crash after the atomic stash+delete but before the link was saved) — so the local
// engagements are never orphaned. A live link owns its stash and is left untouched. failed=1
// blobs are preserved but not re-imported.
export function reconcileStash() {
  if (loadLink()) return 0; // linked: the stash is intentional
  let restored = 0;
  try {
    for (const r of db.prepare(`SELECT id FROM stash_blobs WHERE failed=0`).all()) restored += restoreStash(r.id);
  } catch { /* best effort */ }
  return restored;
}
// Drop the server-mirrored copy on disconnect, without emitting tombstones (the server
// keeps its data — we are only clearing our local cache of it).
function clearMirror() {
  sync.mutedRun(db, () => { db.prepare(`DELETE FROM projects`).run(); });
}

/** Ping the server; returns { online, error? } and refreshes last_ok. */
export async function heartbeat() {
  const link = loadLink();
  if (!link || !link.token) return { online: false, error: 'not linked' };
  const gen = linkGen;
  try {
    const r = await remoteFetch('/api/me', { link });
    if (gen !== linkGen || !loadLink()?.token) return { online: false, error: 'link changed' };
    const online = r.status === 200;
    if (online) { link.last_ok = new Date().toISOString(); saveLink(link); }
    return { online, status: r.status, who: r.json || null, revoked: r.status === 401 };
  } catch (e) { return { online: false, error: e.message }; }
}

/** Unlink (or cancel a pending request): stop syncing/polling, restore the stashed data. */
export function disconnect() {
  const link = loadLink();
  linkGen++;        // invalidate any in-flight syncOnce/heartbeat so it can't write after us
  stopSyncLoop();
  stopApprovalPoll();
  if (link && !link.pending) { // only a fully-linked client cleared a mirror and holds a stash
    try { clearMirror(); } catch {}                 // drop our cached copy of the server's data
    try { restoreStash(link.stash_id); } catch {} // bring personal engagements back
    try { sync.setWatermarks(db, { pull: '', push: '' }); } catch {}
  }
  try { rmSync(LINK_FILE, { force: true }); } catch {}
  return { ok: true, was: link ? publicLink(link) : null };
}

function publicLink(link) {
  if (!link) return null;
  return {
    server_url: link.server_url, fingerprint: link.fingerprint, device_id: link.device_id,
    username: link.username || link.req_username, display_name: link.display_name,
    role: link.role || (link.token ? jwt.decodeUnsafe(link.token)?.role : null) || null,
    pending: !!link.pending, request_id: link.request_id || null,
    needs_login: !!(link.needs_login && !link.token), needs_reauth: !!link.needs_reauth, jwt_exp: link.jwt_exp || null,
    connected_at: link.connected_at || null, last_ok: link.last_ok || null, last_sync: link.last_sync || null,
    // How the token is (or will be) stored: keyed off the actual encryptor, so this is right
    // both for a freshly-connected link and one just loaded from disk.
    token_at_rest: link._locked ? 'locked' : (encryptor?.available ? 'encrypted' : 'unencrypted'),
  };
}

/** Non-secret link status for the UI: linked | pending | (neither). */
export function status() {
  const link = loadLink();
  if (!link) return { linked: false };
  if (link.pending) return { linked: false, pending: true, link: publicLink(link) };
  if (link.needs_login && !link.token) return { linked: false, needs_login: true, link: publicLink(link) };
  return { linked: true, link: publicLink(link) };
}

export const LINK_PATH = LINK_FILE;
