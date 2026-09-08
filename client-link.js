// Client side of the team server: this local Magi becomes a *client* of a remote Magi
// server. It holds the link credentials (encrypted at rest), enrolls with a one-time code,
// pins the server's certificate by fingerprint, and makes authenticated requests.
//
// Design notes:
//   - Trust on first connect is anchored by the fingerprint the admin hands over out of
//     band: we open TLS, read the server's actual certificate, and refuse unless its
//     fingerprint matches. Only then do we pin that certificate for every later request.
//     A man-in-the-middle with a different cert cannot match the pasted fingerprint.
//   - The bearer token (JWT) is the one real secret. It lives as one row inside the local
//     database, so an encrypted workspace protects it with the same passphrase; when the
//     workspace is NOT encrypted the UI warns that it is stored in the clear. Only the minimum
//     is kept — server URL + pinned cert, device id, username, the JWT, and an offline-login
//     verifier. The role and display name are NOT stored: the role is read from the JWT, the
//     display name is fetched from the server.
//   - The device id is a UUID generated here and kept; the server binds the token to it.
import { readFileSync, existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import https from 'node:https';
import tls from 'node:tls';
import { DATA_DIR, db, hashPassword, verifyPassword, isEncrypted } from './db.js';
import * as sync from './sync.js';
import * as jwt from './jwt.js';
import { exportProject } from './projects-io.js';
import { importProject } from './projects-io.js';

const LINK_FILE = join(DATA_DIR, 'link.json');
const TIMEOUT = 8000;

// A legacy at-rest encryptor for the token (Electron safeStorage → OS keychain). Still accepted
// so an OLD link.json written by a previous version can be decrypted once and migrated into the
// database. New links are NOT encrypted here — they live in the (optionally encrypted) DB instead.
//   { available: boolean, encrypt(str)->base64, decrypt(base64)->str }
let encryptor = globalThis.__MAGI_ENCRYPTOR || null;
export function setEncryptor(e) { encryptor = e || null; }

const normFp = (s) => String(s || '').toUpperCase().replace(/[^0-9A-F]/g, '');
const derToPem = (der) => '-----BEGIN CERTIFICATE-----\n'
  + der.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----\n';

// The link is one JSON row in the database (client_link, id=1). Role, display name and token
// expiry are DERIVED (from the JWT / the server) and never stored — see publicLink().
function saveLink(link) {
  const { role, display_name, jwt_exp, _locked, _plaintext, ...keep } = link;
  db.prepare(`INSERT INTO client_link (id, data) VALUES (1, ?)
    ON CONFLICT(id) DO UPDATE SET data=excluded.data`).run(JSON.stringify(keep));
}
function deleteLink() { try { db.prepare(`DELETE FROM client_link`).run(); } catch { /* best effort */ } }

/** Load the stored link. Null when not linked. Migrates a legacy link.json on first read. */
export function loadLink() {
  migrateLegacyLink();
  const row = db.prepare(`SELECT data FROM client_link WHERE id=1`).get();
  if (!row) return null;
  let link; try { link = JSON.parse(row.data); } catch { return null; }
  // v0.9.0 changed the enrolment model: a device now holds its OWN token (link.device_token),
  // distinct from an operator's JWT (link.token). A link written by an older version has an
  // operator/user token but never had a device token, and that old token can't authenticate
  // against the new server. Flag it once for a guided reconnect (which reuses the pinned server +
  // the stashed personal engagements, so nothing is lost) and drop the unusable token so nothing
  // keeps trying to sync with it.
  if (link.token && !link.device_token && !link.pending && !link.needs_reconnect) {
    delete link.token;
    link.needs_reconnect = 1;
    saveLink(link);
  }
  return link;
}

// One-time import of a link.json written by an older version: decrypt its token (via the keychain
// if that is how it was stored), drop the fields we no longer persist, write it into the DB, and
// delete the file. A token we cannot decrypt (keychain gone) is dropped so the client re-authenticates.
let legacyChecked = false;
function migrateLegacyLink() {
  if (legacyChecked) return;
  legacyChecked = true;
  try {
    if (db.prepare(`SELECT 1 FROM client_link WHERE id=1`).get()) return; // already have a DB link
    if (!existsSync(LINK_FILE)) return;
    const raw = JSON.parse(readFileSync(LINK_FILE, 'utf8'));
    if (raw.token && typeof raw.token === 'object') {
      if (raw.token.enc === 'safeStorage') { try { raw.token = encryptor?.available ? encryptor.decrypt(raw.token.data) : null; } catch { raw.token = null; } }
      else raw.token = raw.token.data;
    }
    const { role, display_name, jwt_exp, _locked, _plaintext, ...keep } = raw;
    if (keep.token == null && !keep.pending) keep.needs_reauth = 1; // token lost with the keychain → re-auth
    db.prepare(`INSERT OR REPLACE INTO client_link (id, data) VALUES (1, ?)`).run(JSON.stringify(keep));
    rmSync(LINK_FILE, { force: true });
  } catch { /* corrupt/unreadable file → nothing to migrate */ }
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
export async function connect({ server_url, fingerprint, code, device_name }) {
  if (!server_url || !code) return { ok: false, error: 'the server address and a one-time code are required' };
  linkGen++; // invalidate any in-flight sync from a previous link state
  stopSyncLoop();
  let cert;
  try { cert = await fetchCert(server_url, fingerprint); }
  catch (e) { return { ok: false, error: e.message }; }

  const device_id = randomUUID();
  const name = String(device_name || 'device').trim().slice(0, 60) || 'device';
  const pending = { server_url, fingerprint: cert.fingerprint, cert_pem: cert.pem, device_id, device_name: name, pending: true };
  // Reconnecting an already-linked device (e.g. after a v0.9.0 upgrade left it needs_reconnect):
  // carry the existing stash forward so approval does NOT re-stash — the local mirror and the
  // personal engagements set aside on the first connect stay exactly as they are, and sync just
  // resumes from where it left off. A fresh connect (no prior link) has no stash to carry.
  try { const prev = loadLink(); if (prev && !prev.pending && prev.stash_id !== undefined) pending.stash_id = prev.stash_id; } catch { /* fresh connect */ }
  let res;
  try { res = await remoteFetch('/api/enroll', { method: 'POST', link: pending, body: { code, device_id, device_name: name } }); }
  catch (e) { return { ok: false, error: `could not reach the server: ${e.message}` }; }
  if (res.status !== 202 || res.json?.status !== 'pending')
    return { ok: false, error: res.json?.error || `could not request access (${res.status})` };

  pending.request_id = res.json.request_id;
  pending.requested_at = new Date().toISOString();
  saveLink(pending); // no device token yet — the poll picks it up once an admin accepts
  startApprovalPoll();
  return { ok: true, pending: true, link: publicLink(pending) };
}

// Ask the server for an operator's access token. The DEVICE token (link.device_token) authenticates
// the endpoint; the operator's username/password (+ OTP) authenticate the person. Returns the raw
// response so callers can handle an MFA setup/required step.
async function requestToken(link, username, password, otp) {
  try {
    // Bearer = the device token (not link.token, which is the operator's JWT and may not exist yet).
    return await remoteFetch('/api/auth/token', { method: 'POST', link: { ...link, token: link.device_token },
      body: { username, password, otp } });
  } catch (e) { return { status: 0, json: { error: e.message } }; }
}

// Persist a freshly-minted operator token. The password is used only to compute an offline-login
// verifier (kept per operator, so any of them can open the app offline) and is then discarded.
function storeUserToken(username, password, loginJson) {
  const link = loadLink(); if (!link) return { ok: false, error: 'not connected' };
  link.token = loginJson.token;                  // operator JWT (carries role, epoch, exp, device_id)
  link.username = username;                       // the operator currently signed in
  link.verifiers = { ...(link.verifiers || {}), [username]: hashPassword(String(password)) };
  link.needs_login = 0; link.needs_reauth = 0;
  linkGen++;
  saveLink(link);
  // Kill any leftover LOCAL-account sessions (e.g. admin/admin) so only the server operator opens this.
  try { db.prepare(`DELETE FROM sessions WHERE user_id IS NOT NULL`).run(); } catch { /* best effort */ }
  startSyncLoop();
  return { ok: true, link: publicLink(loadLink()), recovery_codes: loginJson.recovery_codes };
}

// Log an operator in for a token, storing it on success. Surfaces { mfa } when the server wants a
// second factor (first-time setup or a required code) so the UI can collect it and call again.
async function attemptLogin(username, password, otp) {
  const link = loadLink();
  if (!link?.device_token) return { ok: false, error: 'this device is not connected to the server' };
  const r = await requestToken(link, username, password, otp);
  if (r.status === 200 && r.json?.token) return storeUserToken(username, password, r.json);
  if (r.json?.mfa) return { ok: false, mfa: r.json.mfa, secret: r.json.secret, otpauth_uri: r.json.otpauth_uri };
  return { ok: false, error: r.json?.error || `login failed (${r.status})` };
}

// The UI calls this to sign an operator in on a connected device, or to re-authenticate after a
// token expired / was revoked. On success the mirror is untouched — the device is connected and we
// only mint the operator's token.
export async function login({ username, password, otp } = {}) {
  const link = loadLink();
  if (!link) return { ok: false, error: 'not connected' };
  if (!username || !password) return { ok: false, error: 'a username and password are required' };
  return attemptLogin(username, password, otp);
}

// Change the linked user's password. On a linked client the password IS the server account's, so
// the change goes to the server (authoritative). That bumps the credential epoch, killing our
// device token, so we refresh the cached offline verifier to the new password and re-authenticate
// for a fresh token. If the server wants a second factor (or is unreachable) for that refresh, the
// password is already changed — we surface needs_reauth so the normal sign-in flow completes it.
export async function changePassword(current, next) {
  const link = loadLink();
  if (!link?.token || !link.username) return { ok: false, error: 'not signed in' };
  if (!current || !next) return { ok: false, error: 'both your current and new password are required' };
  let r;
  try { r = await remoteFetch('/api/change-password', { method: 'POST', link, body: { current, next } }); }
  catch (e) { return { ok: false, error: `could not reach the server: ${e.message}` }; }
  if (r.status !== 200) return { ok: false, error: r.json?.error || `could not change password (${r.status})` };
  // The server accepted it and its epoch bump has now invalidated our operator token. Update this
  // operator's offline verifier right away so an offline open uses the new password even if the
  // re-auth below can't finish immediately.
  const l = loadLink(); if (l) { l.verifiers = { ...(l.verifiers || {}), [l.username]: hashPassword(String(next)) }; saveLink(l); }
  const relog = await attemptLogin(link.username, next);  // fresh operator token (+ re-store verifier)
  if (relog.ok) return { ok: true };
  markNeedsReauth();                                       // MFA needed or server unreachable — finish via sign-in
  return { ok: true, needs_reauth: true, mfa: relog.mfa };
}

// One poll of a pending request. On approval the device is registered server-side; we then log in
// (auto, using the in-memory password) for a token. rejected -> clears the pending link.
// Reentrancy-guarded: the background timer and a manual "Check now" must never both reach the
// one-time stash concurrently (that could double-stash and orphan the personal engagements).
let approvalBusy = false;
export async function pollApproval() {
  if (approvalBusy) return { pending: true, busy: true };
  approvalBusy = true;
  try {
  const link = loadLink();
  if (!link || !link.pending || !link.request_id) return { pending: false };
  const gen = linkGen; // a disconnect/cancel or a new connect during the await must not resurrect this link
  let r;
  try { r = await remoteFetch(`/api/enroll/poll?request_id=${encodeURIComponent(link.request_id)}&device_id=${encodeURIComponent(link.device_id)}`, { link }); }
  catch { return { pending: true, waiting: true }; } // server unreachable — keep waiting
  if (gen !== linkGen || !loadLink()?.pending) return { pending: false, stale: true };
  if (r.status === 404) { stopApprovalPoll(); deleteLink(); return { pending: false, gone: true }; }
  const st = r.json?.status;
  if (st === 'rejected') { stopApprovalPoll(); deleteLink(); return { pending: false, rejected: true }; }
  if (st !== 'approved') return { pending: true };

  // Accepted. Store the DEVICE token, set local data aside once, and move into 'awaiting login' — an
  // operator now signs in on top of the connected device (no auto-login: connect carries no account).
  if (link.stash_id === undefined) {
    try { link.stash_id = stashLocalProjects() ?? null; } catch (e) { return { pending: true, error: `could not set local data aside: ${e.message}` }; }
    sync.setWatermarks(db, { pull: '', push: '' });
    sync.setPullWatermarks(db, {});
  }
  link.device_token = r.json.token || link.device_token;   // the device credential, delivered once
  link.pending = false; link.needs_login = true; saveLink(link);
  stopApprovalPoll();
  return { approved: true, needs_login: true };
  } finally { approvalBusy = false; }
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

/** Offline identity check for an operator, against their cached verifier — lets an operator who has
 *  signed in online before open the app while the server is unreachable. Grants no token; sync stays
 *  paused until an online login refreshes it. Sets them as the current operator. */
export function offlineLogin(username, password) {
  const link = loadLink();
  if (!link || link.pending || !link.device_token) return { ok: false, error: 'not connected' };
  const v = link.verifiers?.[username];
  if (!v) return { ok: false, error: 'no cached credential — sign in once while online' };
  if (!verifyPassword(String(password || ''), v)) return { ok: false, error: 'wrong password' };
  link.username = username; link.needs_reauth = 1; saveLink(link); stopSyncLoop(); // current operator; sync paused until online
  return { ok: true, link: publicLink(loadLink()) };
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
    // Pull everything newer than our PER-NODE watermarks, merge locally. We send the whole map plus
    // our own node id (the server omits our writes — echoing them back is waste and used to poison
    // the watermark). A per-node map means one fast-clocked peer can't hide the server's (or a slow
    // peer's) later changes: each source node advances independently.
    const nd = sync.node(db);
    const wmMap = sync.pullWatermarks(db);
    const pr = await remoteFetch('/api/sync/pull', { method: 'POST', link, body: { wm: wmMap, node: nd } });
    if (stale()) return { ok: false, error: 'link changed' };
    if (pr.status === 401) { markNeedsReauth(); return { ok: false, needs_reauth: true }; }
    if (pr.status !== 200) return { ok: false, error: pr.json?.error || `pull failed (${pr.status})` };
    const merged = sync.applyChanges(db, pr.json);
    // Advance each source node's watermark to the highest hlc we received from it — but never to or
    // past a row we had to defer (parent not here yet), or that row would never be re-sent. Skip our
    // own echoes entirely (an older server may still send them; they must not move any cursor).
    const minDefByNode = {};
    for (const d of (merged.deferred || [])) { const n = sync.hlcNode(d.hlc); if (!minDefByNode[n] || d.hlc < minDefByNode[n]) minDefByNode[n] = d.hlc; }
    for (const x of [...(pr.json?.rows || []), ...(pr.json?.tombstones || [])]) {
      const n = sync.hlcNode(x.hlc);
      if (n === nd) continue;                                   // our own echo
      const cap = minDefByNode[n];
      if (cap && !(x.hlc < cap)) continue;                      // stop just below the earliest deferred
      if (x.hlc > (wmMap[n] || '')) wmMap[n] = x.hlc;
    }
    sync.setPullWatermarks(db, wmMap);
    const now = new Date().toISOString();
    link.last_sync = now; link.last_ok = now; saveLink(link);
    return { ok: true, pushed: local.rows.length + local.tombstones.length, applied: merged.applied, deleted: merged.deleted, deferred: (merged.deferred || []).length };
  } catch (e) {
    return { ok: false, error: e.message };
  } finally {
    syncing = false;
  }
}

// One-time repair for clients upgraded from a version before the exceptNode pull fix. That bug
// let a client's OWN (clock-skewed) writes advance its pull watermark into the future, after
// which every real server update sorted below the watermark and was never pulled — sync kept
// reporting "up to date" while silently receiving nothing. Resetting the pull watermark once
// makes the next pull re-read the server from scratch and rebuild a correct watermark from
// server-authored rows only (own rows are now excluded from the pull, so it can't recur). Marked
// done in the link row so it runs exactly once; local edits are preserved (the merge is LWW).
export function healPullWatermarkOnce() {
  try {
    const link = loadLink();
    if (!link || link.pending || link.wm_reset_v1) return;
    sync.setWatermarks(db, { pull: '' });
    link.wm_reset_v1 = 1;
    saveLink(link);
  } catch { /* best effort — a failed heal just means the next launch tries again */ }
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
    if (online) { remoteDisplayName = r.json?.display_name || remoteDisplayName; link.last_ok = new Date().toISOString(); saveLink(link); }
    else if (r.status === 401) markNeedsReauth(); // token expired/revoked — surface it, pause sync
    return { online, status: r.status, who: r.json || null, revoked: r.status === 401 };
  } catch (e) { return { online: false, error: e.message }; }
}

/** Unlink (or cancel a pending request): stop syncing/polling, restore the stashed data. */
export function disconnect() {
  const link = loadLink();
  linkGen++;        // invalidate any in-flight syncOnce/heartbeat so it can't write after us
  stopSyncLoop();
  stopApprovalPoll();
  remoteDisplayName = null;
  if (link && !link.pending) { // only a fully-linked client cleared a mirror and holds a stash
    try { clearMirror(); } catch {}                 // drop our cached copy of the server's data
    try { restoreStash(link.stash_id); } catch {} // bring personal engagements back
    try { sync.setWatermarks(db, { pull: '', push: '' }); sync.setPullWatermarks(db, {}); } catch {}
  }
  deleteLink();
  // Drop every session: the link (server) identity no longer applies, and the next login goes back
  // to the local users table (standalone). Whoever holds this device logs in locally again.
  try { db.prepare(`DELETE FROM sessions`).run(); } catch { /* best effort */ }
  try { rmSync(LINK_FILE, { force: true }); } catch {} // remove any leftover legacy file too
  return { ok: true, was: link ? publicLink(link) : null };
}

// The last display name the server reported (from /api/me). Held in memory only — the display
// name is never persisted; offline we fall back to the username.
let remoteDisplayName = null;
function publicLink(link) {
  if (!link) return null;
  const claims = link.token ? jwt.decodeUnsafe(link.token) : null;
  const username = link.username || claims?.username || null;
  return {
    server_url: link.server_url, fingerprint: link.fingerprint, device_id: link.device_id,
    device_name: link.device_name || null,
    username, display_name: remoteDisplayName || username,  // the current operator (if signed in)
    role: claims?.role || null,                             // authoritative source is the signed token
    pending: !!link.pending, request_id: link.request_id || null,
    connected: !!link.device_token,                         // the device itself is authorized
    needs_reconnect: !!link.needs_reconnect,                // pre-0.9.0 link — must re-enrol the device
    needs_login: !!(link.needs_login && !link.token), needs_reauth: !!link.needs_reauth,
    jwt_exp: claims?.exp || null,
    connected_at: link.connected_at || null, last_ok: link.last_ok || null, last_sync: link.last_sync || null,
    // The tokens live in the database, so they're protected exactly when the workspace is encrypted.
    token_at_rest: isEncrypted() ? 'encrypted' : 'unencrypted',
  };
}

/** Non-secret link status for the UI. A connected device with an operator signed in is "linked";
 *  connected but nobody signed in is "needs_login"; a request awaiting acceptance is "pending". */
export function status() {
  const link = loadLink();
  if (!link) return { linked: false };
  if (link.pending) return { linked: false, pending: true, link: publicLink(link) };
  if (link.needs_reconnect) return { linked: false, needs_reconnect: true, link: publicLink(link) };
  if (!link.token) return { linked: false, needs_login: true, connected: !!link.device_token, link: publicLink(link) };
  return { linked: true, link: publicLink(link) };
}

export const LINK_PATH = LINK_FILE;
