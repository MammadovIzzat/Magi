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
import { DATA_DIR, db } from './db.js';
import * as sync from './sync.js';
import { exportProject } from './projects-io.js';
import { importProject } from './projects-io.js';

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

/** Open TLS to the server, verify its certificate matches the pasted fingerprint, return the PEM. */
export function fetchAndPinCert(serverUrl, expectedFingerprint) {
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
      if (normFp(cert.fingerprint256) !== normFp(expectedFingerprint))
        return reject(new Error('certificate fingerprint does not match — refusing to connect (possible man-in-the-middle)'));
      resolve({ pem: derToPem(cert.raw), fingerprint: cert.fingerprint256 });
    });
    socket.on('error', reject);
    socket.setTimeout(TIMEOUT, () => socket.destroy(new Error('connection timed out')));
  });
}

function agentFor(link) {
  // Pin: trust exactly the server's own certificate; the fingerprint was checked on connect.
  return new https.Agent({ ca: link.cert_pem, checkServerIdentity: () => undefined, keepAlive: false });
}

/** One authenticated request to the linked server. Rejects only on transport failure. */
export function remoteFetch(path, { method = 'GET', body, headers = {}, link } = {}) {
  link = link || loadLink();
  if (!link || !link.token) return Promise.reject(new Error('not linked'));
  const u = new URL(link.server_url);
  const data = body != null ? (typeof body === 'string' ? body : JSON.stringify(body)) : null;
  return new Promise((resolve, reject) => {
    const r = https.request({
      host: u.hostname, port: Number(u.port) || 8443, path, method, agent: agentFor(link),
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${link.token}`,
        'x-magi-device': link.device_id,
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
 * Enroll this client with a server. Verifies the fingerprint, redeems the one-time code,
 * stores the device-bound token encrypted. Returns { ok, error?, link? }.
 */
export async function connect({ server_url, fingerprint, code, username, display_name }) {
  if (!server_url || !fingerprint || !code || !username || !display_name)
    return { ok: false, error: 'server URL, fingerprint, code, username and display name are all required' };
  linkGen++; // invalidate any in-flight sync from a previous link state
  let pin;
  try { pin = await fetchAndPinCert(server_url, fingerprint); }
  catch (e) { return { ok: false, error: e.message }; }

  const device_id = randomUUID();
  const link = { server_url, fingerprint: pin.fingerprint, cert_pem: pin.pem, device_id };

  // Set local engagements aside BEFORE the irreversible enrollment, so a failure can undo it.
  let stash_id = null;
  try { stash_id = stashLocalProjects(); }
  catch (e) { return { ok: false, error: `could not set local data aside: ${e.message}` }; }

  let res;
  try { res = await remoteFetch('/api/enroll', { method: 'POST', link: { ...link, token: '-' }, body: { code, username, display_name, device_id } }); }
  catch (e) { restoreStash(stash_id); return { ok: false, error: `could not reach the server: ${e.message}` }; }
  if (res.status !== 201) { restoreStash(stash_id); return { ok: false, error: res.json?.error || `enrollment failed (${res.status})` }; }

  sync.setWatermarks(db, { pull: '', push: '' }); // fresh mirror — pull the whole server
  const full = {
    ...link, token: res.json.token, username: res.json.username,
    display_name: res.json.display_name, role: res.json.role,
    connected_at: new Date().toISOString(), stash_id,
  };
  saveLink(full);
  startSyncLoop();
  return { ok: true, link: publicLink(full) };
}

// ---- replication ----
const payloadMax = (p) => {
  let m = '';
  for (const r of p.rows || []) if (r.hlc > m) m = r.hlc;
  for (const t of p.tombstones || []) if (t.hlc > m) m = t.hlc;
  return m;
};

let syncing = false;
let linkGen = 0; // bumped by connect()/disconnect() so an in-flight sync can't write after the link changes

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
  if (!loadLink()?.token) return;
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
    return { online, status: r.status, who: r.json || null };
  } catch (e) { return { online: false, error: e.message }; }
}

/** Unlink: stop syncing, drop the cached server data, restore the stashed local engagements. */
export function disconnect() {
  const link = loadLink();
  linkGen++;        // invalidate any in-flight syncOnce/heartbeat so it can't write after us
  stopSyncLoop();
  if (link) {
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
    username: link.username, display_name: link.display_name, role: link.role,
    connected_at: link.connected_at || null, last_ok: link.last_ok || null, last_sync: link.last_sync || null,
    // How the token is (or will be) stored: keyed off the actual encryptor, so this is right
    // both for a freshly-connected link and one just loaded from disk.
    token_at_rest: link._locked ? 'locked' : (encryptor?.available ? 'encrypted' : 'unencrypted'),
  };
}

/** Non-secret link status for the UI. */
export function status() {
  const link = loadLink();
  return { linked: !!link, ...(link ? { link: publicLink(link) } : {}) };
}

export const LINK_PATH = LINK_FILE;
