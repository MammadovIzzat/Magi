// End-to-end replication test: a real server + this process acting as a linked client.
//
//   node scripts/sync-smoke.mjs
//
// Proves the sync engine: client->server, server->client, last-writer-wins BOTH ways,
// tombstones, offline edits that flush on reconnect, and the non-destructive stash.
import { spawn } from 'node:child_process';
import { rmSync, existsSync, readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import https from 'node:https';

const PORT = 48445;
const serverDir = mkdtempSync(join(tmpdir(), 'magi-syncsrv-'));
const clientDir = mkdtempSync(join(tmpdir(), 'magi-synccli-'));
const PASS = 'a-strong-admin-passphrase';
const CRT = join(serverDir, 'server', 'server.crt');
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const checks = [];
const check = (name, ok) => { checks.push([name, !!ok]); if (!ok) console.error('   ^ FAILED: ' + name); return !!ok; };

process.env.MAGI_DATA_DIR = clientDir;
process.env.MAGI_DB = join(clientDir, 'magi.db');

let child, agent, stderr = '';
function boot() {
  const c = spawn(process.execPath, ['server.js'], {
    env: { ...process.env, MAGI_DATA_DIR: serverDir, MAGI_DB: join(serverDir, 'magi.db'),
      MAGI_SERVER: '1', MAGI_HOST: '127.0.0.1', MAGI_PORT: String(PORT), MAGI_PASS: PASS, MAGI_USER: 'admin' },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  c.stderr.on('data', d => { stderr += d; });
  return c;
}
function cleanup() {
  try { child?.kill(); } catch {}
  try { agent?.destroy(); } catch {}
  for (const d of [serverDir, clientDir]) { try { rmSync(d, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch {} }
}
process.on('exit', () => { try { child?.kill(); } catch {} });
process.on('uncaughtException', (e) => { console.error('\n  SYNC SMOKE crashed:', e?.stack || e); if (stderr.trim()) console.error(stderr); cleanup(); process.exit(1); });
function die(msg) { console.error(`\n  SYNC SMOKE FAILED: ${msg}`); if (stderr.trim()) console.error(stderr.split('\n').map(l => '   ' + l).join('\n')); cleanup(); process.exit(1); }

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
async function waitUp() {
  for (let i = 0; i < 120; i++) { if (existsSync(CRT)) { try { return readFileSync(CRT); } catch {} } if (child.exitCode != null) die('server exited early'); await sleep(150); }
  die('server never wrote its cert');
}
async function waitAnswering() { for (let i = 0; i < 60; i++) { try { const r = await req('GET', '/api/me'); if (r.status) return; } catch {} await sleep(150); } }

// ---- boot + enrol ----
child = boot();
const cert = await waitUp();
agent = new https.Agent({ ca: cert, checkServerIdentity: () => undefined });
await waitAnswering();
const fingerprint = new (await import('node:crypto')).X509Certificate(cert).fingerprint256;
const login = await req('POST', '/api/auth/login', { body: { username: 'admin', password: PASS } });
const cookie = (login.headers['set-cookie'] || []).map(c => c.split(';')[0]).join('; ');
const mkCode = async () => (await req('POST', '/api/admin/enroll-codes', { cookie, body: { role: 'worker' } })).json.code;

const link = await import('../client-link.js');
const { db } = await import('../db.js');
// the background loop fires an immediate sync on connect; retry past its "busy" guard so
// the test drives replication deterministically
const syncNow = async () => { let r; for (let i = 0; i < 40; i++) { r = await link.syncOnce(); if (r.ok || r.error !== 'busy') return r; await sleep(50); } return r; };
const serverDb = new DatabaseSync(join(serverDir, 'magi.db')); // read-only-ish verification handle
const sName = (uid) => serverDb.prepare('SELECT name FROM projects WHERE uid=?').get(uid)?.name;

// connect (a pending request), admin-approve it, poll to finalize the link — then drive sync
// deterministically for the test.
async function connectApprove(username, display_name) {
  const r = await link.connect({ server_url: `https://127.0.0.1:${PORT}`, code: await mkCode(), username, display_name });
  if (!r.ok) return { ok: false, error: r.error };
  const pending = (await req('GET', '/api/admin/requests', { cookie })).json;
  const rid = (pending || []).find(x => x.display_name === display_name)?.id;
  if (rid) await req('POST', `/api/admin/requests/${rid}/approve`, { cookie });
  await link.pollApproval();
  link.stopSyncLoop();
  return { ok: link.status().linked === true };
}

const c1 = await connectApprove('ana', 'Ana R.');
check('client links to server (after approval)', c1.ok === true);

// ---- 1) client -> server ----
const pid = db.prepare('INSERT INTO projects (name,client) VALUES (?,?)').run('Client Made', 'Acme').lastInsertRowid;
const fid = db.prepare('INSERT INTO folders (project_id,grp,label) VALUES (?,?,?)').run(pid, 'external', 'External').lastInsertRowid;
const aid = db.prepare('INSERT INTO assets (project_id,folder_id,type,label) VALUES (?,?,?,?)').run(pid, fid, 'web', 'https://app.acme.test').lastInsertRowid;
db.prepare('INSERT INTO items (asset_id,group_key,group_title,title,kind,status) VALUES (?,?,?,?,?,?)').run(aid, 'recon', 'Recon', 'Check headers', 'check', 'todo');
db.prepare('INSERT INTO findings (asset_id,title,kind,body) VALUES (?,?,?,?)').run(aid, 'Open redirect', 'vuln', 'GET /r?u=//evil');
const projUid = db.prepare('SELECT uid FROM projects WHERE id=?').get(pid).uid;
let r = await syncNow();
check('sync ok (client->server push)', r.ok === true && r.pushed >= 5);
check('server received the whole target tree', sName(projUid) === 'Client Made'
  && serverDb.prepare('SELECT COUNT(*) c FROM items WHERE uid IN (SELECT uid FROM items)').get().c >= 1
  && serverDb.prepare("SELECT COUNT(*) c FROM findings WHERE title='Open redirect'").get().c === 1);

// ---- 1b) engagement dates replicate, but a WORKER cannot finish via sync ----
// This client is enrolled as a worker; even a crafted push that sets status='finished' must be
// neutralized server-side (only a team admin finishes an engagement), while detail/date edits sync.
db.prepare(`UPDATE projects SET start_date='2026-08-01', end_date='2026-08-15', status='finished' WHERE id=?`).run(pid);
await syncNow();
const sProj = serverDb.prepare('SELECT status,start_date,end_date FROM projects WHERE uid=?').get(projUid);
check('engagement dates replicate to the server', sProj && sProj.start_date === '2026-08-01' && sProj.end_date === '2026-08-15');
check('a worker cannot finish an engagement through sync', sProj && sProj.status !== 'finished');

// ---- 2) server -> client ----
const sp = await req('POST', '/api/projects', { cookie, body: { name: 'Server Made' } });
const sAsset = await req('POST', `/api/projects/${sp.json.id}/assets`, { cookie, body: { grp: 'external', label: 'Ext' } });
const sTarget = await req('POST', `/api/assets/${sAsset.json.id}/targets`, { cookie, body: { type: 'web', label: 'https://srv.test' } });
await syncNow();
const localServerProj = db.prepare("SELECT id,uid FROM projects WHERE name='Server Made'").get();
check('client received the server-made project', !!localServerProj);
const localTargetItems = localServerProj ? db.prepare(`SELECT COUNT(*) c FROM items i JOIN assets a ON a.id=i.asset_id JOIN folders f ON f.id=a.folder_id WHERE f.project_id=?`).get(localServerProj.id).c : 0;
check('client received the server target’s full checklist', localTargetItems > 20);

// ---- 2b) security: a crafted tombstone with an injected table name must be rejected ----
const projBefore = serverDb.prepare('SELECT COUNT(*) c FROM projects').get().c;
const evil = await link.remoteFetch('/api/sync/push', { method: 'POST', body: {
  rows: [], tombstones: [{ tbl: 'projects WHERE 1=1; --', uid: 'x', hlc: '999999999999999-999999-attacker' }],
} });
const projAfter = serverDb.prepare('SELECT COUNT(*) c FROM projects').get().c;
check('malicious tombstone table is rejected (no SQL injection / no mass delete)', evil.status === 200 && projAfter === projBefore && projAfter >= 2);

// ---- 3) last-writer-wins, both directions, on the SAME item ----
// pick a server-origin item both sides now share by uid
const sharedItem = db.prepare(`SELECT i.uid FROM items i JOIN assets a ON a.id=i.asset_id JOIN folders f ON f.id=a.folder_id WHERE f.project_id=? LIMIT 1`).get(localServerProj.id).uid;
const sItemId = serverDb.prepare('SELECT id FROM items WHERE uid=?').get(sharedItem).id;
// server sets it 'done' (a later clock), client had it 'todo'
await req('PATCH', `/api/items/${sItemId}`, { cookie, body: { status: 'done' } });
await syncNow();
const afterPull = db.prepare('SELECT status FROM items WHERE uid=?').get(sharedItem).status;
check('LWW server->client: newer server status wins', afterPull === 'done');
// now client sets it 'na' (even later) and pushes
db.prepare('UPDATE items SET status=? WHERE uid=?').run('na', sharedItem);
await syncNow();
const afterPush = serverDb.prepare('SELECT status FROM items WHERE uid=?').get(sharedItem).status;
check('LWW client->server: newer client status wins', afterPush === 'na');

// ---- 4) tombstones both ways ----
// server deletes its project -> client should drop it
await req('DELETE', `/api/projects/${sp.json.id}`, { cookie });
await syncNow();
check('server delete propagates to client', !db.prepare("SELECT 1 FROM projects WHERE name='Server Made'").get());
// client deletes its project -> server should drop it
db.prepare('DELETE FROM projects WHERE id=?').run(pid);
await syncNow();
check('client delete propagates to server', !sName(projUid));

// ---- 5) offline edits flush on reconnect ----
const op = db.prepare('INSERT INTO projects (name) VALUES (?)').run('Made Offline').lastInsertRowid;
const opUid = db.prepare('SELECT uid FROM projects WHERE id=?').get(op).uid;
child.kill(); await new Promise(r => child.once('exit', r)); await sleep(300);
const offline = await syncNow();
check('sync fails gracefully while offline', offline.ok === false);
check('offline edit is still local (queued)', !!db.prepare('SELECT 1 FROM projects WHERE uid=?').get(opUid));
stderr = ''; child = boot(); await waitUp(); await waitAnswering();
const back = await syncNow();
check('queued offline edit flushes after reconnect', back.ok === true && sName(opUid) === 'Made Offline');

// ---- 6) non-destructive stash ----
link.disconnect(); // restores (empty) stash, clears the mirror
check('disconnect cleared the server mirror', db.prepare('SELECT COUNT(*) c FROM projects').get().c === 0);
const personal = db.prepare('INSERT INTO projects (name) VALUES (?)').run('My Personal Notes').lastInsertRowid;
const personalUid = db.prepare('SELECT uid FROM projects WHERE id=?').get(personal).uid;
const c2 = await connectApprove('bob', 'Bob');
check('reconnect (new user) ok', c2.ok === true);
check('personal project was stashed out of the active db', !db.prepare("SELECT 1 FROM projects WHERE name='My Personal Notes'").get());
check('personal data held as an atomic db stash blob', db.prepare('SELECT COUNT(*) c FROM stash_blobs').get().c === 1);
await syncNow();
check('stashed personal data did NOT reach the server', !serverDb.prepare("SELECT 1 FROM projects WHERE name='My Personal Notes'").get());
link.disconnect();
check('personal project restored on disconnect', !!db.prepare("SELECT 1 FROM projects WHERE name='My Personal Notes'").get());

// ---- report ----
let bad = 0;
for (const [name, ok] of checks) { console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${name}`); if (!ok) bad++; }
serverDb.close();
cleanup();
if (bad) { console.error(`\n  SYNC SMOKE FAILED — ${bad} check(s)\n`); process.exit(1); }
console.log('\n  sync smoke ok\n');
