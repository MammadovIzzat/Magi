// Regression: a client whose clock runs AHEAD of the server must still receive later server
// updates. The engine pulls with `exceptNode` so a client's own echoed writes never advance
// (and poison) its pull watermark. Before that fix, one client write + any forward clock skew
// froze all inbound server updates while sync still reported "ok / up to date".
//
//   node scripts/sync-skew-smoke.mjs
import { DatabaseSync } from 'node:sqlite';
import { collectChanges, applyChanges, setupSchema, watermarks, setWatermarks, node } from '../sync.js';

const checks = [];
const check = (name, ok) => { checks.push([name, !!ok]); if (!ok) console.error('   ^ FAILED: ' + name); return !!ok; };

const BASE = `
  CREATE TABLE projects (id INTEGER PRIMARY KEY, name TEXT, client TEXT, scope TEXT, notes TEXT, status TEXT, start_date TEXT, end_date TEXT, created_at TEXT);
  CREATE TABLE folders  (id INTEGER PRIMARY KEY, project_id INTEGER, grp TEXT, label TEXT, created_at TEXT);
  CREATE TABLE assets   (id INTEGER PRIMARY KEY, project_id INTEGER, folder_id INTEGER, type TEXT, label TEXT, metadata TEXT, created_at TEXT);
  CREATE TABLE items    (id INTEGER PRIMARY KEY, asset_id INTEGER, parent_id INTEGER, group_key TEXT, group_title TEXT, title TEXT, detail TEXT, payloads TEXT, kind TEXT, spawns TEXT, catalog TEXT, options TEXT, opt_key TEXT, status TEXT, answer TEXT, sort INTEGER, is_custom INTEGER, created_at TEXT);
  CREATE TABLE findings (id INTEGER PRIMARY KEY, asset_id INTEGER, title TEXT, kind TEXT, severity TEXT, body TEXT, refs TEXT, fix_status TEXT, in_report INTEGER, author TEXT, created_at TEXT);
  CREATE TABLE attachments (id INTEGER PRIMARY KEY, finding_id INTEGER, filename TEXT, mime TEXT, size INTEGER, created_at TEXT, data BLOB);
`;
const mkdb = () => { const d = new DatabaseSync(':memory:'); d.exec(BASE); setupSchema(d); return d; };
const payloadMax = (p) => { let m = ''; for (const r of p.rows || []) if (r.hlc > m) m = r.hlc; for (const t of p.tombstones || []) if (t.hlc > m) m = t.hlc; return m; };

const S = mkdb(), C = mkdb();
const cNode = node(C);

// The client's logical clock is stuck ~1h in the future (a laptop that was briefly ahead).
C.prepare(`UPDATE _sync_meta SET last_ms = (CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)) + ?`).run(60 * 60 * 1000);

// One client cycle, mirroring client-link.syncOnce: push own rows, then pull with exceptNode and
// advance the watermark only over foreign rows.
function clientCycle() {
  const wm = watermarks(C);
  const local = collectChanges(C, wm.push, { onlyLocal: true });
  if (local.rows.length || local.tombstones.length) { applyChanges(S, local); const pm = payloadMax(local); if (pm > wm.push) setWatermarks(C, { push: pm }); }
  const pr = collectChanges(S, wm.pull, { exceptNode: cNode });   // the fix under test
  applyChanges(C, pr);
  const pm = payloadMax(pr);
  if (pm && pm > wm.pull) setWatermarks(C, { pull: pm });
  return pr;
}

// 1) client works (authors a row with its future clock) and syncs it up + back
C.prepare(`INSERT INTO projects (name) VALUES ('Client Work')`).run();
const firstPull = clientCycle();
check('server does not echo the client its own row', firstPull.rows.every(r => !r.hlc.endsWith('-' + cNode)));
check("client's future clock did NOT jump the pull watermark", watermarks(C).pull === '');

// 2) a teammate adds a finding-bearing project on the server NOW (server's real, earlier clock)
S.prepare(`INSERT INTO projects (name) VALUES ('Server Update')`).run();
const sAsset = S.prepare(`INSERT INTO assets (project_id,type,label) VALUES ((SELECT id FROM projects WHERE name='Server Update'),'web','x')`).run().lastInsertRowid;
S.prepare(`INSERT INTO findings (asset_id,title,kind,body) VALUES (?,?,?,?)`).run(sAsset, 'IDOR', 'vuln', 'getUserPhoto');

// 3) client syncs again — the later server update must arrive despite the client being "ahead"
clientCycle();
check('client receives the later server project', !!C.prepare(`SELECT 1 FROM projects WHERE name='Server Update'`).get());
check('client receives the server finding', !!C.prepare(`SELECT 1 FROM findings WHERE title='IDOR'`).get());

let bad = 0;
for (const [name, ok] of checks) { console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${name}`); if (!ok) bad++; }
S.close(); C.close();
if (bad) { console.error(`\n  SYNC SKEW SMOKE FAILED — ${bad} check(s)\n`); process.exit(1); }
console.log('\n  sync skew smoke ok\n');
