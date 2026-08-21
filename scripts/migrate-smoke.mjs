// Guards the upgrade path: a database created BEFORE the sync columns existed must migrate
// cleanly on first boot of the new code. This is the exact path that shipped broken once —
// backfill ran only on pre-sync rows, which no other test produces.
//
//   node scripts/migrate-smoke.mjs
import { DatabaseSync } from 'node:sqlite';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const dir = mkdtempSync(join(tmpdir(), 'magi-migrate-'));
const dbPath = join(dir, 'legacy.db');
const checks = [];
const check = (n, ok) => { checks.push([n, !!ok]); };

// 1) Build a legacy database: the pre-sync engagement tables (no uid/hlc, no triggers) with
//    a little real-shaped data, including a self-referential item child and an attachment.
{
  const db = new DatabaseSync(dbPath);
  db.exec(`
    CREATE TABLE projects (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, client TEXT, scope TEXT, notes TEXT, created_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE folders (id INTEGER PRIMARY KEY AUTOINCREMENT, project_id INTEGER, grp TEXT, label TEXT, created_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE assets (id INTEGER PRIMARY KEY AUTOINCREMENT, project_id INTEGER, folder_id INTEGER, type TEXT, label TEXT, metadata TEXT DEFAULT '{}', created_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE items (id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id INTEGER, parent_id INTEGER, group_key TEXT, group_title TEXT, title TEXT, detail TEXT, payloads TEXT DEFAULT '[]', kind TEXT DEFAULT 'check', spawns TEXT, catalog TEXT, options TEXT DEFAULT '[]', opt_key TEXT, status TEXT DEFAULT 'todo', answer TEXT, sort INTEGER DEFAULT 0, is_custom INTEGER DEFAULT 0, created_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id INTEGER, title TEXT, kind TEXT DEFAULT 'note', severity TEXT, body TEXT, created_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE attachments (id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id INTEGER, filename TEXT, mime TEXT, size INTEGER, data BLOB, created_at TEXT DEFAULT (datetime('now')));
  `);
  db.prepare("INSERT INTO projects (name,client) VALUES ('Legacy Eng','Acme')").run();
  db.prepare("INSERT INTO folders (project_id,grp,label) VALUES (1,'external','Ext')").run();
  db.prepare("INSERT INTO assets (project_id,folder_id,type,label) VALUES (1,1,'web','https://x.test')").run();
  db.prepare("INSERT INTO items (asset_id,group_key,group_title,title) VALUES (1,'recon','Recon','Parent')").run();
  db.prepare("INSERT INTO items (asset_id,parent_id,group_key,group_title,title) VALUES (1,1,'recon','Recon','Child')").run();
  db.prepare("INSERT INTO findings (asset_id,title,kind) VALUES (1,'A finding','vuln')").run();
  db.prepare("INSERT INTO attachments (finding_id,filename,mime,size,data) VALUES (1,'shot.png','image/png',3,?)").run(Buffer.from([1, 2, 3]));
  db.close();
}

// 2) Boot the REAL db.js against it — exactly what the app does on startup.
const r = spawnSync(process.execPath,
  ['-e', 'import("./db.js").then(()=>process.exit(0)).catch(e=>{console.error(e.message);process.exit(1)})'],
  { cwd: ROOT, env: { ...process.env, MAGI_DB: dbPath, MAGI_DATA_DIR: dir }, encoding: 'utf8' });
check('legacy database migrates without error', r.status === 0);
if (r.status !== 0) console.error('   migration stderr:', (r.stderr || '').split('\n').filter(l => l && !/^\s*\[/.test(l))[0]);

// 3) Every pre-existing row must have gained a uid + clock (so it will sync).
if (r.status === 0) {
  const db = new DatabaseSync(dbPath);
  const bad = ['projects', 'folders', 'assets', 'items', 'findings', 'attachments']
    .filter(t => db.prepare(`SELECT COUNT(*) c FROM ${t} WHERE uid IS NULL OR hlc IS NULL`).get().c > 0);
  const uids = db.prepare('SELECT COUNT(DISTINCT uid) c FROM items').get().c;
  db.close();
  check('every migrated row has a uid + clock', bad.length === 0);
  check('uids are distinct per row (not shared)', uids === 2);
}

let failed = 0;
for (const [n, ok] of checks) { console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${n}`); if (!ok) failed++; }
rmSync(dir, { recursive: true, force: true });
if (failed) { console.error('\n  MIGRATE SMOKE FAILED\n'); process.exit(1); }
console.log('\n  migrate smoke ok\n');
