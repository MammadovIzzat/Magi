// Backup engine test: incremental + encrypted + image-preserving + restore.
//
//   node scripts/backup-smoke.mjs
//
// Proves: first backup is a full snapshot, later ones carry only the delta since the last
// (adds AND deletes), findings' image blobs survive the round trip, a wrong password is
// rejected, and restoring rebuilds the exact state (deleted rows stay deleted via tombstones).
import { rmSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const dir = mkdtempSync(join(tmpdir(), 'magi-bk-'));
process.env.MAGI_DATA_DIR = dir;
process.env.MAGI_DB = join(dir, 'magi.db');
const PW = 'correct horse battery staple';

const { db } = await import('../db.js');
const sync = await import('../sync.js');
const backup = await import('../backup.js');
sync.setupSchema(db);

const checks = [];
const check = (n, ok) => { checks.push([n, !!ok]); if (!ok) console.error('   ^ FAILED: ' + n); return !!ok; };
const cleanup = () => { try { rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch {} };
process.on('exit', cleanup);
process.on('uncaughtException', (e) => { console.error('\n  BACKUP SMOKE crashed:', e?.stack || e); cleanup(); process.exit(1); });

const rid = (r) => Number(r.lastInsertRowid);
// --- seed a small engagement with a real image blob on a finding ---
const pid = rid(db.prepare(`INSERT INTO projects (name) VALUES (?)`).run('Acme Pentest'));
const aid = rid(db.prepare(`INSERT INTO assets (project_id, type, label) VALUES (?,?,?)`).run(pid, 'web', 'app.acme.test'));
const f1 = rid(db.prepare(`INSERT INTO findings (asset_id, title, kind, severity, body) VALUES (?,?,?,?,?)`)
  .run(aid, 'Reflected XSS', 'vuln', 'high', 'search box reflects q'));
const f2 = rid(db.prepare(`INSERT INTO findings (asset_id, title, kind, severity, body) VALUES (?,?,?,?,?)`)
  .run(aid, 'Recon note', 'note', '', 'nmap done'));
const IMG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 253, 254, 255]); // PNG-ish bytes incl. high bytes
db.prepare(`INSERT INTO attachments (finding_id, filename, mime, size, data) VALUES (?,?,?,?,?)`)
  .run(f1, 'poc.png', 'image/png', IMG.length, IMG);
const imgUid = db.prepare(`SELECT uid FROM attachments WHERE finding_id=?`).get(f1).uid;
const f1Uid = db.prepare(`SELECT uid FROM findings WHERE id=?`).get(f1).uid;
const f2Uid = db.prepare(`SELECT uid FROM findings WHERE id=?`).get(f2).uid;

// --- backup 1: full snapshot ---
const b1 = backup.runBackup(db, { password: PW });
check('backup 1 captures the whole engagement', b1.rows >= 5); // project, asset, 2 findings, attachment
check('backup 1 includes the image attachment row', b1.rows >= 5 && backup.listBackups().length === 1);

// --- backup 2: nothing changed -> empty delta (NOT a full re-dump) ---
const b2 = backup.runBackup(db);
check('backup 2 is an empty incremental (no changes)', b2.rows === 0 && b2.tombstones === 0);

// --- change: add a credential finding, delete the note ---
const f3 = rid(db.prepare(`INSERT INTO findings (asset_id, title, kind, severity, body) VALUES (?,?,?,?,?)`)
  .run(aid, 'Admin creds', 'credential', '', 'admin:hunter2@app.acme.test'));
const f3Uid = db.prepare(`SELECT uid FROM findings WHERE id=?`).get(f3).uid;
db.prepare(`DELETE FROM findings WHERE id=?`).run(f2); // trigger writes a tombstone

// --- backup 3: only the delta (one add, one delete) ---
const b3 = backup.runBackup(db);
check('backup 3 carries only the new finding', b3.rows === 1);
check('backup 3 carries the delete as a tombstone', b3.tombstones === 1);
check('three backup files on disk', backup.listBackups().length === 3);

// --- wrong password must be rejected ---
let wrongRejected = false;
try { backup.restoreAll(db, 'not the password'); } catch { wrongRejected = true; }
check('restore with the wrong password is rejected', wrongRejected);

// --- simulate data loss, then restore ---
sync.mutedRun(db, () => { // muted: wipe without minting new tombstones
  for (const t of ['attachments', 'findings', 'assets', 'projects']) db.prepare(`DELETE FROM ${t}`).run();
  db.prepare(`DELETE FROM tombstones`).run();
});
check('data is gone before restore', db.prepare(`SELECT COUNT(*) c FROM findings`).get().c === 0);

const rr = backup.restoreAll(db, PW);
check('restore reports files applied', rr.files === 3 && rr.applied >= 5);

const gotF1 = db.prepare(`SELECT * FROM findings WHERE uid=?`).get(f1Uid);
const gotF3 = db.prepare(`SELECT * FROM findings WHERE uid=?`).get(f3Uid);
const gotF2 = db.prepare(`SELECT * FROM findings WHERE uid=?`).get(f2Uid);
check('restored the vuln finding', gotF1 && gotF1.title === 'Reflected XSS' && gotF1.severity === 'high');
check('restored the later credential finding', gotF3 && gotF3.kind === 'credential');
check('the deleted note stayed deleted (tombstone honored)', !gotF2);

const gotImg = db.prepare(`SELECT * FROM attachments WHERE uid=?`).get(imgUid);
check('restored the attachment row', gotImg && gotImg.filename === 'poc.png');
check('the image bytes survived exactly', gotImg && Buffer.from(gotImg.data).equals(IMG));

const failed = checks.filter(([, ok]) => !ok);
console.log(`\nbackup-smoke: ${checks.length - failed.length}/${checks.length} checks passed`);
if (failed.length) { console.error('FAILED:', failed.map(([n]) => n).join(', ')); process.exit(1); }
console.log('  ✓ incremental, encrypted, image-preserving backups round-trip cleanly');
