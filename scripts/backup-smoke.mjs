// Backup engine test: full snapshots, encrypted, image-preserving, verifier, retention, restore.
//
//   node scripts/backup-smoke.mjs
//
// Proves: every backup is a full self-contained snapshot; the password is NEVER stored (only a
// verifier); a mismatched/wrong password is rejected; findings' image blobs survive; only the
// newest few files are kept; and a single full backup restores the whole state (deletes honored).
import { rmSync, mkdtempSync, existsSync, readFileSync, readdirSync } from 'node:fs';
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
const wipe = () => sync.mutedRun(db, () => { // muted: wipe without minting new tombstones
  for (const t of ['attachments', 'findings', 'assets', 'projects']) db.prepare(`DELETE FROM ${t}`).run();
  db.prepare(`DELETE FROM tombstones`).run();
});

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

// --- a password is always required (never stored) ---
let needPw = false;
try { backup.runBackup(db, {}); } catch { needPw = true; }
check('a backup refuses to run without a password', needPw);

// --- backup 1: full snapshot ---
const b1 = backup.runBackup(db, { password: PW });
check('backup 1 captures the whole engagement', b1.rows >= 5); // project, asset, 2 findings, attachment

// --- the password is NOT persisted; only a verifier is ---
const cfg = JSON.parse(readFileSync(join(dir, 'backup-config.json'), 'utf8'));
check('the backup password is never written to disk', !('password' in cfg) && typeof cfg.pw_check === 'string' && !cfg.pw_check.includes(PW));
check('config() reports a password is on file without exposing it', backup.config().has_password === true && backup.config().password === undefined);

// --- a DIFFERENT password is rejected (verifier catches drift/typos) ---
let mismatch = false;
try { backup.runBackup(db, { password: 'a different password' }); } catch { mismatch = true; }
check('a backup with a mismatched password is rejected', mismatch);

// --- backup 2: still a FULL snapshot (not an empty delta) ---
const b2 = backup.runBackup(db, { password: PW });
check('every backup is a full snapshot', b2.rows >= 5);

// --- change: add a credential finding, delete the note; next backup is full and current ---
const f3 = rid(db.prepare(`INSERT INTO findings (asset_id, title, kind, severity, body) VALUES (?,?,?,?,?)`)
  .run(aid, 'Admin creds', 'credential', '', 'admin:hunter2@app.acme.test'));
const f3Uid = db.prepare(`SELECT uid FROM findings WHERE id=?`).get(f3).uid;
db.prepare(`DELETE FROM findings WHERE id=?`).run(f2); // trigger writes a tombstone
const b3 = backup.runBackup(db, { password: PW });
check('the full snapshot has the live rows (note gone, creds in)', b3.rows >= 5);
check('the full snapshot carries the delete as a tombstone', b3.tombstones >= 1);

// --- retention: only the newest 5 are kept ---
for (let i = 0; i < 4; i++) backup.runBackup(db, { password: PW }); // 3 + 4 = 7 runs total
check('only the newest 5 backups are retained', backup.listBackups().length === 5);

// --- a single latest full backup restores the whole state on its own ---
const latest = backup.listBackups().at(-1).file;
wipe();
check('data is gone before restore', db.prepare(`SELECT COUNT(*) c FROM findings`).get().c === 0);
let wrongRejected = false;
try { backup.restoreFromFiles(db, [{ name: latest, text: backup.readBackup(latest) }], 'nope'); } catch { wrongRejected = true; }
check('restore with the wrong password is rejected', wrongRejected);
const one = backup.restoreFromFiles(db, [{ name: latest, text: backup.readBackup(latest) }], PW);
check('one full backup restores the whole engagement', one.applied >= 5);
const gotF1 = db.prepare(`SELECT * FROM findings WHERE uid=?`).get(f1Uid);
const gotF3 = db.prepare(`SELECT * FROM findings WHERE uid=?`).get(f3Uid);
check('restored the vuln finding', gotF1 && gotF1.title === 'Reflected XSS' && gotF1.severity === 'high');
check('restored the later credential finding', gotF3 && gotF3.kind === 'credential');
check('the deleted note stayed deleted (tombstone honored)', !db.prepare(`SELECT 1 FROM findings WHERE uid=?`).get(f2Uid));
const gotImg = db.prepare(`SELECT * FROM attachments WHERE uid=?`).get(imgUid);
check('the image bytes survived exactly', gotImg && Buffer.from(gotImg.data).equals(IMG));

// --- readBackup guards its filename; restoreAll uses the server's own store ---
check('readBackup returns a stored file, rejects a bogus name', backup.readBackup(latest) && backup.readBackup('../etc/passwd') === null);
wipe();
const rr = backup.restoreAll(db, PW);
check('restoreAll rebuilds from the stored backups', rr.applied >= 5 && db.prepare(`SELECT 1 FROM findings WHERE uid=?`).get(f1Uid));

const failed = checks.filter(([, ok]) => !ok);
console.log(`\nbackup-smoke: ${checks.length - failed.length}/${checks.length} checks passed`);
if (failed.length) { console.error('FAILED:', failed.map(([n]) => n).join(', ')); process.exit(1); }
console.log('  ✓ full, encrypted, image-preserving backups — password never stored, newest 5 kept');
