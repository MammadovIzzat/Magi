// Tests the non-destructive stash recovery (client-link.js), in-process, no server.
//
//   node scripts/stash-smoke.mjs
//
// Guards the two crash-safety fixes: (1) a stash blob left by an interrupted connect is
// restored on boot when NOT linked, and (2) a blob whose import partially fails is preserved
// and marked, so it is never re-imported into duplicates on a later boot.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const dir = mkdtempSync(join(tmpdir(), 'magi-stash-'));
process.env.MAGI_DATA_DIR = dir;
process.env.MAGI_DB = join(dir, 'magi.db');

const checks = [];
const check = (n, ok) => { checks.push([n, !!ok]); if (!ok) console.error('   ^ FAILED: ' + n); };
const { db } = await import('../db.js');
const link = await import('../client-link.js');

const projCount = () => db.prepare('SELECT COUNT(*) c FROM projects').get().c;
const has = (name) => !!db.prepare('SELECT 1 FROM projects WHERE name=?').get(name);
const good = (name) => ({ magi: 'engagement', version: 2, project: { name }, assets: [] });
const bad = { magi: 'engagement', version: 2, project: {}, assets: [] }; // no name -> importProject throws

// 1) a stash blob with NO active link is restored on boot (interrupted-connect recovery)
db.prepare('INSERT INTO stash_blobs (data) VALUES (?)').run(JSON.stringify({ projects: [good('Restored A'), good('Restored B')] }));
const r1 = link.reconcileStash();
check('reconcile restores a stash blob when not linked', r1 === 2 && has('Restored A') && has('Restored B'));
check('restored blob is dropped afterwards', db.prepare('SELECT COUNT(*) c FROM stash_blobs').get().c === 0);

// 2) partial import failure -> blob trimmed to the failures and marked, good bundle imported once
db.prepare('INSERT INTO stash_blobs (data) VALUES (?)').run(JSON.stringify({ projects: [good('Good One'), bad] }));
const r2 = link.reconcileStash();
check('partial restore imports only the good bundle', r2 === 1 && has('Good One'));
const fb = db.prepare('SELECT failed, data FROM stash_blobs').get();
check('failed remnant is preserved and marked failed=1', fb && fb.failed === 1 && JSON.parse(fb.data).projects.length === 1);
const after = projCount();

// 3) a later boot must NOT re-import the already-restored bundle (no duplication)
const r3 = link.reconcileStash();
check('reconcile skips the failed blob — no duplicate re-import', r3 === 0 && projCount() === after);

let bad2 = 0;
for (const [n, ok] of checks) { console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${n}`); if (!ok) bad2++; }
try { rmSync(dir, { recursive: true, force: true }); } catch {}
if (bad2) { console.error('\n  STASH SMOKE FAILED\n'); process.exit(1); }
console.log('\n  stash smoke ok\n');
