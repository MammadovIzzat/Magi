// Project export/import round-trip: an engagement survives a trip out to a portable file and
// back, INCLUDING attack-chain links (refs, remapped to the new findings' uids) and retest
// fix statuses. Guards against silently dropping those columns on export or import.
//
//   node scripts/io-smoke.mjs
import { rmSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const dir = mkdtempSync(join(tmpdir(), 'magi-io-'));
process.env.MAGI_DATA_DIR = dir;
process.env.MAGI_DB = join(dir, 'magi.db');

const { db } = await import('../db.js');
const sync = await import('../sync.js');
const io = await import('../projects-io.js');
sync.setupSchema(db);

const checks = [];
const check = (n, ok) => { checks.push([n, !!ok]); if (!ok) console.error('   ^ FAILED: ' + n); };
process.on('exit', () => { try { rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch {} });

const rid = (r) => Number(r.lastInsertRowid);
const pid = rid(db.prepare(`INSERT INTO projects (name) VALUES (?)`).run('Src'));
const fid = rid(db.prepare(`INSERT INTO folders (project_id,grp,label) VALUES (?,?,?)`).run(pid, 'external', 'Ext'));
const aid = rid(db.prepare(`INSERT INTO assets (project_id,folder_id,type,label) VALUES (?,?,?,?)`).run(pid, fid, 'web', 'https://x'));
const fA = rid(db.prepare(`INSERT INTO findings (asset_id,title,kind) VALUES (?,?,?)`).run(aid, 'Creds', 'credential'));
const uidA = db.prepare(`SELECT uid FROM findings WHERE id=?`).get(fA).uid;
db.prepare(`INSERT INTO findings (asset_id,title,kind,severity,refs) VALUES (?,?,?,?,?)`).run(aid, 'RCE', 'vuln', 'critical', JSON.stringify([uidA]));
// a retest target with a fix status
const rf = rid(db.prepare(`INSERT INTO folders (project_id,grp,label) VALUES (?,?,?)`).run(pid, 'retest', 'RT'));
const ra = rid(db.prepare(`INSERT INTO assets (project_id,folder_id,type,label) VALUES (?,?,?,?)`).run(pid, rf, 'retest', 'Remediation'));
db.prepare(`INSERT INTO findings (asset_id,title,kind,fix_status,in_report) VALUES (?,?,?,?,?)`).run(ra, 'ACME-1', 'vuln', 'half_fixed', 1);

const bundle = io.exportProject(pid);
check('export carries refs + fix_status', /\brefs\b/.test(JSON.stringify(bundle)) && JSON.stringify(bundle).includes('half_fixed'));

const res = io.importProject(bundle, 'Imported');
const imp = db.prepare(`SELECT f.title, f.refs, f.fix_status, f.in_report FROM findings f JOIN assets a ON a.id=f.asset_id WHERE a.project_id=?`).all(res.projectId);
const newCredsUid = db.prepare(`SELECT f.uid FROM findings f JOIN assets a ON a.id=f.asset_id WHERE a.project_id=? AND f.title='Creds'`).get(res.projectId).uid;
const rce = imp.find(f => f.title === 'RCE');

check('import preserves the retest fix status', imp.find(f => f.title === 'ACME-1')?.fix_status === 'half_fixed');
check('import preserves the report tick', imp.find(f => f.title === 'ACME-1')?.in_report === 1);
check('import keeps the attack-chain link', rce && JSON.parse(rce.refs || '[]').length === 1);
check('the chain link is remapped to the imported finding’s new uid', rce && JSON.parse(rce.refs)[0] === newCredsUid);
check('the old uid did not leak into the import', rce && !JSON.parse(rce.refs).includes(uidA));

const failed = checks.filter(([, ok]) => !ok);
console.log(`\nio-smoke: ${checks.length - failed.length}/${checks.length} checks passed`);
if (failed.length) { console.error('FAILED:', failed.map(([n]) => n).join(', ')); process.exit(1); }
console.log('  ✓ project export/import round-trips refs (remapped) and fix_status');
