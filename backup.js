// Incremental, encrypted backups for the team server.
//
// A backup is the set of changes since the previous one — rows newer than a watermark plus
// tombstones for deletes — captured with the SAME collectChanges the sync engine uses. So it
// automatically includes screenshots attached to findings, and a restore is just applyChanges
// (last-writer-wins merge) of the deltas back onto the database, in order. The first backup
// (watermark empty) is therefore a full snapshot; later ones are small deltas.
//
// Each file is encrypted with an admin password: an AES-256-GCM key derived by scrypt, with a
// per-file random salt + IV and an auth tag. A backup copied off the server is unreadable
// without the password, and tampering fails the tag on restore. The password is stored (0600)
// so scheduled backups can run unattended — its value is protecting backups moved OFF the box.
import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync, statSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes, scryptSync, createCipheriv, createDecipheriv } from 'node:crypto';
import { DATA_DIR } from './db.js';
import { collectChanges, applyChanges, maxHlc } from './sync.js';

const DIR = join(DATA_DIR, 'backups');
const CONFIG = join(DATA_DIR, 'backup-config.json');
const DEFAULTS = { enabled: false, interval_hours: 24, password: null, last_hlc: '', seq: 0, last_backup_at: null };

function loadConfig() {
  if (!existsSync(CONFIG)) return { ...DEFAULTS };
  try { return { ...DEFAULTS, ...JSON.parse(readFileSync(CONFIG, 'utf8')) }; } catch { return { ...DEFAULTS }; }
}
function saveConfig(c) { writeFileSync(CONFIG, JSON.stringify(c, null, 2)); try { chmodSync(CONFIG, 0o600); } catch {} }

const keyFor = (password, salt) => scryptSync(String(password), salt, 32);
function encrypt(obj, password) {
  const salt = randomBytes(16), iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', keyFor(password, salt), iv);
  const data = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
  return { magi: 'backup', v: 1, salt: salt.toString('hex'), iv: iv.toString('hex'), tag: c.getAuthTag().toString('hex'), data: data.toString('base64') };
}
function decrypt(file, password) {
  const d = createDecipheriv('aes-256-gcm', keyFor(password, Buffer.from(file.salt, 'hex')), Buffer.from(file.iv, 'hex'));
  d.setAuthTag(Buffer.from(file.tag, 'hex'));
  const out = Buffer.concat([d.update(Buffer.from(file.data, 'base64')), d.final()]); // throws on wrong password / tampering
  return JSON.parse(out.toString('utf8'));
}

/** Non-secret backup status for the UI. */
export function config() {
  const c = loadConfig();
  return { enabled: c.enabled, interval_hours: c.interval_hours, has_password: !!c.password, last_backup_at: c.last_backup_at, seq: c.seq };
}
export function setConfig(db, { enabled, interval_hours, password } = {}) {
  const c = loadConfig();
  if (enabled !== undefined) c.enabled = !!enabled;
  if (interval_hours !== undefined) c.interval_hours = Math.max(1, Math.min(24 * 30, Math.floor(Number(interval_hours) || 24)));
  if (password) c.password = String(password);
  saveConfig(c);
  reschedule(db);
  return config();
}
export function listBackups() {
  try {
    return readdirSync(DIR).filter(f => f.endsWith('.magi.enc')).sort()
      .map(f => { const s = statSync(join(DIR, f)); return { file: f, size: s.size, at: s.mtime.toISOString() }; });
  } catch { return []; }
}

/** Run one incremental backup now (delta since the last). Encrypts with `password` or the stored one. */
export function runBackup(db, { password } = {}) {
  const c = loadConfig();
  const pw = password || c.password;
  if (!pw) throw new Error('set a backup password first');
  mkdirSync(DIR, { recursive: true });
  const changes = collectChanges(db, c.last_hlc || '');
  const upto = maxHlc(db) || c.last_hlc || '';
  const payload = { at: new Date().toISOString(), since: c.last_hlc || '', upto, rows: changes.rows, tombstones: changes.tombstones };
  const seq = (c.seq || 0) + 1;
  const name = `backup-${String(seq).padStart(4, '0')}.magi.enc`;
  writeFileSync(join(DIR, name), JSON.stringify(encrypt(payload, pw)));
  try { chmodSync(join(DIR, name), 0o600); } catch {}
  c.seq = seq; c.last_hlc = upto; c.last_backup_at = payload.at;
  if (password && !c.password) c.password = String(password); // remember it for scheduling
  saveConfig(c);
  return { file: name, rows: changes.rows.length, tombstones: changes.tombstones.length };
}

/** Restore by decrypting every backup file in order and merging its changes back in. */
export function restoreAll(db, password) {
  if (!password) throw new Error('the backup password is required');
  if (!existsSync(DIR)) throw new Error('no backups found');
  const files = readdirSync(DIR).filter(f => f.endsWith('.magi.enc')).sort();
  if (!files.length) throw new Error('no backups found');
  let applied = 0, deleted = 0;
  for (const f of files) {
    let payload;
    try { payload = decrypt(JSON.parse(readFileSync(join(DIR, f), 'utf8')), password); }
    catch { throw new Error('wrong password, or a backup file is corrupt'); }
    const r = applyChanges(db, { rows: payload.rows || [], tombstones: payload.tombstones || [] });
    applied += r.applied; deleted += r.deleted;
  }
  return { files: files.length, applied, deleted };
}

let timer = null;
export function reschedule(db) {
  if (timer) { clearInterval(timer); timer = null; }
  const c = loadConfig();
  if (!c.enabled || !c.password) return;
  timer = setInterval(() => { try { runBackup(db); } catch { /* logged nowhere; a failed backup must not crash the server */ } },
    Math.max(1, c.interval_hours) * 3600 * 1000);
  if (timer.unref) timer.unref();
}
