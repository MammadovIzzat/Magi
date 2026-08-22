// Full, encrypted backups for the team server.
//
// Each backup is a COMPLETE snapshot of the syncable data — every live row plus every
// tombstone — captured with the same collectChanges the sync engine uses (so it includes
// screenshots attached to findings). Any single backup restores the whole database on its
// own; there is no "keep the set together" requirement. Only the newest few are kept.
//
// Each file is encrypted with an admin-chosen password: an AES-256-GCM key derived by scrypt,
// with a per-file random salt + IV and an auth tag. The password is **never stored** — the
// admin types it each time a backup runs, and is reminded when a scheduled one is due. We keep
// only a scrypt *verifier* so a typo can be caught before it produces a backup no one can open.
import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync, statSync, chmodSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes, scryptSync, timingSafeEqual, createCipheriv, createDecipheriv } from 'node:crypto';
import { DATA_DIR } from './db.js';
import { collectChanges, applyChanges } from './sync.js';

const DIR = join(DATA_DIR, 'backups');
const CONFIG = join(DATA_DIR, 'backup-config.json');
const RETAIN = 5; // keep only the newest N backups; older ones are pruned after each run
const DEFAULTS = { enabled: false, interval_hours: 24, pw_check: null, seq: 0, last_backup_at: null };

// A verifier for the backup password: a scrypt hash with a FIXED salt. It never decrypts
// anything (each file has its own random salt) — it only lets us tell "same password as before"
// from "typo", without keeping the password itself.
const VERIFY_SALT = Buffer.from('magi-backup-verifier-v1');
const pwCheck = (password) => scryptSync(String(password), VERIFY_SALT, 16).toString('hex');
const pwMatches = (password, stored) => {
  if (!stored) return true; // no verifier yet — first backup sets it
  try { return timingSafeEqual(Buffer.from(pwCheck(password), 'hex'), Buffer.from(stored, 'hex')); } catch { return false; }
};

function loadConfig() {
  let c = { ...DEFAULTS };
  if (existsSync(CONFIG)) { try { c = { ...DEFAULTS, ...JSON.parse(readFileSync(CONFIG, 'utf8')) }; } catch { c = { ...DEFAULTS }; } }
  // Migrate away from any earlier build that stored the password (or an incremental watermark)
  // in plaintext: keep a verifier for continuity, then strip the secret and dead fields.
  let dirty = false;
  if (c.password) { if (!c.pw_check) c.pw_check = pwCheck(c.password); delete c.password; dirty = true; }
  if ('last_hlc' in c) { delete c.last_hlc; dirty = true; }
  if (dirty) saveConfig(c);
  return c;
}
function saveConfig(c) {
  const { enabled, interval_hours, pw_check, seq, last_backup_at } = c;
  writeFileSync(CONFIG, JSON.stringify({ enabled, interval_hours, pw_check, seq, last_backup_at }, null, 2));
  try { chmodSync(CONFIG, 0o600); } catch {}
}

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

const intervalMs = (c) => Math.max(1, c.interval_hours || 24) * 3600 * 1000;
function nextDueAt(c) { return c.last_backup_at ? new Date(new Date(c.last_backup_at).getTime() + intervalMs(c)).toISOString() : null; }
function isDue(c) {
  if (!c.enabled) return false;
  if (!c.last_backup_at) return true; // scheduled, but never run yet
  return Date.now() - new Date(c.last_backup_at).getTime() >= intervalMs(c);
}

/** Non-secret backup status for the UI. */
export function config() {
  const c = loadConfig();
  return {
    enabled: c.enabled, interval_hours: c.interval_hours, has_password: !!c.pw_check,
    last_backup_at: c.last_backup_at, seq: c.seq, retain: RETAIN,
    due: isDue(c), next_due_at: nextDueAt(c),
  };
}
/** Set the reminder schedule only — no password is ever taken or stored here. */
export function setConfig(db, { enabled, interval_hours } = {}) {
  const c = loadConfig();
  if (enabled !== undefined) c.enabled = !!enabled;
  if (interval_hours !== undefined) c.interval_hours = Math.max(1, Math.min(24 * 30, Math.floor(Number(interval_hours) || 24)));
  saveConfig(c);
  return config();
}
export function listBackups() {
  try {
    return readdirSync(DIR).filter(f => f.endsWith('.magi.enc')).sort()
      .map(f => { const s = statSync(join(DIR, f)); return { file: f, size: s.size, at: s.mtime.toISOString() }; });
  } catch { return []; }
}
function prune() {
  const files = readdirSync(DIR).filter(f => f.endsWith('.magi.enc')).sort(); // oldest-first by zero-padded seq
  for (const f of files.slice(0, Math.max(0, files.length - RETAIN))) { try { unlinkSync(join(DIR, f)); } catch {} }
}

/** Run one FULL backup now, encrypted with `password` (always required — never stored). */
export function runBackup(db, { password } = {}) {
  if (!password) throw new Error('a backup password is required');
  const c = loadConfig();
  if (!pwMatches(password, c.pw_check)) throw new Error('that password does not match the one your existing backups use');
  mkdirSync(DIR, { recursive: true });
  const changes = collectChanges(db, ''); // '' = everything: a full, self-contained snapshot
  const payload = { at: new Date().toISOString(), full: true, rows: changes.rows, tombstones: changes.tombstones };
  const seq = (c.seq || 0) + 1;
  const name = `backup-${String(seq).padStart(4, '0')}.magi.enc`;
  writeFileSync(join(DIR, name), JSON.stringify(encrypt(payload, password)));
  try { chmodSync(join(DIR, name), 0o600); } catch {}
  c.seq = seq; c.last_backup_at = payload.at; if (!c.pw_check) c.pw_check = pwCheck(password);
  saveConfig(c);
  prune(); // keep only the newest RETAIN
  return { file: name, rows: changes.rows.length, tombstones: changes.tombstones.length, kept: listBackups().length };
}

const NAME_RE = /^backup-\d{4,}\.magi\.enc$/;

/** Raw text of one stored backup file, for download. Null if the name is bogus or missing. */
export function readBackup(name) {
  if (!NAME_RE.test(String(name))) return null;
  const p = join(DIR, name);
  return existsSync(p) ? readFileSync(p, 'utf8') : null;
}

function applyOne(db, text, password) {
  let payload;
  try {
    const file = typeof text === 'string' ? JSON.parse(text) : text;
    if (!file || file.magi !== 'backup') throw new Error('not a backup');
    payload = decrypt(file, password);
  } catch { throw new Error('wrong password, or a backup file is not a Magi backup / is corrupt'); }
  return applyChanges(db, { rows: payload.rows || [], tombstones: payload.tombstones || [] });
}

/**
 * Restore from the server's stored backups. Each is a full snapshot, so applying them
 * oldest-first (newest-wins on any conflict) reconstructs the latest saved state.
 */
export function restoreAll(db, password) {
  if (!password) throw new Error('the backup password is required');
  if (!existsSync(DIR)) throw new Error('no backups found');
  const files = readdirSync(DIR).filter(f => f.endsWith('.magi.enc')).sort();
  if (!files.length) throw new Error('no backups found');
  let applied = 0, deleted = 0;
  for (const f of files) { const r = applyOne(db, readFileSync(join(DIR, f), 'utf8'), password); applied += r.applied; deleted += r.deleted; }
  return { files: files.length, applied, deleted };
}

/**
 * Restore from files the admin UPLOADED (not the server's own store) — for rebuilding a
 * server whose data directory is gone. `files` is `[{name, text}]`; a single full backup is
 * enough, but several are applied in name order (newest-wins).
 */
export function restoreFromFiles(db, files, password) {
  if (!password) throw new Error('the backup password is required');
  if (!Array.isArray(files) || !files.length) throw new Error('no backup files were uploaded');
  const sorted = [...files].sort((a, b) => (String(a.name) < String(b.name) ? -1 : String(a.name) > String(b.name) ? 1 : 0));
  let applied = 0, deleted = 0;
  for (const f of sorted) { const r = applyOne(db, f.text, password); applied += r.applied; deleted += r.deleted; }
  return { files: sorted.length, applied, deleted };
}
