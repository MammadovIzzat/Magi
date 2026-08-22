// Magi — SQLite data layer using Node's built-in node:sqlite (Node 22.5+ / 26).
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { mkdirSync, existsSync, accessSync, constants } from 'node:fs';
import { homedir } from 'node:os';
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { ASSET_TYPES, TEMPLATES, instantiateItems } from './seed/templates.js';

// --- password hashing (scrypt) ---
export function hashPassword(pw) {
  const salt = randomBytes(16).toString('hex');
  const hash = scryptSync(pw, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
export function verifyPassword(pw, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const a = Buffer.from(hash, 'hex');
  const b = scryptSync(pw, salt, 64);
  return a.length === b.length && timingSafeEqual(a, b);
}

// Env vars moved to MAGI_* with the rename; the old CHECKLISTER_* names still work
// so existing setups and scripts do not break.
// An empty value counts as unset: `MAGI_PASS= magi` should not create a blank password.
export const env = (name, fallback) => {
  const v = process.env['MAGI_' + name] || process.env['CHECKLISTER_' + name];
  return v || fallback;
};

const __dirname = dirname(fileURLToPath(import.meta.url));

// Where the database lives.
//
// A source checkout keeps it in ./data so a clone is self-contained. An installed
// copy cannot: /usr/lib/magi is read-only, so it uses the XDG data directory. Decide
// by actually trying to write rather than by guessing the runtime — the earlier
// node:sea check was false under Electron and the installed app died on EACCES.
const XDG_DIR = join(process.env.XDG_DATA_HOME || join(homedir(), '.local', 'share'), 'magi');
const SYSTEM_PREFIXES = ['/usr/', '/opt/', '/nix/store/'];

function resolveDataDir() {
  const explicit = env('DATA_DIR');
  if (explicit) { mkdirSync(explicit, { recursive: true }); return explicit; }

  // Never write beside the code when it is installed system-wide, even as root.
  if (!SYSTEM_PREFIXES.some(p => __dirname.startsWith(p))) {
    const local = join(__dirname, 'data');
    try {
      mkdirSync(local, { recursive: true });
      accessSync(local, constants.W_OK);
      return local;
    } catch { /* not writable — fall through */ }
  }
  mkdirSync(XDG_DIR, { recursive: true });
  return XDG_DIR;
}

export const DATA_DIR = resolveDataDir();
export const PACKAGED = DATA_DIR === XDG_DIR;

// New installs get magi.db. An existing checklister.db is adopted as-is rather than
// renamed, so upgrading never orphans someone's engagement data.
const LEGACY_DB = join(DATA_DIR, 'checklister.db');
const DEFAULT_DB = existsSync(LEGACY_DB) ? LEGACY_DB : join(DATA_DIR, 'magi.db');
export const DB_PATH = env('DB', DEFAULT_DB);

export const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');

db.exec(`
CREATE TABLE IF NOT EXISTS projects (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL,
  client      TEXT,
  scope       TEXT,
  notes       TEXT,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS assets (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  type        TEXT NOT NULL,              -- web | ip | subnet | domain | ad | api | mobile | container
  label       TEXT NOT NULL,             -- e.g. https://app.example.com or 10.0.0.5
  metadata    TEXT NOT NULL DEFAULT '{}',-- JSON: freeform per-type fields
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_assets_project ON assets(project_id);

-- One row per checklist item instantiated for an asset (from a template or added manually).
CREATE TABLE IF NOT EXISTS items (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id    INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  -- tree: child items unfolded from a select/trigger. DBs created before this FK
  -- existed keep a plain column; deleteItemTree() in server.js covers both cases.
  parent_id   INTEGER REFERENCES items(id) ON DELETE CASCADE,
  group_key   TEXT NOT NULL,             -- section grouping key
  group_title TEXT NOT NULL,
  title       TEXT NOT NULL,
  detail      TEXT,                      -- guidance / description
  payloads    TEXT NOT NULL DEFAULT '[]',-- JSON array of example commands/payloads
  kind        TEXT NOT NULL DEFAULT 'check', -- check | question | input | trigger | select
  spawns      TEXT,                      -- spawn-group key this trigger can add
  catalog     TEXT,                      -- for select items: which catalog to draw options from
  options     TEXT NOT NULL DEFAULT '[]',-- for select items: JSON [{key,label}] selectable options
  opt_key     TEXT,                      -- for child items: which parent option produced them
  status      TEXT NOT NULL DEFAULT 'todo', -- todo | done | na | flag | yes | no
  answer      TEXT,                      -- free text answer/result
  sort        INTEGER NOT NULL DEFAULT 0,
  is_custom   INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_items_asset ON items(asset_id);

-- Findings / evidence captured against an asset (e.g. a raw HTTP request for a login).
CREATE TABLE IF NOT EXISTS findings (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_id    INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  title       TEXT NOT NULL,
  kind        TEXT NOT NULL DEFAULT 'note', -- note | request | credential | vuln
  severity    TEXT,                      -- info | low | medium | high | critical
  body        TEXT,                      -- raw request / description
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id);

-- Image attachments for a finding (screenshots). Stored as BLOBs in the DB rather than
-- loose files: it keeps the "one local file" property, travels with a project export,
-- and never leaves orphaned files behind on delete.
CREATE TABLE IF NOT EXISTS attachments (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id  INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  filename    TEXT NOT NULL,
  mime        TEXT NOT NULL,
  size        INTEGER NOT NULL,
  data        BLOB NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_attachments_finding ON attachments(finding_id);

-- Three-level model: a project holds "Asset" folders (engagement types: internal,
-- external, mobile, otiot, additional, wireless); each folder holds "Target" rows.
-- Internally the existing assets table IS the Target (it owns items and findings);
-- this folders table is the engagement "Asset" the user sees. assets.folder_id links them.
CREATE TABLE IF NOT EXISTS folders (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  grp         TEXT NOT NULL,             -- engagement type: internal|external|mobile|otiot|additional|wireless
  label       TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_folders_project ON folders(project_id);

-- auth
CREATE TABLE IF NOT EXISTS users (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  username    TEXT NOT NULL UNIQUE,
  pass_hash   TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS sessions (
  token       TEXT PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ---- team server (multi-user) ----
-- Single-use codes an admin mints to let a new client join the server. Only the hash is
-- stored, so a later read of the database never reveals a live code. Consumed atomically.
CREATE TABLE IF NOT EXISTS enroll_codes (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  code_hash   TEXT NOT NULL UNIQUE,
  role        TEXT NOT NULL DEFAULT 'worker',   -- worker | admin
  note        TEXT,                             -- optional label ("Ana's laptop")
  created_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at  TEXT,
  used_at     TEXT,
  used_by     INTEGER REFERENCES users(id) ON DELETE SET NULL
);

-- One row per enrolled client device. The bearer token is device-bound: only its hash is
-- kept, and a token presented from a different device id is rejected. revoked=1 kills it.
CREATE TABLE IF NOT EXISTS devices (
  id           TEXT PRIMARY KEY,                -- client-generated UUID
  user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  display_name TEXT NOT NULL,                   -- human name shown in attribution
  token_hash   TEXT NOT NULL,
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen    TEXT,
  revoked      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_devices_token ON devices(token_hash);

-- A client redeeming a code creates a PENDING request here; an admin approves or rejects it
-- from the Admin panel. Only on approval is the code consumed, the user/device created, and a
-- token issued (delivered once to the polling client via the token column, then cleared).
CREATE TABLE IF NOT EXISTS enroll_requests (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  code_hash    TEXT NOT NULL,
  role         TEXT NOT NULL DEFAULT 'worker',
  username     TEXT NOT NULL,
  display_name TEXT NOT NULL,
  device_id    TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'pending',   -- pending | approved | rejected
  token        TEXT,                              -- raw token, handed to the client once then cleared
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  decided_at   TEXT,
  decided_by   TEXT                               -- admin display name / username
);
CREATE INDEX IF NOT EXISTS idx_enroll_requests_status ON enroll_requests(status);

-- Append-only attribution log: who changed what, when. Drives the "current position" view.
CREATE TABLE IF NOT EXISTS audit (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  at           TEXT NOT NULL DEFAULT (datetime('now')),
  user_id      INTEGER,
  username     TEXT,
  display_name TEXT,
  device_id    TEXT,
  method       TEXT NOT NULL,
  path         TEXT NOT NULL,
  action       TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit(id);

-- editable default templates (what new assets are instantiated from)
CREATE TABLE IF NOT EXISTS tpl_types (
  type   TEXT PRIMARY KEY,
  label  TEXT NOT NULL,
  icon   TEXT,
  hint   TEXT,
  grp    TEXT,                        -- engagement group: internal|external|mobile|wireless|otiot|additional
  soon   INTEGER NOT NULL DEFAULT 0,  -- 1 = shown in the picker but not yet selectable
  sort   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tpl_items (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  type        TEXT NOT NULL REFERENCES tpl_types(type) ON DELETE CASCADE,
  group_key   TEXT NOT NULL,
  group_title TEXT NOT NULL,
  title       TEXT NOT NULL,
  detail      TEXT,
  payloads    TEXT NOT NULL DEFAULT '[]',
  kind        TEXT NOT NULL DEFAULT 'check',
  spawns      TEXT,
  catalog     TEXT,
  options     TEXT NOT NULL DEFAULT '[]',
  sort        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_tpl_items_type ON tpl_items(type);

-- Editable follow-up content: the checklists a trigger item spawns and the per-option
-- checklists a select item unfolds. Previously these lived only in seed/templates.js,
-- which made them uneditable and unavailable to custom asset types.
--   kind='spawn'   -> catalog='', gkey = the trigger's spawns value  (e.g. 'login')
--   kind='catalog' -> catalog = the select's catalog value ('tech'), gkey = option key ('nginx')
CREATE TABLE IF NOT EXISTS tpl_groups (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  type        TEXT NOT NULL,
  kind        TEXT NOT NULL,             -- spawn | catalog
  catalog     TEXT NOT NULL DEFAULT '',
  gkey        TEXT NOT NULL,
  title       TEXT NOT NULL,
  sort        INTEGER NOT NULL DEFAULT 0,
  UNIQUE(type, kind, catalog, gkey)
);
CREATE TABLE IF NOT EXISTS tpl_group_items (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  group_id    INTEGER NOT NULL REFERENCES tpl_groups(id) ON DELETE CASCADE,
  title       TEXT NOT NULL,
  detail      TEXT,
  payloads    TEXT NOT NULL DEFAULT '[]',
  kind        TEXT NOT NULL DEFAULT 'check',
  spawns      TEXT,
  sort        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_tpl_group_items ON tpl_group_items(group_id);
`);

// --- lightweight migration for DBs created before the tree/catalog columns existed ---
const cols = new Set(db.prepare(`PRAGMA table_info(items)`).all().map(r => r.name));
const addCol = (name, def) => { if (!cols.has(name)) db.exec(`ALTER TABLE items ADD COLUMN ${name} ${def}`); };
addCol('parent_id', 'INTEGER');
addCol('catalog', 'TEXT');
addCol('options', `TEXT NOT NULL DEFAULT '[]'`);
addCol('opt_key', 'TEXT');
db.exec(`CREATE INDEX IF NOT EXISTS idx_items_parent ON items(parent_id);`);

// assets (Targets) gained a parent folder (engagement Asset) with the three-level model.
const assetCols = new Set(db.prepare(`PRAGMA table_info(assets)`).all().map(r => r.name));
if (!assetCols.has('folder_id')) db.exec(`ALTER TABLE assets ADD COLUMN folder_id INTEGER REFERENCES folders(id) ON DELETE CASCADE`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_assets_folder ON assets(folder_id)`);

// tpl_types gained engagement-group columns after the first releases.
const tplCols = new Set(db.prepare(`PRAGMA table_info(tpl_types)`).all().map(r => r.name));
if (!tplCols.has('grp'))  db.exec(`ALTER TABLE tpl_types ADD COLUMN grp TEXT`);
if (!tplCols.has('soon')) db.exec(`ALTER TABLE tpl_types ADD COLUMN soon INTEGER NOT NULL DEFAULT 0`);

// users gained a role with the team server. New accounts default to 'worker'; any account
// that predates roles is the local owner, so it becomes an admin.
const userCols = new Set(db.prepare(`PRAGMA table_info(users)`).all().map(r => r.name));
if (!userCols.has('role')) {
  db.exec(`ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'worker'`);
  db.exec(`UPDATE users SET role='admin'`);
}

// --- seed the first user ---
// admin/admin by default. A generated password is lost the moment you launch from a
// desktop icon and never see a console, which locks you out of your own data. The
// desktop app opens no port at all, so this login is a lock screen rather than a
// network control — and server.js refuses to bind a non-loopback address while the
// password is still the default.
export const DEFAULT_PASS = 'admin';
if (db.prepare(`SELECT COUNT(*) c FROM users`).get().c === 0) {
  const user = env('USER', 'admin');
  const pass = env('PASS', DEFAULT_PASS);
  db.prepare(`INSERT INTO users (username, pass_hash, role) VALUES (?,?, 'admin')`).run(user, hashPassword(pass));
  console.error(`\n  [auth] created login  ->  ${user} / ${pass}`);
}

/** True while any account still uses the shipped default password. */
export function usingDefaultPassword() {
  return db.prepare(`SELECT pass_hash FROM users`).all()
    .some(u => verifyPassword(DEFAULT_PASS, u.pass_hash));
}

// Sessions are pruned on boot and on every lookup; without this they lived forever,
// outliving the 30-day cookie they were issued with.
export const SESSION_TTL_DAYS = Number(env('SESSION_DAYS', 30));
db.exec(`DELETE FROM sessions WHERE created_at < datetime('now', '-${SESSION_TTL_DAYS} days')`);

// The audit log grows without bound otherwise; keep roughly six months of history.
const AUDIT_TTL_DAYS = Number(env('AUDIT_DAYS', 180));
try { db.exec(`DELETE FROM audit WHERE at < datetime('now', '-${AUDIT_TTL_DAYS} days')`); } catch { /* pre-migration DBs */ }

// --- seeding the editable templates from seed/templates.js ---
const insType = db.prepare(`INSERT INTO tpl_types (type,label,icon,hint,grp,soon,sort) VALUES (?,?,?,?,?,?,?)`);
const insTplItem = db.prepare(`INSERT INTO tpl_items
  (type,group_key,group_title,title,detail,payloads,kind,spawns,catalog,options,sort)
  VALUES (@type,@group_key,@group_title,@title,@detail,@payloads,@kind,@spawns,@catalog,@options,@sort)`);
const insGroup = db.prepare(`INSERT INTO tpl_groups (type,kind,catalog,gkey,title,sort) VALUES (?,?,?,?,?,?)`);
const insGroupItem = db.prepare(`INSERT INTO tpl_group_items
  (group_id,title,detail,payloads,kind,spawns,sort) VALUES (?,?,?,?,?,?,?)`);

/** Install the seed file's default checklist items for one asset type. */
export function seedTypeItems(type) {
  for (const r of instantiateItems(type)) {
    insTplItem.run({
      type, group_key: r.group_key, group_title: r.group_title, title: r.title,
      detail: r.detail || '', payloads: r.payloads ?? '[]', kind: r.kind || 'check',
      spawns: r.spawns ?? null, catalog: r.catalog ?? null, options: r.options ?? '[]', sort: r.sort,
    });
  }
}

/** Install the seed file's spawn groups and catalogs for one asset type. */
export function seedTypeGroups(type) {
  const t = TEMPLATES[type];
  if (!t) return;
  let sort = 0;
  for (const [gkey, sg] of Object.entries(t.spawnGroups || {})) {
    const gid = insGroup.run(type, 'spawn', '', gkey, sg.title, sort++).lastInsertRowid;
    (sg.items || []).forEach((it, i) => insGroupItem.run(gid, it.title, it.detail || '',
      JSON.stringify(it.payloads || []), it.kind || 'check', it.spawns || null, i));
  }
  for (const [catalog, entries] of Object.entries(t.catalogs || {})) {
    for (const [gkey, cat] of Object.entries(entries)) {
      const gid = insGroup.run(type, 'catalog', catalog, gkey, cat.label || gkey, sort++).lastInsertRowid;
      (cat.items || []).forEach((it, i) => insGroupItem.run(gid, it.title, it.detail || '',
        JSON.stringify(it.payloads || []), it.kind || 'check', it.spawns || null, i));
    }
  }
}

/**
 * Wipe and reinstall every default for one type. Discards template edits; assets are untouched.
 * Refuses on types with no shipped defaults, so a custom type is never emptied.
 * Returns the number of checklist items installed, or false if there was nothing to restore.
 */
export function resetType(type) {
  if (!TEMPLATES[type]) return false;
  const gids = db.prepare(`SELECT id FROM tpl_groups WHERE type=?`).all(type).map(r => r.id);
  for (const id of gids) db.prepare(`DELETE FROM tpl_group_items WHERE group_id=?`).run(id);
  db.prepare(`DELETE FROM tpl_groups WHERE type=?`).run(type);
  db.prepare(`DELETE FROM tpl_items WHERE type=?`).run(type);
  seedTypeItems(type);
  seedTypeGroups(type);
  return db.prepare(`SELECT COUNT(*) c FROM tpl_items WHERE type=?`).get(type).c;
}

// first run: install the shipped asset types and their checklists
if (db.prepare(`SELECT COUNT(*) c FROM tpl_types`).get().c === 0) {
  ASSET_TYPES.forEach((t, i) => {
    insType.run(t.type, t.label, t.icon || null, t.hint || null, t.group || null, t.soon ? 1 : 0, i);
    seedTypeItems(t.type);
  });
  console.error(`  [templates] seeded default checklists for ${ASSET_TYPES.length} asset types`);
}

// Spawn groups / catalogs moved into the DB after the first release, so this runs
// on upgrade too — otherwise existing DBs would have triggers that spawn nothing.
if (db.prepare(`SELECT COUNT(*) c FROM tpl_groups`).get().c === 0) {
  for (const t of ASSET_TYPES) seedTypeGroups(t.type);
  console.error(`  [templates] seeded follow-up checklists & catalogs`);
}

// --- upgrade path for databases seeded before engagement groups existed ---
// Fresh installs already have the merged, grouped structure above; this only touches
// older databases so the grouped picker works without forcing a reseed.
{
  const GRP = { ip: 'internal', ad: 'internal', web: 'external', api: 'external', domain: 'external',
    mobile: 'mobile', wireless: 'wireless', iot: 'otiot', ot: 'otiot', container: 'additional' };

  // Fold the old standalone Subnet type into Host/Network (ip). Existing subnet assets
  // keep their already-copied checklists; only the template type is merged away.
  const hasSubnet = db.prepare(`SELECT 1 FROM tpl_types WHERE type='subnet'`).get();
  const hasIp = db.prepare(`SELECT 1 FROM tpl_types WHERE type='ip'`).get();
  if (hasSubnet && hasIp) {
    const bump = db.prepare(`SELECT COALESCE(MAX(sort),0) s FROM tpl_items WHERE type='ip'`).get().s + 1000;
    db.prepare(`UPDATE tpl_items SET type='ip', sort=sort+? WHERE type='subnet'`).run(bump);
    // Re-type existing subnet TARGETS too, so they carry the merged 'ip' type and group under
    // Internal (not Additional) in the three-level upgrade below. Their checklists are kept.
    db.prepare(`UPDATE assets SET type='ip' WHERE type='subnet'`).run();
    db.prepare(`DELETE FROM tpl_groups WHERE type='subnet'`).run();   // subnet had none; safe
    db.prepare(`DELETE FROM tpl_types WHERE type='subnet'`).run();
    db.prepare(`UPDATE tpl_types SET label='Host / Network', hint='10.0.0.5 or 10.0.0.0/24'
                WHERE type='ip' AND label='IP / Host'`).run();
    console.error(`  [templates] merged Subnet into Host / Network`);
  }

  // Backfill engagement group for shipped types that don't have one yet (never overwrites edits).
  const setGrp = db.prepare(`UPDATE tpl_types SET grp=? WHERE type=? AND (grp IS NULL OR grp='')`);
  for (const [t, g] of Object.entries(GRP)) setGrp.run(g, t);
  db.prepare(`UPDATE tpl_types SET soon=1 WHERE type='wireless' AND soon=0`).run();
}

// Three-level upgrade: existing targets (assets rows) predate the folder layer. Group
// each one under an engagement "Asset" folder for its project, matched by its type's
// engagement group. Runs once — new targets are created with a folder from the start.
{
  const orphans = db.prepare(`SELECT id, project_id, type FROM assets WHERE folder_id IS NULL`).all();
  if (orphans.length) {
    // subnet was folded into Host/Network (ip, Internal); map it explicitly in case a DB still
    // has subnet-typed targets when this runs.
    const grpOf = (type) => (type === 'subnet' ? 'internal'
      : db.prepare(`SELECT grp FROM tpl_types WHERE type=?`).get(type)?.grp || 'additional');
    const GRP_LABEL = { internal: 'Internal', external: 'External', mobile: 'Mobile',
      wireless: 'Wireless', otiot: 'OT / IoT', additional: 'Additional' };
    const findFolder = db.prepare(`SELECT id FROM folders WHERE project_id=? AND grp=?`);
    const makeFolder = db.prepare(`INSERT INTO folders (project_id, grp, label) VALUES (?,?,?)`);
    const setFolder = db.prepare(`UPDATE assets SET folder_id=? WHERE id=?`);
    for (const a of orphans) {
      const grp = grpOf(a.type);
      let fid = findFolder.get(a.project_id, grp)?.id;
      if (!fid) fid = makeFolder.run(a.project_id, grp, GRP_LABEL[grp] || 'Additional').lastInsertRowid;
      setFolder.run(fid, a.id);
    }
    console.error(`  [migrate] grouped ${orphans.length} target(s) under engagement folders`);
  }
}

// Sync: add the uid/clock columns and capture triggers to the engagement tables so this
// database can replicate with a team server. Harmless for a purely local install — it just
// stamps rows it never sends anywhere.
import { setupSchema as setupSync } from './sync.js';
setupSync(db);

export default db;
