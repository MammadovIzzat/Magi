// Portable import/export of checklist templates, so a methodology can be shared
// between installs. A bundle is a self-contained asset type (or several) with its
// default items and its follow-up/catalog groups — no engagement data, no findings,
// nothing client-confidential.
//
// Shape:
//   { magi: 'checklist-template', version: 1, exported: '<iso>', types: [ TYPE, ... ] }
//   TYPE = { type, label, icon, hint, items: [ITEM...], groups: [GROUP...] }
//   ITEM = { group_key, group_title, title, detail, payloads:[], kind, spawns, catalog, options:[], sort }
//   GROUP = { kind:'spawn'|'catalog', catalog, gkey, title, sort, items:[{ title, detail, payloads:[], kind, spawns, sort }] }
import { db } from './db.js';

const FORMAT = 'checklist-template';
const VERSION = 1;

const parseArr = (s) => { try { const v = JSON.parse(s || '[]'); return Array.isArray(v) ? v : []; } catch { return []; } };
const str = (v) => (v == null ? null : String(v));

/** Build a portable object for one asset type, or null if it does not exist. */
export function exportType(type) {
  const t = db.prepare(`SELECT type,label,icon,hint,grp FROM tpl_types WHERE type=?`).get(type);
  if (!t) return null;
  const items = db.prepare(`SELECT group_key,group_title,title,detail,payloads,kind,spawns,catalog,options,sort
                            FROM tpl_items WHERE type=? ORDER BY sort,id`).all(type)
    .map(i => ({ ...i, payloads: parseArr(i.payloads), options: parseArr(i.options) }));
  const groups = db.prepare(`SELECT id,kind,catalog,gkey,title,sort FROM tpl_groups WHERE type=? ORDER BY kind,catalog,sort,id`).all(type)
    .map(g => ({
      kind: g.kind, catalog: g.catalog || '', gkey: g.gkey, title: g.title, sort: g.sort,
      items: db.prepare(`SELECT title,detail,payloads,kind,spawns,sort FROM tpl_group_items WHERE group_id=? ORDER BY sort,id`).all(g.id)
        .map(it => ({ ...it, payloads: parseArr(it.payloads) })),
    }));
  return { type: t.type, label: t.label, icon: t.icon, hint: t.hint, grp: t.grp, items, groups };
}

/** Build a bundle for the given type keys, or every type when `types` is omitted. */
export function exportBundle(types, nowISO) {
  const keys = types && types.length
    ? types
    : db.prepare(`SELECT type FROM tpl_types ORDER BY sort,type`).all().map(r => r.type);
  return {
    magi: FORMAT, version: VERSION, exported: nowISO || null,
    types: keys.map(exportType).filter(Boolean),
  };
}

/** Validate a parsed bundle, throwing a friendly error on anything unusable. */
export function validateBundle(b) {
  if (!b || typeof b !== 'object') throw new Error('not a JSON object');
  if (b.magi !== FORMAT) throw new Error('not a Magi checklist template (missing magi:"checklist-template")');
  if (b.version > VERSION) throw new Error(`bundle is version ${b.version}; this Magi understands up to ${VERSION}`);
  if (!Array.isArray(b.types) || !b.types.length) throw new Error('bundle contains no asset types');
  for (const t of b.types) {
    if (!t.type || !/^[a-z0-9_]+$/.test(t.type)) throw new Error(`invalid type key: ${JSON.stringify(t.type)}`);
    if (!t.label) throw new Error(`type "${t.type}" has no label`);
    if (!Array.isArray(t.items)) throw new Error(`type "${t.type}" has no items array`);
  }
  return b;
}

const insType = () => db.prepare(`INSERT INTO tpl_types (type,label,icon,hint,grp,sort) VALUES (?,?,?,?,?,?)`);
const insItem = () => db.prepare(`INSERT INTO tpl_items
  (type,group_key,group_title,title,detail,payloads,kind,spawns,catalog,options,sort)
  VALUES (?,?,?,?,?,?,?,?,?,?,?)`);
const insGroup = () => db.prepare(`INSERT INTO tpl_groups (type,kind,catalog,gkey,title,sort) VALUES (?,?,?,?,?,?)`);
const insGroupItem = () => db.prepare(`INSERT INTO tpl_group_items (group_id,title,detail,payloads,kind,spawns,sort) VALUES (?,?,?,?,?,?,?)`);

function writeType(t, targetKey) {
  const type = targetKey || t.type;
  const maxSort = db.prepare(`SELECT COALESCE(MAX(sort),0)+1 s FROM tpl_types`).get().s;
  insType().run(type, t.label, t.icon || null, t.hint || null, t.grp || null, maxSort);
  const ii = insItem();
  (t.items || []).forEach((r, i) => ii.run(type, r.group_key || 'custom', r.group_title || 'Custom',
    r.title || '(untitled)', r.detail || '', JSON.stringify(r.payloads || []), r.kind || 'check',
    str(r.spawns), str(r.catalog), JSON.stringify(r.options || []), r.sort ?? i));
  const ig = insGroup(); const igi = insGroupItem();
  (t.groups || []).forEach((g, gi) => {
    const gid = ig.run(type, g.kind === 'catalog' ? 'catalog' : 'spawn', g.catalog || '',
      g.gkey, g.title || g.gkey, g.sort ?? gi).lastInsertRowid;
    (g.items || []).forEach((it, ii2) => igi.run(gid, it.title || '(untitled)', it.detail || '',
      JSON.stringify(it.payloads || []), it.kind || 'check', str(it.spawns), it.sort ?? ii2));
  });
}

function deleteType(type) {
  const gids = db.prepare(`SELECT id FROM tpl_groups WHERE type=?`).all(type).map(r => r.id);
  for (const id of gids) db.prepare(`DELETE FROM tpl_group_items WHERE group_id=?`).run(id);
  db.prepare(`DELETE FROM tpl_groups WHERE type=?`).run(type);
  db.prepare(`DELETE FROM tpl_items WHERE type=?`).run(type);
  db.prepare(`DELETE FROM tpl_types WHERE type=?`).run(type);
}

/**
 * Import a validated bundle. onConflict decides what happens when a type key already
 * exists: 'skip' (default, safe), 'replace' (overwrite it), or 'rename' (import under
 * a fresh key so both survive). Returns a per-type summary.
 */
export function importBundle(bundle, onConflict = 'skip') {
  validateBundle(bundle);
  const results = [];
  const tx = db.prepare('BEGIN'); tx.run();
  try {
    for (const t of bundle.types) {
      const exists = db.prepare(`SELECT type FROM tpl_types WHERE type=?`).get(t.type);
      if (!exists) { writeType(t); results.push({ type: t.type, action: 'created' }); continue; }
      if (onConflict === 'replace') { deleteType(t.type); writeType(t); results.push({ type: t.type, action: 'replaced' }); }
      else if (onConflict === 'rename') {
        let key = t.type, n = 2;
        while (db.prepare(`SELECT type FROM tpl_types WHERE type=?`).get(key)) key = `${t.type}_${n++}`;
        writeType(t, key); results.push({ type: t.type, action: 'imported as', as: key });
      } else results.push({ type: t.type, action: 'skipped (already exists)' });
    }
    db.prepare('COMMIT').run();
  } catch (e) {
    db.prepare('ROLLBACK').run();
    throw e;
  }
  return results;
}
