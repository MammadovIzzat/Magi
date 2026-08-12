// Portable import/export of a whole engagement — the project, its targets, the full
// checklist item tree (statuses, answers, custom items and spawned/unfolded children)
// and every finding. Unlike a template bundle this DOES contain client-confidential
// data (credentials, raw requests), so the UI warns before writing one to disk.
//
// Import always creates a NEW project and never overwrites, so there is no conflict
// handling to get wrong. Item ids are remapped on the way in to rebuild the tree.
//
// Shape:
//   { magi: 'engagement', version: 1, exported: '<iso>',
//     project: { name, client, scope, notes, created_at },
//     assets: [ { type, label, metadata, created_at,
//                 items: [ { i, parent, group_key, group_title, title, detail, payloads[],
//                            kind, spawns, catalog, options[], opt_key, status, answer, sort,
//                            is_custom, created_at } ],
//                 findings: [ { title, kind, severity, body, created_at } ] } ] }
import { db } from './db.js';

const FORMAT = 'engagement';
const VERSION = 1;
const parseArr = (s) => { try { const v = JSON.parse(s || '[]'); return Array.isArray(v) ? v : []; } catch { return []; } };

/** Build a portable, fully re-importable object for one project, or null if missing. */
export function exportProject(id, nowISO) {
  const p = db.prepare(`SELECT name,client,scope,notes,created_at FROM projects WHERE id=?`).get(id);
  if (!p) return null;
  const assets = db.prepare(`SELECT id,type,label,metadata,created_at FROM assets WHERE project_id=? ORDER BY created_at,id`).all(id);
  return {
    magi: FORMAT, version: VERSION, exported: nowISO || null,
    project: { name: p.name, client: p.client, scope: p.scope, notes: p.notes, created_at: p.created_at },
    assets: assets.map(a => {
      const rows = db.prepare(`SELECT * FROM items WHERE asset_id=? ORDER BY id`).all(a.id);
      // stable local index per item, and the index of its parent (or null)
      const idx = new Map(rows.map((r, i) => [r.id, i]));
      return {
        type: a.type, label: a.label, metadata: JSON.parse(a.metadata || '{}'), created_at: a.created_at,
        items: rows.map((r, i) => ({
          i, parent: r.parent_id == null ? null : (idx.has(r.parent_id) ? idx.get(r.parent_id) : null),
          group_key: r.group_key, group_title: r.group_title, title: r.title, detail: r.detail,
          payloads: parseArr(r.payloads), kind: r.kind, spawns: r.spawns, catalog: r.catalog,
          options: parseArr(r.options), opt_key: r.opt_key, status: r.status, answer: r.answer,
          sort: r.sort, is_custom: r.is_custom, created_at: r.created_at,
        })),
        findings: db.prepare(`SELECT title,kind,severity,body,created_at FROM findings WHERE asset_id=? ORDER BY id`).all(a.id),
      };
    }),
  };
}

export function validateProjectBundle(b) {
  if (!b || typeof b !== 'object') throw new Error('not a JSON object');
  if (b.magi !== FORMAT) throw new Error('not a Magi project file (missing magi:"engagement")');
  if (b.version > VERSION) throw new Error(`file is version ${b.version}; this Magi understands up to ${VERSION}`);
  if (!b.project || !b.project.name) throw new Error('bundle has no project name');
  if (!Array.isArray(b.assets)) throw new Error('bundle has no assets array');
  return b;
}

/**
 * Import a project bundle as a brand-new project. Rebuilds the item tree by remapping
 * each item's local index to its new rowid. Returns a summary. Transactional.
 */
export function importProject(bundle, nameOverride) {
  validateProjectBundle(bundle);
  const P = bundle.project;
  db.prepare('BEGIN').run();
  try {
    const pid = db.prepare(`INSERT INTO projects (name,client,scope,notes,created_at) VALUES (?,?,?,?,?)`)
      .run(nameOverride || P.name, P.client ?? null, P.scope ?? null, P.notes ?? null,
        P.created_at || new Date().toISOString()).lastInsertRowid;

    const insAsset = db.prepare(`INSERT INTO assets (project_id,type,label,metadata,created_at) VALUES (?,?,?,?,?)`);
    const insItem = db.prepare(`INSERT INTO items
      (asset_id,parent_id,group_key,group_title,title,detail,payloads,kind,spawns,catalog,options,opt_key,status,answer,sort,is_custom,created_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
    const setParent = db.prepare(`UPDATE items SET parent_id=? WHERE id=?`);
    const insFinding = db.prepare(`INSERT INTO findings (asset_id,title,kind,severity,body,created_at) VALUES (?,?,?,?,?,?)`);

    let nAssets = 0, nItems = 0, nFindings = 0;
    for (const a of (bundle.assets || [])) {
      if (!a.type || !a.label) continue;
      const aid = insAsset.run(pid, a.type, a.label, JSON.stringify(a.metadata || {}),
        a.created_at || new Date().toISOString()).lastInsertRowid;
      nAssets++;

      // insert every item first (parent_id null), remember local index -> new rowid
      const map = new Map();
      const items = a.items || [];
      items.forEach((it, i) => {
        const localIdx = it.i ?? i;
        const rowid = insItem.run(aid, null, it.group_key || 'custom', it.group_title || 'Custom',
          it.title || '(untitled)', it.detail || '', JSON.stringify(it.payloads || []), it.kind || 'check',
          it.spawns ?? null, it.catalog ?? null, JSON.stringify(it.options || []), it.opt_key ?? null,
          it.status || 'todo', it.answer ?? null, it.sort ?? i, it.is_custom ? 1 : 0,
          it.created_at || new Date().toISOString()).lastInsertRowid;
        map.set(localIdx, rowid);
        nItems++;
      });
      // second pass: wire up parent links
      items.forEach((it, i) => {
        if (it.parent == null) return;
        const child = map.get(it.i ?? i), parent = map.get(it.parent);
        if (child && parent) setParent.run(parent, child);
      });

      for (const f of (a.findings || [])) {
        if (!f.title) continue;
        insFinding.run(aid, f.title, f.kind || 'note', f.severity ?? null, f.body ?? null,
          f.created_at || new Date().toISOString());
        nFindings++;
      }
    }
    db.prepare('COMMIT').run();
    return { projectId: pid, assets: nAssets, items: nItems, findings: nFindings };
  } catch (e) {
    db.prepare('ROLLBACK').run();
    throw e;
  }
}
