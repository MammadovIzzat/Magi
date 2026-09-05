// Portable import/export of a whole engagement across the three-level model:
//   project  ->  assets (engagement-type folders)  ->  targets (checklist + findings)
// Unlike a template bundle this DOES contain client-confidential data (credentials, raw
// requests, screenshots), so the UI warns before writing one to disk. Import always
// creates a NEW project and never overwrites. The item tree is rebuilt by index remap.
//
// Shape (version 2):
//   { magi:'engagement', version:2, exported,
//     project:{ name, client, scope, notes, created_at },
//     assets:[ { grp, label, created_at,
//                targets:[ { type, label, metadata, created_at,
//                            items:[ {i,parent,...,status,answer,...} ],
//                            findings:[ {title,kind,severity,body, attachments:[{filename,mime,size,data(b64)}]} ] } ] } ] }
// Version-1 files (assets = flat targets, no folders) still import: each is wrapped in
// a folder chosen from its type's engagement group.
import { db } from './db.js';

const FORMAT = 'engagement';
const VERSION = 2;
const parseArr = (s) => { try { const v = JSON.parse(s || '[]'); return Array.isArray(v) ? v : []; } catch { return []; } };
const GRP_LABEL = { internal: 'Internal', external: 'External', mobile: 'Mobile', wireless: 'Wireless', otiot: 'OT / IoT', additional: 'Additional' };
const grpOfType = (type) => db.prepare(`SELECT grp FROM tpl_types WHERE type=?`).get(type)?.grp || 'additional';

function serializeTarget(a) {
  const rows = db.prepare(`SELECT * FROM items WHERE asset_id=? ORDER BY id`).all(a.id);
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
    findings: db.prepare(`SELECT id,uid,title,kind,severity,body,refs,fix_status,in_report,author,cvss,created_at FROM findings WHERE asset_id=? ORDER BY id`).all(a.id)
      .map(f => ({
        uid: f.uid, title: f.title, kind: f.kind, severity: f.severity, body: f.body, refs: f.refs, fix_status: f.fix_status, in_report: f.in_report, author: f.author, cvss: f.cvss, created_at: f.created_at,
        attachments: db.prepare(`SELECT filename,mime,size,data,created_at FROM attachments WHERE finding_id=? ORDER BY id`).all(f.id)
          .map(at => ({ filename: at.filename, mime: at.mime, size: at.size, created_at: at.created_at, data: Buffer.from(at.data).toString('base64') })),
      })),
  };
}

/** Build a portable, fully re-importable object for one project, or null if missing. */
export function exportProject(id, nowISO) {
  const p = db.prepare(`SELECT name,client,scope,notes,created_at FROM projects WHERE id=?`).get(id);
  if (!p) return null;
  const folders = db.prepare(`SELECT id,grp,label,created_at FROM folders WHERE project_id=? ORDER BY created_at,id`).all(id);
  return {
    magi: FORMAT, version: VERSION, exported: nowISO || null,
    project: { name: p.name, client: p.client, scope: p.scope, notes: p.notes, created_at: p.created_at },
    assets: folders.map(f => ({
      grp: f.grp, label: f.label, created_at: f.created_at,
      targets: db.prepare(`SELECT * FROM assets WHERE folder_id=? ORDER BY created_at,id`).all(f.id).map(serializeTarget),
    })),
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

// Normalise either format into folders[] -> targets[].
function foldersFromBundle(b) {
  // v2: assets are folders with a targets[] array
  if (b.assets.some(a => Array.isArray(a.targets))) {
    return b.assets.map(a => ({ grp: a.grp || 'additional', label: a.label || GRP_LABEL[a.grp] || 'Additional', created_at: a.created_at, targets: a.targets || [] }));
  }
  // v1: assets ARE targets; wrap each under a folder for its type's group
  const byGrp = new Map();
  for (const t of b.assets) {
    const grp = grpOfType(t.type);
    if (!byGrp.has(grp)) byGrp.set(grp, { grp, label: GRP_LABEL[grp] || 'Additional', targets: [] });
    byGrp.get(grp).targets.push(t);
  }
  return [...byGrp.values()];
}

/** Import a project bundle as a brand-new project. Transactional. */
export function importProject(bundle, nameOverride) {
  validateProjectBundle(bundle);
  const P = bundle.project;
  db.prepare('BEGIN').run();
  try {
    const pid = db.prepare(`INSERT INTO projects (name,client,scope,notes,created_at) VALUES (?,?,?,?,?)`)
      .run(nameOverride || P.name, P.client ?? null, P.scope ?? null, P.notes ?? null,
        P.created_at || new Date().toISOString()).lastInsertRowid;

    const insFolder = db.prepare(`INSERT INTO folders (project_id,grp,label,created_at) VALUES (?,?,?,?)`);
    const insTarget = db.prepare(`INSERT INTO assets (project_id,folder_id,type,label,metadata,created_at) VALUES (?,?,?,?,?,?)`);
    const insItem = db.prepare(`INSERT INTO items
      (asset_id,parent_id,group_key,group_title,title,detail,payloads,kind,spawns,catalog,options,opt_key,status,answer,sort,is_custom,created_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
    const setParent = db.prepare(`UPDATE items SET parent_id=? WHERE id=?`);
    const insFinding = db.prepare(`INSERT INTO findings (asset_id,title,kind,severity,body,fix_status,in_report,author,cvss,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`);
    const insAttach = db.prepare(`INSERT INTO attachments (finding_id,filename,mime,size,data,created_at) VALUES (?,?,?,?,?,?)`);

    // Attack-chain links reference other findings by uid; imported findings get fresh uids, so
    // remember old->new and rewrite the refs in a second pass once every finding exists.
    const uidMap = new Map();          // old exported uid -> new uid
    const pendingRefs = [];            // { id, refs: <old uids JSON> } to translate afterwards
    let nAssets = 0, nTargets = 0, nItems = 0, nFindings = 0;
    for (const folder of foldersFromBundle(bundle)) {
      const fid = insFolder.run(pid, folder.grp || 'additional', folder.label || 'Additional',
        folder.created_at || new Date().toISOString()).lastInsertRowid;
      nAssets++;
      for (const tgt of (folder.targets || [])) {
        if (!tgt.type || !tgt.label) continue;
        const aid = insTarget.run(pid, fid, tgt.type, tgt.label, JSON.stringify(tgt.metadata || {}),
          tgt.created_at || new Date().toISOString()).lastInsertRowid;
        nTargets++;

        const map = new Map();
        const items = tgt.items || [];
        items.forEach((it, i) => {
          const rowid = insItem.run(aid, null, it.group_key || 'custom', it.group_title || 'Custom',
            it.title || '(untitled)', it.detail || '', JSON.stringify(it.payloads || []), it.kind || 'check',
            it.spawns ?? null, it.catalog ?? null, JSON.stringify(it.options || []), it.opt_key ?? null,
            it.status || 'todo', it.answer ?? null, it.sort ?? i, it.is_custom ? 1 : 0,
            it.created_at || new Date().toISOString()).lastInsertRowid;
          map.set(it.i ?? i, rowid);
          nItems++;
        });
        items.forEach((it, i) => {
          if (it.parent == null) return;
          const child = map.get(it.i ?? i), parent = map.get(it.parent);
          if (child && parent) setParent.run(parent, child);
        });

        for (const f of (tgt.findings || [])) {
          if (!f.title) continue;
          // fix_status only belongs on a retest target; keep it just there and only for a known
          // value, so a hand-edited bundle can't flip an ordinary finding into "retest mode".
          const fix = (tgt.type === 'retest' && ['fixed', 'half_fixed', 'not_fixed'].includes(f.fix_status)) ? f.fix_status : null;
          const fnd = insFinding.run(aid, f.title, f.kind || 'note', f.severity ?? null, f.body ?? null,
            fix, f.in_report ? 1 : 0, f.author ?? null, f.cvss ?? null, f.created_at || new Date().toISOString()).lastInsertRowid;
          nFindings++;
          const newUid = db.prepare(`SELECT uid FROM findings WHERE id=?`).get(fnd)?.uid;
          if (f.uid && newUid) uidMap.set(f.uid, newUid);
          if (f.refs) pendingRefs.push({ id: fnd, refs: f.refs });
          for (const at of (f.attachments || [])) {
            if (!at.data || !at.mime) continue;
            const buf = Buffer.from(at.data, 'base64');
            insAttach.run(fnd, at.filename || 'image', at.mime, at.size || buf.length, buf, at.created_at || new Date().toISOString());
          }
        }
      }
    }
    // Second pass: translate each finding's refs from old uids to the new ones (dropping any
    // that pointed outside this bundle), so the attack chain survives the round trip.
    const setRefs = db.prepare(`UPDATE findings SET refs=? WHERE id=?`);
    for (const p of pendingRefs) {
      let old; try { old = JSON.parse(p.refs || '[]'); } catch { old = []; }
      const mapped = (Array.isArray(old) ? old : []).map(u => uidMap.get(u)).filter(Boolean);
      if (mapped.length) setRefs.run(JSON.stringify(mapped), p.id);
    }
    db.prepare('COMMIT').run();
    return { projectId: pid, assets: nAssets, targets: nTargets, items: nItems, findings: nFindings };
  } catch (e) {
    db.prepare('ROLLBACK').run();
    throw e;
  }
}
