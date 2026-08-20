#!/usr/bin/env node
// Magi CLI — shares the same SQLite DB as the web app.
import { readFileSync } from 'node:fs';
import { db, resetType } from './db.js';
import { exportBundle, importBundle } from './templates-io.js';
import { exportProject as exportProjectBundle, importProject } from './projects-io.js';

const q = (s) => db.prepare(s);
const args = process.argv.slice(2);
const cmd = args[0];

function help() {
  console.log(`MAGI — the pentester's familiar  ·  CLI

  magi projects                          list projects
  magi new-project "<name>" [client]     create a project
  magi types                             list asset types
  magi assets <projectId>                list assets (engagement types) in a project
  magi add-asset <projectId> <engagement-type> <name>   add an asset folder
                                         (internal|external|mobile|wireless|otiot|additional)
  magi targets <assetId>                 list targets inside an asset
  magi add-target <assetId> <type> <identifier>   add a target (+ its checklist)
  magi show <targetId>                    show a target's checklist
  magi set <itemId> <status>             status: todo|done|na|flag|yes|no
  magi export <projectId>                print markdown report
  magi export-project <projectId>        print a portable project file (JSON, re-importable)
  magi import-project <file.json> [name] import a project file as a new engagement
  magi rm-project <projectId> [--yes]    delete a project + everything in it
  magi rm-asset <assetId> [--yes]        delete an asset + all its targets
  magi rm-target <targetId> [--yes]      delete one target + its checklist
  magi reseed [type|all]                 restore shipped default checklists
                                                (discards template edits; assets untouched)

  Share checklist templates between installs (no engagement data):
  magi export-templates [type ...]       print a template bundle as JSON (all types if none given)
  magi import-templates <file.json> [--replace | --rename]
                                         import a bundle; existing types are skipped
                                         by default, --replace overwrites, --rename keeps both

  Web app:  npm start   ->  http://localhost:4173\n`);
}

function table(rows, cols) {
  if (!rows.length) return console.log('  (none)');
  const w = cols.map(c => Math.max(c.length, ...rows.map(r => String(r[c] ?? '').length)));
  const line = (vals) => '  ' + vals.map((v, i) => String(v).padEnd(w[i])).join('  ');
  console.log(line(cols)); console.log('  ' + w.map(x => '-'.repeat(x)).join('  '));
  for (const r of rows) console.log(line(cols.map(c => r[c] ?? '')));
}

switch (cmd) {
  case 'projects':
    table(q(`SELECT p.id, p.name, p.client,
      (SELECT COUNT(*) FROM assets a WHERE a.project_id=p.id) AS assets FROM projects p ORDER BY p.id`).all(),
      ['id', 'name', 'client', 'assets']);
    break;

  case 'new-project': {
    if (!args[1]) { console.error('name required'); process.exit(1); }
    const info = q(`INSERT INTO projects (name, client) VALUES (?,?)`).run(args[1], args[2] || null);
    console.log(`Created project #${info.lastInsertRowid}: ${args[1]}`);
    break;
  }

  case 'types':
    table(q(`SELECT t.type, t.label, t.hint AS example,
             (SELECT COUNT(*) FROM tpl_items i WHERE i.type=t.type) AS items
             FROM tpl_types t ORDER BY t.sort, t.type`).all(), ['type', 'label', 'example', 'items']);
    break;

  case 'assets':
    if (!args[1]) { console.error('projectId required'); process.exit(1); }
    table(q(`SELECT f.id, f.grp, f.label,
             (SELECT COUNT(*) FROM assets a WHERE a.folder_id=f.id) AS targets
             FROM folders f WHERE f.project_id=? ORDER BY f.id`).all(args[1]), ['id', 'grp', 'label', 'targets']);
    break;

  case 'add-asset': {
    const [, pid, grp, ...rest] = args;
    const label = rest.join(' ');
    const GRPS = ['internal', 'external', 'mobile', 'wireless', 'otiot', 'additional'];
    if (!pid || !grp || !label) { console.error('usage: add-asset <projectId> <engagement-type> <name>\n  engagement-type: ' + GRPS.join(' | ')); process.exit(1); }
    if (!GRPS.includes(grp)) { console.error(`unknown engagement type "${grp}". Try: ${GRPS.join(', ')}`); process.exit(1); }
    const selectable = new Set(q(`SELECT DISTINCT grp FROM tpl_types WHERE soon=0 AND grp IS NOT NULL`).all().map(r => r.grp));
    if (!selectable.has(grp)) { console.error(`engagement type "${grp}" is coming soon`); process.exit(1); }
    if (!q(`SELECT id FROM projects WHERE id=?`).get(pid)) { console.error('project not found'); process.exit(1); }
    const info = q(`INSERT INTO folders (project_id, grp, label) VALUES (?,?,?)`).run(pid, grp, label);
    console.log(`Added ${grp} asset #${info.lastInsertRowid} "${label}". Add targets with: add-target ${info.lastInsertRowid} <type> <identifier>`);
    break;
  }

  case 'targets':
    if (!args[1]) { console.error('assetId required'); process.exit(1); }
    table(q(`SELECT id, type, label FROM assets WHERE folder_id=? ORDER BY id`).all(args[1]), ['id', 'type', 'label']);
    break;

  case 'add-target': {
    const [, fid, type, ...rest] = args;
    const label = rest.join(' ');
    if (!fid || !type || !label) { console.error('usage: add-target <assetId> <type> <identifier>'); process.exit(1); }
    const folder = q(`SELECT * FROM folders WHERE id=?`).get(fid);
    if (!folder) { console.error('asset not found'); process.exit(1); }
    const t = q(`SELECT type, soon, grp FROM tpl_types WHERE type=?`).get(type);
    if (!t) { console.error(`unknown type "${type}". See: magi types`); process.exit(1); }
    if (t.soon) { console.error(`type "${type}" is coming soon`); process.exit(1); }
    if (t.grp && t.grp !== folder.grp) { console.error(`a ${type} target does not belong in a ${folder.grp} asset`); process.exit(1); }
    const info = q(`INSERT INTO assets (project_id, folder_id, type, label) VALUES (?,?,?,?)`).run(folder.project_id, folder.id, type, label);
    const aid = info.lastInsertRowid;
    const stmt = q(`INSERT INTO items (asset_id, group_key, group_title, title, detail, payloads, kind, spawns, catalog, options, sort)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)`);
    const rows = q(`SELECT * FROM tpl_items WHERE type=? ORDER BY sort, id`).all(type);
    for (const r of rows) stmt.run(aid, r.group_key, r.group_title, r.title, r.detail, r.payloads,
      r.kind, r.spawns, r.catalog, r.options, r.sort);
    console.log(`Added ${type} target #${aid} "${label}" with ${rows.length} checklist items.`);
    break;
  }

  case 'show': {
    const a = q(`SELECT * FROM assets WHERE id=?`).get(args[1]);
    if (!a) { console.error('asset not found'); process.exit(1); }
    console.log(`\n  ${a.type.toUpperCase()} — ${a.label}\n`);
    const items = q(`SELECT * FROM items WHERE asset_id=? ORDER BY sort`).all(a.id);
    const mark = { done: '[x]', na: '[-]', flag: '[!]', yes: '[Y]', no: '[N]', todo: '[ ]' };
    let g = null;
    for (const i of items) {
      if (i.group_title !== g) { console.log(`\n  ${i.group_title}`); g = i.group_title; }
      console.log(`   ${mark[i.status] || '[ ]'} #${i.id} ${i.title}${i.answer ? '  => ' + i.answer : ''}`);
    }
    console.log();
    break;
  }

  case 'set': {
    const [, itemId, status] = args;
    const ok = ['todo', 'done', 'na', 'flag', 'yes', 'no'];
    if (!ok.includes(status)) { console.error('status must be: ' + ok.join('|')); process.exit(1); }
    const r = q(`UPDATE items SET status=? WHERE id=?`).run(status, itemId);
    console.log(r.changes ? `Item #${itemId} -> ${status}` : 'item not found');
    break;
  }

  case 'export': {
    const p = q(`SELECT * FROM projects WHERE id=?`).get(args[1]);
    if (!p) { console.error('project not found'); process.exit(1); }
    const icon = { done: '✅', na: '➖', flag: '🚩', yes: '✔️', no: '✖️', todo: '⬜' };
    let out = `# ${p.name}\n`;
    for (const a of q(`SELECT * FROM assets WHERE project_id=? ORDER BY id`).all(p.id)) {
      out += `\n## ${a.type.toUpperCase()} — ${a.label}\n`;
      const items = q(`SELECT * FROM items WHERE asset_id=? ORDER BY sort, id`).all(a.id);
      const kids = {};
      for (const i of items) if (i.parent_id != null) (kids[i.parent_id] ||= []).push(i);
      const line = (i, d) => `${'  '.repeat(d)}- ${icon[i.status] || '⬜'} ${i.title}`
        + (i.answer ? ' — _' + i.answer + '_' : '') + '\n'
        + (kids[i.id] || []).map(k => line(k, d + 1)).join('');
      let g = null;
      for (const i of items.filter(x => x.parent_id == null)) {
        if (i.group_key !== g) { out += `\n### ${i.group_title}\n`; g = i.group_key; }
        out += line(i, 0);
      }
    }
    console.log(out);
    break;
  }

  // Destructive and unrecoverable, so it is a two-step: describe, then --yes to commit.
  case 'rm-project': {
    const p = q(`SELECT * FROM projects WHERE id=?`).get(args[1]);
    if (!p) { console.error('project not found'); process.exit(1); }
    const assets = q(`SELECT id,type,label FROM assets WHERE project_id=? ORDER BY id`).all(p.id);
    const items = q(`SELECT COUNT(*) c FROM items WHERE asset_id IN (SELECT id FROM assets WHERE project_id=?)`).get(p.id).c;
    const finds = q(`SELECT COUNT(*) c FROM findings WHERE asset_id IN (SELECT id FROM assets WHERE project_id=?)`).get(p.id).c;
    console.log(`\nProject #${p.id} "${p.name}"${p.client ? ' (' + p.client + ')' : ''}`);
    console.log(`  ${assets.length} target(s), ${items} checklist item(s), ${finds} finding(s)`);
    for (const a of assets) console.log(`    - #${a.id} ${a.type} ${a.label}`);
    if (!args.includes('--yes')) {
      console.log(`\nNothing deleted. Re-run with --yes to delete permanently:`);
      console.log(`  node cli.js rm-project ${p.id} --yes\n`);
      break;
    }
    q(`DELETE FROM projects WHERE id=?`).run(p.id);
    console.log(`\nDeleted project #${p.id} and everything under it.\n`);
    break;
  }

  case 'rm-asset': {
    const f = q(`SELECT * FROM folders WHERE id=?`).get(args[1]);
    if (!f) { console.error('asset not found'); process.exit(1); }
    const targets = q(`SELECT COUNT(*) c FROM assets WHERE folder_id=?`).get(f.id).c;
    console.log(`\nAsset #${f.id} ${f.grp} "${f.label}" (project #${f.project_id})`);
    console.log(`  ${targets} target(s) and all their checklists/findings`);
    if (!args.includes('--yes')) {
      console.log(`\nNothing deleted. Re-run with --yes to delete permanently:`);
      console.log(`  node cli.js rm-asset ${f.id} --yes\n`);
      break;
    }
    q(`DELETE FROM folders WHERE id=?`).run(f.id);
    console.log(`\nDeleted asset #${f.id} and everything inside it.\n`);
    break;
  }

  case 'rm-target': {
    const a = q(`SELECT * FROM assets WHERE id=?`).get(args[1]);
    if (!a) { console.error('target not found'); process.exit(1); }
    const items = q(`SELECT COUNT(*) c FROM items WHERE asset_id=?`).get(a.id).c;
    const finds = q(`SELECT COUNT(*) c FROM findings WHERE asset_id=?`).get(a.id).c;
    console.log(`\nTarget #${a.id} ${a.type} "${a.label}"`);
    console.log(`  ${items} checklist item(s), ${finds} finding(s)`);
    if (!args.includes('--yes')) {
      console.log(`\nNothing deleted. Re-run with --yes to delete permanently:`);
      console.log(`  node cli.js rm-target ${a.id} --yes\n`);
      break;
    }
    q(`DELETE FROM assets WHERE id=?`).run(a.id);
    console.log(`\nDeleted target #${a.id}.\n`);
    break;
  }

  case 'reseed': {
    const target = args[1];
    if (!target) { console.error('usage: reseed <type|all>   (see: magi types)'); process.exit(1); }
    const types = target === 'all'
      ? q(`SELECT type FROM tpl_types ORDER BY sort, type`).all().map(r => r.type)
      : [target];
    for (const t of types) {
      const n = resetType(t);
      console.log(n === false ? `  ${t}: no shipped defaults, left alone` : `  ${t}: restored ${n} items`);
    }
    console.log('\nExisting assets keep their current checklists; this only affects newly-added assets.');
    break;
  }

  case 'export-project': {
    if (!args[1]) { console.error('usage: export-project <projectId>'); process.exit(1); }
    const bundle = exportProjectBundle(args[1], new Date().toISOString());
    if (!bundle) { console.error('project not found'); process.exit(1); }
    console.log(JSON.stringify(bundle, null, 2));
    break;
  }

  case 'import-project': {
    const file = args[1];
    if (!file) { console.error('usage: import-project <file.json> [new name]'); process.exit(1); }
    let bundle;
    try { bundle = JSON.parse(readFileSync(file, 'utf8')); }
    catch (e) { console.error(`cannot read ${file}: ${e.message}`); process.exit(1); }
    try {
      const r = importProject(bundle, args[2] || null);
      console.log(`Imported project #${r.projectId}: ${r.assets} asset(s), ${r.targets} target(s), ${r.items} item(s), ${r.findings} finding(s).`);
    } catch (e) { console.error(`import failed: ${e.message}`); process.exit(1); }
    break;
  }

  case 'export-templates': {
    const types = args.slice(1);
    const known = q(`SELECT type FROM tpl_types`).all().map(r => r.type);
    for (const t of types) if (!known.includes(t)) { console.error(`unknown type "${t}"`); process.exit(1); }
    const bundle = exportBundle(types.length ? types : null, new Date().toISOString());
    if (!bundle.types.length) { console.error('no templates to export'); process.exit(1); }
    console.log(JSON.stringify(bundle, null, 2));
    break;
  }

  case 'import-templates': {
    const file = args[1];
    if (!file) { console.error('usage: import-templates <file.json> [--replace | --rename]'); process.exit(1); }
    const onConflict = args.includes('--replace') ? 'replace' : args.includes('--rename') ? 'rename' : 'skip';
    let bundle;
    try { bundle = JSON.parse(readFileSync(file, 'utf8')); }
    catch (e) { console.error(`cannot read ${file}: ${e.message}`); process.exit(1); }
    try {
      const results = importBundle(bundle, onConflict);
      for (const r of results) console.log(`  ${r.type}: ${r.action}${r.as ? ' ' + r.as : ''}`);
      console.log('\nNewly-added assets of these types use the imported checklist; existing assets are unchanged.');
    } catch (e) { console.error(`import failed: ${e.message}`); process.exit(1); }
    break;
  }

  default:
    help();
}
