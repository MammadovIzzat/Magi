import express from 'express';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { db, hashPassword, verifyPassword, resetType, SESSION_TTL_DAYS, env, usingDefaultPassword } from './db.js';
import { exportBundle, importBundle, validateBundle } from './templates-io.js';
import { exportProject as exportProjectBundle, importProject, validateProjectBundle } from './projects-io.js';
import { projectReportHTML } from './report-html.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
app.set('trust proxy', false); // req.ip must not be spoofable via X-Forwarded-For (login throttling uses it)
app.disable('x-powered-by');

// Magi stores credentials and raw requests, so it defaults to localhost only.
const PORT = env('PORT', process.env.PORT || 4173);
const HOST = env('HOST', '127.0.0.1');

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
  next();
});
// Generous limit: a project import carries its screenshots inline as base64, and this
// is a local single-user tool, not a public endpoint. Raw image uploads have their own
// tighter per-file cap below.
app.use(express.json({ limit: '64mb' }));

// A packaged build has no public/ on disk: build/build.mjs compiles those files into
// the bundle and its entry point sets globalThis.__MAGI_ASSETS before this module runs.
// Read it per request rather than at import time so module evaluation order cannot
// matter, and always leave express.static mounted behind it for source checkouts.
app.use((req, res, next) => {
  const embedded = globalThis.__MAGI_ASSETS;
  if (!embedded || req.method !== 'GET') return next();
  const file = embedded[req.path === '/' ? '/index.html' : req.path];
  if (!file) return next();
  res.type(file.type);
  res.setHeader('Cache-Control', req.path.startsWith('/fonts/') ? 'public, max-age=604800' : 'no-cache');
  res.end(file.body);
});
app.use(express.static(join(__dirname, 'public')));

// ---- helpers ----
const q = (sql) => db.prepare(sql);
function assetSummary(row) { return { ...row, metadata: JSON.parse(row.metadata || '{}') }; }
// Optional-string field update: absent key keeps the current value, empty string clears it.
// (`b.x ?? cur.x` alone makes a set value impossible to unset.)
function blank(next, cur) { return next === undefined ? cur : (next || null); }

// ---- auth ----
function parseCookies(req) {
  const out = {};
  for (const p of (req.headers.cookie || '').split(';')) {
    const i = p.indexOf('='); if (i < 0) continue;
    out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  }
  return out;
}
function currentUser(req) {
  const sid = parseCookies(req).sid;
  if (!sid) return null;
  // expiry is enforced here, not just by the cookie's Max-Age (which the client controls)
  return q(`SELECT u.id, u.username FROM sessions s JOIN users u ON u.id=s.user_id
            WHERE s.token=? AND s.created_at > datetime('now', '-${SESSION_TTL_DAYS} days')`).get(sid) || null;
}
function sessionCookie(req, token, maxAge) {
  const secure = req.secure || req.headers['x-forwarded-proto'] === 'https' ? ' Secure;' : '';
  return `sid=${token}; HttpOnly;${secure} SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}

// Defence in depth against CSRF alongside SameSite=Strict: a cross-site form post
// carries an Origin header, and a same-origin XHR from our own page matches Host.
app.use('/api', (req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const origin = req.headers.origin;
  if (origin) {
    let host;
    try { host = new URL(origin).host; } catch { return res.status(403).json({ error: 'bad origin' }); }
    if (host !== req.headers.host) return res.status(403).json({ error: 'cross-origin request refused' });
  }
  next();
});

// gate every /api route except the auth handshake
app.use('/api', (req, res, next) => {
  if (req.path === '/auth/login' || req.path === '/me') return next();
  if (!currentUser(req)) return res.status(401).json({ error: 'unauthorized' });
  next();
});

// --- login throttling ---
// In-memory, per username+IP. Enough to stop online brute force against a tool that
// is meant to be bound to localhost; it resets on restart by design.
const attempts = new Map();
const LOCK_AFTER = 8, LOCK_MS = 15 * 60 * 1000;
function throttleKey(req, username) { return `${req.ip}|${(username || '').toLowerCase()}`; }
function lockedFor(key) {
  const a = attempts.get(key);
  if (!a || a.count < LOCK_AFTER) return 0;
  const left = a.until - Date.now();
  if (left <= 0) { attempts.delete(key); return 0; }
  return Math.ceil(left / 1000);
}
function noteFailure(key) {
  const a = attempts.get(key) || { count: 0, until: 0 };
  a.count++;
  if (a.count >= LOCK_AFTER) a.until = Date.now() + LOCK_MS;
  attempts.set(key, a);
}

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  const key = throttleKey(req, username);
  const wait = lockedFor(key);
  if (wait) return res.status(429).json({ error: `too many attempts — try again in ${Math.ceil(wait / 60)} min` });

  const u = q(`SELECT * FROM users WHERE username=?`).get(username || '');
  if (!u || !verifyPassword(password || '', u.pass_hash)) {
    noteFailure(key);
    return res.status(401).json({ error: 'invalid credentials' });
  }
  attempts.delete(key);
  const token = randomBytes(32).toString('hex');
  q(`INSERT INTO sessions (token, user_id) VALUES (?,?)`).run(token, u.id);
  res.setHeader('Set-Cookie', sessionCookie(req, token, 60 * 60 * 24 * SESSION_TTL_DAYS));
  res.json({ username: u.username });
});
app.post('/api/auth/logout', (req, res) => {
  const sid = parseCookies(req).sid;
  if (sid) q(`DELETE FROM sessions WHERE token=?`).run(sid);
  res.setHeader('Set-Cookie', sessionCookie(req, '', 0));
  res.json({ ok: true });
});
app.get('/api/me', (req, res) => {
  const u = currentUser(req);
  if (!u) {
    // Only ever surfaced in the desktop app, which opens no port — never over HTTP.
    const hint = process.env.MAGI_EMBED === '1' && usingDefaultPassword() ? 'admin / admin' : undefined;
    return res.status(401).json({ error: 'unauthorized', hint });
  }
  res.json({ username: u.username });
});
app.post('/api/change-password', (req, res) => {
  const u = currentUser(req);
  const { current, next } = req.body || {};
  const row = q(`SELECT * FROM users WHERE id=?`).get(u.id);
  if (!verifyPassword(current || '', row.pass_hash)) return res.status(400).json({ error: 'current password is wrong' });
  if (!next || next.length < 10) return res.status(400).json({ error: 'new password must be at least 10 characters' });
  if (next === current) return res.status(400).json({ error: 'new password must differ from the current one' });
  q(`UPDATE users SET pass_hash=? WHERE id=?`).run(hashPassword(next), u.id);
  // a password change should end every other session, not just rotate this one
  const sid = parseCookies(req).sid;
  q(`DELETE FROM sessions WHERE user_id=? AND token<>?`).run(u.id, sid);
  res.json({ ok: true });
});

const insertItem = q(`INSERT INTO items
  (asset_id, parent_id, group_key, group_title, title, detail, payloads, kind, spawns, catalog, options, opt_key, sort)
  VALUES (@asset_id,@parent_id,@group_key,@group_title,@title,@detail,@payloads,@kind,@spawns,@catalog,@options,@opt_key,@sort)`);
function addItem(assetId, r) {
  insertItem.run({
    asset_id: assetId, parent_id: r.parent_id ?? null,
    group_key: r.group_key, group_title: r.group_title, title: r.title, detail: r.detail || '',
    payloads: r.payloads ?? '[]', kind: r.kind || 'check', spawns: r.spawns ?? null,
    catalog: r.catalog ?? null, options: r.options ?? '[]', opt_key: r.opt_key ?? null, sort: r.sort ?? 0,
  });
}
// delete an item and all of its descendants (tree)
function deleteItemTree(id) {
  for (const c of q(`SELECT id FROM items WHERE parent_id=?`).all(id)) deleteItemTree(c.id);
  q(`DELETE FROM items WHERE id=?`).run(id);
}

// instantiate a new asset's checklist from the editable DB templates
function tplRows(type) {
  return q(`SELECT * FROM tpl_items WHERE type=? ORDER BY sort, id`).all(type);
}
// a spawn group / catalog entry plus its items, from the editable DB templates
function tplGroup(type, kind, catalog, gkey) {
  const g = q(`SELECT * FROM tpl_groups WHERE type=? AND kind=? AND catalog=? AND gkey=?`)
    .get(type, kind, catalog || '', gkey);
  if (!g) return null;
  return { ...g, items: q(`SELECT * FROM tpl_group_items WHERE group_id=? ORDER BY sort, id`).all(g.id) };
}
function createAssetWithItems(projectId, type, label, metadata = {}) {
  const info = q(`INSERT INTO assets (project_id, type, label, metadata) VALUES (?,?,?,?)`)
    .run(projectId, type, label, JSON.stringify(metadata));
  const assetId = info.lastInsertRowid;
  for (const r of tplRows(type)) addItem(assetId, {
    group_key: r.group_key, group_title: r.group_title, title: r.title, detail: r.detail,
    payloads: r.payloads, kind: r.kind, spawns: r.spawns, catalog: r.catalog, options: r.options, sort: r.sort,
  });
  return assetId;
}

// ---- meta ----
app.get('/api/asset-types', (req, res) => {
  const types = q(`SELECT * FROM tpl_types ORDER BY sort, type`).all();
  res.json(types.map(t => ({
    type: t.type, label: t.label, icon: t.icon, hint: t.hint,
    groups: [...new Set(tplRows(t.type).map(i => i.group_title))],
  })));
});

// ---- template editor (default checklists + asset types) ----
// ---- share templates (portable import/export, no engagement data) ----
// Registered before /api/templates/:type so "export" is not read as a type name.
app.get('/api/templates/export', (req, res) => {
  const types = req.query.types ? String(req.query.types).split(',').filter(Boolean) : null;
  const bundle = exportBundle(types, new Date().toISOString());
  if (!bundle.types.length) return res.status(404).json({ error: 'no matching templates' });
  const name = types && types.length === 1 ? `magi-template-${types[0]}` : 'magi-templates';
  res.setHeader('Content-Disposition', `attachment; filename="${name}.json"`);
  res.type('application/json').send(JSON.stringify(bundle, null, 2));
});

app.get('/api/templates', (req, res) => {
  const types = q(`SELECT t.*, (SELECT COUNT(*) FROM tpl_items i WHERE i.type=t.type) AS item_count
                   FROM tpl_types t ORDER BY sort, type`).all();
  res.json(types);
});
app.get('/api/templates/:type', (req, res) => {
  const t = q(`SELECT * FROM tpl_types WHERE type=?`).get(req.params.type);
  if (!t) return res.status(404).json({ error: 'not found' });
  const items = q(`SELECT * FROM tpl_items WHERE type=? ORDER BY sort, id`).all(req.params.type)
    .map(i => ({ ...i, payloads: JSON.parse(i.payloads || '[]'), options: JSON.parse(i.options || '[]') }));
  const groups = q(`SELECT g.*, (SELECT COUNT(*) FROM tpl_group_items i WHERE i.group_id=g.id) AS item_count
                    FROM tpl_groups g WHERE g.type=? ORDER BY g.kind, g.catalog, g.sort, g.id`).all(t.type);
  const catalogs = [...new Set(groups.filter(g => g.kind === 'catalog').map(g => g.catalog))];
  res.json({ ...t, catalogs, groups, items });
});

// ---- follow-up checklists (trigger spawns) & catalogs (select options) ----
app.get('/api/tpl-groups/:id', (req, res) => {
  const g = q(`SELECT * FROM tpl_groups WHERE id=?`).get(req.params.id);
  if (!g) return res.status(404).json({ error: 'not found' });
  const items = q(`SELECT * FROM tpl_group_items WHERE group_id=? ORDER BY sort, id`).all(g.id)
    .map(i => ({ ...i, payloads: JSON.parse(i.payloads || '[]') }));
  res.json({ ...g, items });
});
app.post('/api/templates/:type/groups', (req, res) => {
  if (!q(`SELECT type FROM tpl_types WHERE type=?`).get(req.params.type)) return res.status(404).json({ error: 'type not found' });
  const b = req.body || {};
  const kind = b.kind === 'catalog' ? 'catalog' : 'spawn';
  const catalog = kind === 'catalog' ? (b.catalog || '') : '';
  if (!b.gkey || !/^[a-z0-9_]+$/.test(b.gkey)) return res.status(400).json({ error: 'key must be lowercase letters/numbers/underscore' });
  if (kind === 'catalog' && !/^[a-z0-9_]+$/.test(catalog)) return res.status(400).json({ error: 'catalog name must be lowercase letters/numbers/underscore' });
  if (!b.title) return res.status(400).json({ error: 'title required' });
  if (q(`SELECT id FROM tpl_groups WHERE type=? AND kind=? AND catalog=? AND gkey=?`).get(req.params.type, kind, catalog, b.gkey))
    return res.status(409).json({ error: 'that key already exists for this type' });
  const sort = q(`SELECT COALESCE(MAX(sort),0)+1 s FROM tpl_groups WHERE type=?`).get(req.params.type).s;
  const info = q(`INSERT INTO tpl_groups (type,kind,catalog,gkey,title,sort) VALUES (?,?,?,?,?,?)`)
    .run(req.params.type, kind, catalog, b.gkey, b.title, sort);
  res.status(201).json(q(`SELECT * FROM tpl_groups WHERE id=?`).get(info.lastInsertRowid));
});
app.patch('/api/tpl-groups/:id', (req, res) => {
  const g = q(`SELECT * FROM tpl_groups WHERE id=?`).get(req.params.id);
  if (!g) return res.status(404).json({ error: 'not found' });
  q(`UPDATE tpl_groups SET title=? WHERE id=?`).run((req.body || {}).title || g.title, g.id);
  res.json(q(`SELECT * FROM tpl_groups WHERE id=?`).get(g.id));
});
app.delete('/api/tpl-groups/:id', (req, res) => {
  q(`DELETE FROM tpl_group_items WHERE group_id=?`).run(req.params.id); // explicit: older DBs may lack the FK
  q(`DELETE FROM tpl_groups WHERE id=?`).run(req.params.id);
  res.json({ ok: true });
});
app.post('/api/tpl-groups/:id/items', (req, res) => {
  const g = q(`SELECT * FROM tpl_groups WHERE id=?`).get(req.params.id);
  if (!g) return res.status(404).json({ error: 'group not found' });
  const b = req.body || {};
  if (!b.title) return res.status(400).json({ error: 'title required' });
  const sort = q(`SELECT COALESCE(MAX(sort),0)+1 s FROM tpl_group_items WHERE group_id=?`).get(g.id).s;
  const info = q(`INSERT INTO tpl_group_items (group_id,title,detail,payloads,kind,spawns,sort) VALUES (?,?,?,?,?,?,?)`)
    .run(g.id, b.title, b.detail || '', JSON.stringify(b.payloads || []), b.kind || 'check', b.spawns || null, sort);
  res.status(201).json(q(`SELECT * FROM tpl_group_items WHERE id=?`).get(info.lastInsertRowid));
});
app.patch('/api/tpl-group-items/:id', (req, res) => {
  const cur = q(`SELECT * FROM tpl_group_items WHERE id=?`).get(req.params.id);
  if (!cur) return res.status(404).json({ error: 'not found' });
  const b = req.body || {};
  q(`UPDATE tpl_group_items SET title=?, detail=?, payloads=?, kind=?, spawns=?, sort=? WHERE id=?`)
    .run(b.title ?? cur.title, b.detail ?? cur.detail,
      Array.isArray(b.payloads) ? JSON.stringify(b.payloads) : cur.payloads,
      b.kind ?? cur.kind, blank(b.spawns, cur.spawns), b.sort ?? cur.sort, cur.id);
  res.json(q(`SELECT * FROM tpl_group_items WHERE id=?`).get(cur.id));
});
app.delete('/api/tpl-group-items/:id', (req, res) => {
  q(`DELETE FROM tpl_group_items WHERE id=?`).run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/templates/:type/export', (req, res) => {
  const bundle = exportBundle([req.params.type], new Date().toISOString());
  if (!bundle.types.length) return res.status(404).json({ error: 'type not found' });
  res.setHeader('Content-Disposition', `attachment; filename="magi-template-${req.params.type}.json"`);
  res.type('application/json').send(JSON.stringify(bundle, null, 2));
});
// Preview what an uploaded bundle would do without touching the DB.
app.post('/api/templates/import/preview', (req, res) => {
  try {
    const b = validateBundle(req.body);
    res.json({
      version: b.version, exported: b.exported || null,
      types: b.types.map(t => ({
        type: t.type, label: t.label, icon: t.icon,
        items: (t.items || []).length,
        groups: (t.groups || []).length,
        exists: !!q(`SELECT type FROM tpl_types WHERE type=?`).get(t.type),
      })),
    });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.post('/api/templates/import', (req, res) => {
  const { bundle, onConflict } = req.body || {};
  try {
    const results = importBundle(bundle, ['skip', 'replace', 'rename'].includes(onConflict) ? onConflict : 'skip');
    res.json({ ok: true, results });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// restore this type's shipped defaults (template edits are discarded; assets untouched)
app.post('/api/templates/:type/reset', (req, res) => {
  if (!q(`SELECT type FROM tpl_types WHERE type=?`).get(req.params.type)) return res.status(404).json({ error: 'type not found' });
  const n = resetType(req.params.type);
  if (n === false) return res.status(400).json({ error: 'this type has no shipped defaults to restore' });
  res.json({ ok: true, items: n });
});
app.post('/api/templates', (req, res) => {
  const { type, label, icon, hint } = req.body || {};
  if (!type || !/^[a-z0-9_]+$/.test(type)) return res.status(400).json({ error: 'type must be lowercase letters/numbers/underscore' });
  if (!label) return res.status(400).json({ error: 'label required' });
  if (q(`SELECT type FROM tpl_types WHERE type=?`).get(type)) return res.status(409).json({ error: 'type already exists' });
  const sort = q(`SELECT COALESCE(MAX(sort),0)+1 s FROM tpl_types`).get().s;
  q(`INSERT INTO tpl_types (type,label,icon,hint,sort) VALUES (?,?,?,?,?)`).run(type, label, icon || null, hint || null, sort);
  res.status(201).json(q(`SELECT * FROM tpl_types WHERE type=?`).get(type));
});
app.patch('/api/templates/:type', (req, res) => {
  const t = q(`SELECT * FROM tpl_types WHERE type=?`).get(req.params.type);
  if (!t) return res.status(404).json({ error: 'not found' });
  const b = req.body || {};
  q(`UPDATE tpl_types SET label=?, icon=?, hint=? WHERE type=?`)
    .run(b.label ?? t.label, b.icon ?? t.icon, b.hint ?? t.hint, t.type);
  res.json(q(`SELECT * FROM tpl_types WHERE type=?`).get(t.type));
});
app.delete('/api/templates/:type', (req, res) => {
  q(`DELETE FROM tpl_items WHERE type=?`).run(req.params.type);
  q(`DELETE FROM tpl_types WHERE type=?`).run(req.params.type);
  res.json({ ok: true });
});
app.post('/api/templates/:type/items', (req, res) => {
  const t = q(`SELECT type FROM tpl_types WHERE type=?`).get(req.params.type);
  if (!t) return res.status(404).json({ error: 'type not found' });
  const b = req.body || {};
  if (!b.title) return res.status(400).json({ error: 'title required' });
  const sort = q(`SELECT COALESCE(MAX(sort),0)+1 s FROM tpl_items WHERE type=?`).get(req.params.type).s;
  const info = q(`INSERT INTO tpl_items (type,group_key,group_title,title,detail,payloads,kind,spawns,catalog,options,sort)
                  VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(
    req.params.type, (b.group_title || 'Custom').toLowerCase().replace(/\s+/g, '_'), b.group_title || 'Custom',
    b.title, b.detail || '', JSON.stringify(b.payloads || []), b.kind || 'check',
    b.spawns || null, b.catalog || null, JSON.stringify(b.options || []), sort);
  res.status(201).json(q(`SELECT * FROM tpl_items WHERE id=?`).get(info.lastInsertRowid));
});
app.patch('/api/tpl-items/:id', (req, res) => {
  const cur = q(`SELECT * FROM tpl_items WHERE id=?`).get(req.params.id);
  if (!cur) return res.status(404).json({ error: 'not found' });
  const b = req.body || {};
  const payloads = Array.isArray(b.payloads) ? JSON.stringify(b.payloads) : cur.payloads;
  const options = Array.isArray(b.options) ? JSON.stringify(b.options) : cur.options;
  const gt = b.group_title ?? cur.group_title;
  q(`UPDATE tpl_items SET group_title=?, group_key=?, title=?, detail=?, payloads=?, kind=?, spawns=?, catalog=?, options=?, sort=? WHERE id=?`)
    .run(gt, gt.toLowerCase().replace(/\s+/g, '_'), b.title ?? cur.title, b.detail ?? cur.detail,
      payloads, b.kind ?? cur.kind, blank(b.spawns, cur.spawns), blank(b.catalog, cur.catalog), options,
      b.sort ?? cur.sort, req.params.id);
  res.json(q(`SELECT * FROM tpl_items WHERE id=?`).get(req.params.id));
});
app.delete('/api/tpl-items/:id', (req, res) => {
  q(`DELETE FROM tpl_items WHERE id=?`).run(req.params.id);
  res.json({ ok: true });
});

// ---- projects ----
// The engagements table shows coverage and finding counts, so roll them up here
// rather than making the client fetch every project.
app.get('/api/projects', (req, res) => {
  res.json(q(`SELECT p.*,
      (SELECT COUNT(*) FROM assets a WHERE a.project_id=p.id) AS asset_count,
      (SELECT COUNT(*) FROM findings f JOIN assets a ON a.id=f.asset_id WHERE a.project_id=p.id) AS finding_count,
      (SELECT COUNT(*) FROM items i JOIN assets a ON a.id=i.asset_id
         WHERE a.project_id=p.id AND i.kind NOT IN ('select','group')) AS total,
      (SELECT COUNT(*) FROM items i JOIN assets a ON a.id=i.asset_id
         WHERE a.project_id=p.id AND i.kind NOT IN ('select','group')
           AND i.status IN ('done','na','yes','no')) AS handled
      FROM projects p ORDER BY p.created_at DESC`).all());
});

app.post('/api/projects', (req, res) => {
  const { name, client, scope, notes } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name required' });
  const info = q(`INSERT INTO projects (name, client, scope, notes) VALUES (?,?,?,?)`)
    .run(name, client || null, scope || null, notes || null);
  res.status(201).json(q(`SELECT * FROM projects WHERE id=?`).get(info.lastInsertRowid));
});

// ---- move a whole engagement between installs (contains client-confidential data) ----
app.get('/api/projects/:id/bundle', (req, res) => {
  const bundle = exportProjectBundle(req.params.id, new Date().toISOString());
  if (!bundle) return res.status(404).json({ error: 'not found' });
  const safe = (bundle.project.name || 'project').replace(/[^a-z0-9._-]+/gi, '-').slice(0, 60);
  res.setHeader('Content-Disposition', `attachment; filename="magi-project-${safe}.json"`);
  res.type('application/json').send(JSON.stringify(bundle, null, 2));
});
app.post('/api/projects/import/preview', (req, res) => {
  try {
    const b = validateProjectBundle(req.body);
    res.json({
      version: b.version, exported: b.exported || null,
      name: b.project.name, client: b.project.client || null,
      assets: (b.assets || []).length,
      items: (b.assets || []).reduce((n, a) => n + (a.items || []).length, 0),
      findings: (b.assets || []).reduce((n, a) => n + (a.findings || []).length, 0),
    });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
app.post('/api/projects/import', (req, res) => {
  const { bundle, name } = req.body || {};
  try {
    const r = importProject(bundle, name && String(name).trim() ? String(name).trim() : null);
    res.status(201).json({ ok: true, ...r });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.get('/api/projects/:id', (req, res) => {
  const p = q(`SELECT * FROM projects WHERE id=?`).get(req.params.id);
  if (!p) return res.status(404).json({ error: 'not found' });
  // counts exclude select/group containers — they are structure, not work
  const assets = q(`SELECT a.*,
      (SELECT COUNT(*) FROM items i WHERE i.asset_id=a.id AND i.kind NOT IN ('select','group')) AS total,
      (SELECT COUNT(*) FROM items i WHERE i.asset_id=a.id AND i.kind NOT IN ('select','group')
         AND i.status IN ('done','na','yes','no')) AS handled,
      (SELECT COUNT(*) FROM items i WHERE i.asset_id=a.id AND i.status='flag') AS flags,
      (SELECT COUNT(*) FROM findings f WHERE f.asset_id=a.id) AS findings
      FROM assets a WHERE a.project_id=? ORDER BY a.created_at`).all(req.params.id);
  res.json({ ...p, assets: assets.map(assetSummary) });
});

// Cascades to assets -> items/findings via the schema's ON DELETE CASCADE.
app.delete('/api/projects/:id', (req, res) => {
  const p = q(`SELECT id FROM projects WHERE id=?`).get(req.params.id);
  if (!p) return res.status(404).json({ error: 'not found' });
  const assets = q(`SELECT COUNT(*) c FROM assets WHERE project_id=?`).get(p.id).c;
  q(`DELETE FROM projects WHERE id=?`).run(p.id);
  res.json({ ok: true, assets });
});

// ---- assets ----
app.post('/api/projects/:id/assets', (req, res) => {
  const p = q(`SELECT id FROM projects WHERE id=?`).get(req.params.id);
  if (!p) return res.status(404).json({ error: 'project not found' });
  const { type, label, metadata } = req.body || {};
  // validate against the editable types, not the seed file — otherwise asset types
  // created in the template editor can be listed but never used
  if (!q(`SELECT type FROM tpl_types WHERE type=?`).get(type || '')) return res.status(400).json({ error: 'unknown asset type' });
  if (!label) return res.status(400).json({ error: 'label required' });
  const id = createAssetWithItems(req.params.id, type, label, metadata || {});
  res.status(201).json(assetSummary(q(`SELECT * FROM assets WHERE id=?`).get(id)));
});

app.get('/api/assets/:id', (req, res) => {
  const a = q(`SELECT * FROM assets WHERE id=?`).get(req.params.id);
  if (!a) return res.status(404).json({ error: 'not found' });
  const items = q(`SELECT * FROM items WHERE asset_id=? ORDER BY sort, id`).all(req.params.id)
    .map(i => ({ ...i, payloads: JSON.parse(i.payloads || '[]'), options: JSON.parse(i.options || '[]') }));
  const findings = q(`SELECT * FROM findings WHERE asset_id=? ORDER BY created_at DESC`).all(req.params.id)
    .map(f => ({ ...f, attachments: q(`SELECT id, filename, mime, size FROM attachments WHERE finding_id=? ORDER BY id`).all(f.id) }));
  res.json({ ...assetSummary(a), items, findings });
});

app.delete('/api/assets/:id', (req, res) => {
  const a = q(`SELECT id FROM assets WHERE id=?`).get(req.params.id);
  if (!a) return res.status(404).json({ error: 'not found' });
  const items = q(`SELECT COUNT(*) c FROM items WHERE asset_id=?`).get(a.id).c;
  const findings = q(`SELECT COUNT(*) c FROM findings WHERE asset_id=?`).get(a.id).c;
  q(`DELETE FROM assets WHERE id=?`).run(a.id);
  res.json({ ok: true, items, findings });
});

// ---- items ----
app.patch('/api/items/:id', (req, res) => {
  const cur = q(`SELECT * FROM items WHERE id=?`).get(req.params.id);
  if (!cur) return res.status(404).json({ error: 'not found' });
  const b = req.body || {};
  const status = b.status ?? cur.status;
  const answer = b.answer ?? cur.answer;
  const title = b.title ?? cur.title;
  const detail = b.detail ?? cur.detail;
  const group_title = b.group_title ?? cur.group_title;
  const kind = b.kind ?? cur.kind;
  // changing away from select/trigger would strand the children it unfolded
  if (kind !== cur.kind && ['select', 'trigger'].includes(cur.kind)
      && q(`SELECT COUNT(*) c FROM items WHERE parent_id=?`).get(cur.id).c) {
    return res.status(400).json({ error: `remove this ${cur.kind}'s follow-up items before changing its kind` });
  }
  const payloads = Array.isArray(b.payloads) ? JSON.stringify(b.payloads) : cur.payloads;
  q(`UPDATE items SET status=?, answer=?, title=?, detail=?, group_title=?, kind=?, payloads=? WHERE id=?`)
    .run(status, answer, title, detail, group_title, kind, payloads, req.params.id);
  res.json(q(`SELECT * FROM items WHERE id=?`).get(req.params.id));
});

app.post('/api/assets/:id/items', (req, res) => {
  const a = q(`SELECT id FROM assets WHERE id=?`).get(req.params.id);
  if (!a) return res.status(404).json({ error: 'asset not found' });
  const { title, detail, group_title, payloads, kind, parent_id } = req.body || {};
  if (!title) return res.status(400).json({ error: 'title required' });
  const parent = parent_id ? q(`SELECT * FROM items WHERE id=? AND asset_id=?`).get(parent_id, req.params.id) : null;
  const maxSort = q(`SELECT COALESCE(MAX(sort),0)+1 AS s FROM items WHERE asset_id=?`).get(req.params.id).s;
  const info = insertItem.run({
    asset_id: req.params.id, parent_id: parent ? parent.id : null,
    group_key: parent ? parent.group_key : 'custom', group_title: parent ? parent.group_title : (group_title || 'Custom / Notes'),
    title, detail: detail || '', payloads: JSON.stringify(payloads || []), kind: kind || 'check',
    spawns: null, catalog: null, options: '[]', opt_key: null, sort: maxSort,
  });
  q(`UPDATE items SET is_custom=1 WHERE id=?`).run(info.lastInsertRowid);
  res.status(201).json(q(`SELECT * FROM items WHERE id=?`).get(info.lastInsertRowid));
});

// Spawn a follow-up checklist under a trigger. Can be added multiple times; each
// instance is a deletable container ('group') nested under the trigger.
app.post('/api/items/:id/spawn', (req, res) => {
  const it = q(`SELECT * FROM items WHERE id=?`).get(req.params.id);
  if (!it) return res.status(404).json({ error: 'not found' });
  if (!it.spawns) return res.status(400).json({ error: 'item has no spawn group' });
  const asset = q(`SELECT * FROM assets WHERE id=?`).get(it.asset_id);
  const sg = tplGroup(asset.type, 'spawn', '', it.spawns);
  if (!sg) return res.status(400).json({ error: `no follow-up checklist named "${it.spawns}" for type ${asset.type}` });
  const optKey = `spawn:${it.spawns}`;
  const n = q(`SELECT COUNT(*) c FROM items WHERE parent_id=? AND opt_key=?`).get(it.id, optKey).c + 1;
  let sort = q(`SELECT COALESCE(MAX(sort),0)+1 AS s FROM items WHERE asset_id=?`).get(it.asset_id).s;
  const cinfo = insertItem.run({
    asset_id: it.asset_id, parent_id: it.id, group_key: it.group_key, group_title: it.group_title,
    title: sg.title + (n > 1 ? ` #${n}` : ''), detail: '', payloads: '[]', kind: 'group',
    spawns: null, catalog: null, options: '[]', opt_key: optKey, sort: sort++,
  });
  const containerId = cinfo.lastInsertRowid;
  for (const item of sg.items) addItem(it.asset_id, {
    parent_id: containerId, group_key: it.group_key, group_title: it.group_title,
    title: item.title, detail: item.detail || '', payloads: item.payloads || '[]', // already JSON in the DB
    kind: item.kind || 'check', spawns: item.spawns || null, sort: sort++,
  });
  res.status(201).json({ ok: true, added: sg.items.length, instance: n });
});

// Toggle a `select` option -> unfold (or remove) that option's catalog checklist as children.
app.post('/api/items/:id/select', (req, res) => {
  const it = q(`SELECT * FROM items WHERE id=?`).get(req.params.id);
  if (!it) return res.status(404).json({ error: 'not found' });
  const key = (req.body || {}).key;
  if (!it.catalog || !key) return res.status(400).json({ error: 'not a select item / key missing' });
  const existing = q(`SELECT id FROM items WHERE parent_id=? AND opt_key=?`).all(it.id, key);
  if (existing.length) { // deselect -> remove that option's subtree
    for (const c of existing) deleteItemTree(c.id);
    return res.json({ ok: true, selected: false });
  }
  const asset = q(`SELECT * FROM assets WHERE id=?`).get(it.asset_id);
  const cat = tplGroup(asset.type, 'catalog', it.catalog, key);
  if (!cat) return res.status(400).json({ error: 'no catalog entry for that option' });
  let sort = q(`SELECT COALESCE(MAX(sort),0)+1 AS s FROM items WHERE asset_id=?`).get(it.asset_id).s;
  for (const r of cat.items) addItem(it.asset_id, {
    parent_id: it.id, group_key: it.group_key, group_title: it.group_title, opt_key: key,
    title: `[${cat.title}] ${r.title}`, detail: r.detail || '', payloads: r.payloads || '[]',
    kind: r.kind || 'check', spawns: r.spawns || null, sort: sort++,
  });
  res.status(201).json({ ok: true, selected: true, added: cat.items.length });
});

app.delete('/api/items/:id', (req, res) => {
  deleteItemTree(req.params.id);
  res.json({ ok: true });
});

// ---- findings ----
app.post('/api/assets/:id/findings', (req, res) => {
  const a = q(`SELECT id FROM assets WHERE id=?`).get(req.params.id);
  if (!a) return res.status(404).json({ error: 'asset not found' });
  const { title, kind, severity, body } = req.body || {};
  if (!title) return res.status(400).json({ error: 'title required' });
  const info = q(`INSERT INTO findings (asset_id, title, kind, severity, body) VALUES (?,?,?,?,?)`)
    .run(req.params.id, title, kind || 'note', severity || null, body || null);
  res.status(201).json(q(`SELECT * FROM findings WHERE id=?`).get(info.lastInsertRowid));
});

app.patch('/api/findings/:id', (req, res) => {
  const cur = q(`SELECT * FROM findings WHERE id=?`).get(req.params.id);
  if (!cur) return res.status(404).json({ error: 'not found' });
  const b = req.body || {};
  if ('title' in b && !b.title) return res.status(400).json({ error: 'title cannot be empty' });
  q(`UPDATE findings SET title=?, kind=?, severity=?, body=? WHERE id=?`).run(
    b.title ?? cur.title, b.kind ?? cur.kind,
    b.severity === undefined ? cur.severity : (b.severity || null),
    b.body === undefined ? cur.body : (b.body || null), cur.id);
  res.json(q(`SELECT * FROM findings WHERE id=?`).get(cur.id));
});

app.delete('/api/findings/:id', (req, res) => {
  q(`DELETE FROM findings WHERE id=?`).run(req.params.id);
  res.json({ ok: true });
});

// ---- image attachments on a finding ----
const MAX_UPLOAD = 15 * 1024 * 1024;
// Raw body, any content-type, so screenshots upload without base64 bloat or a multipart parser.
const rawUpload = express.raw({ type: () => true, limit: MAX_UPLOAD });
app.post('/api/findings/:id/attachments', rawUpload, (req, res) => {
  if (!q(`SELECT id FROM findings WHERE id=?`).get(req.params.id)) return res.status(404).json({ error: 'finding not found' });
  const mime = (req.headers['content-type'] || '').split(';')[0].trim();
  if (!mime.startsWith('image/')) return res.status(400).json({ error: 'only image files are accepted' });
  const buf = req.body;
  if (!Buffer.isBuffer(buf) || !buf.length) return res.status(400).json({ error: 'empty upload' });
  if (buf.length > MAX_UPLOAD) return res.status(413).json({ error: 'image too large (15 MB max)' });
  // filename comes in a header so the raw body stays the file itself
  const raw = req.headers['x-filename'] ? decodeURIComponent(req.headers['x-filename']) : 'image';
  const filename = raw.replace(/[\\/\x00-\x1f]+/g, '_').slice(0, 120) || 'image';
  const info = q(`INSERT INTO attachments (finding_id, filename, mime, size, data) VALUES (?,?,?,?,?)`)
    .run(req.params.id, filename, mime, buf.length, buf);
  res.status(201).json(q(`SELECT id, finding_id, filename, mime, size, created_at FROM attachments WHERE id=?`).get(info.lastInsertRowid));
});
app.get('/api/attachments/:id', (req, res) => {
  const a = q(`SELECT filename, mime, data FROM attachments WHERE id=?`).get(req.params.id);
  if (!a) return res.status(404).json({ error: 'not found' });
  res.setHeader('Content-Type', a.mime);
  res.setHeader('Cache-Control', 'private, max-age=31536000, immutable');
  res.setHeader('Content-Disposition', `inline; filename="${a.filename.replace(/"/g, '')}"`);
  res.end(Buffer.from(a.data));
});
app.delete('/api/attachments/:id', (req, res) => {
  q(`DELETE FROM attachments WHERE id=?`).run(req.params.id);
  res.json({ ok: true });
});

// ---- export ----
// Standalone HTML findings report with screenshots embedded as data: URIs.
app.get('/api/projects/:id/report.html', (req, res) => {
  const html = projectReportHTML(req.params.id);
  if (html == null) return res.status(404).json({ error: 'not found' });
  const safe = (q(`SELECT name FROM projects WHERE id=?`).get(req.params.id)?.name || 'report')
    .replace(/[^a-z0-9._-]+/gi, '-').slice(0, 60);
  res.setHeader('Content-Disposition', `attachment; filename="magi-findings-${safe}.html"`);
  res.type('html').send(html);
});
app.get('/api/projects/:id/export', (req, res) => {
  const p = q(`SELECT * FROM projects WHERE id=?`).get(req.params.id);
  if (!p) return res.status(404).json({ error: 'not found' });
  const assets = q(`SELECT * FROM assets WHERE project_id=? ORDER BY created_at`).all(p.id);
  const data = assets.map(a => ({
    ...assetSummary(a),
    items: q(`SELECT * FROM items WHERE asset_id=? ORDER BY sort`).all(a.id)
      .map(i => ({ ...i, payloads: JSON.parse(i.payloads || '[]') })),
    findings: q(`SELECT * FROM findings WHERE asset_id=?`).all(a.id),
  }));
  if (req.query.format === 'json') return res.json({ project: p, assets: data });

  // markdown
  const icon = { done: '✅', na: '➖', flag: '🚩', yes: '✔️', no: '✖️', todo: '⬜' };
  let md = `# ${p.name}\n`;
  if (p.client) md += `**Client:** ${p.client}  \n`;
  if (p.scope) md += `**Scope:** ${p.scope}  \n`;
  md += `\n_Exported ${new Date().toISOString()}_\n`;
  for (const a of data) {
    md += `\n## ${a.type.toUpperCase()} — ${a.label}\n`;
    if (a.findings.length) {
      md += `\n### Findings\n`;
      for (const f of a.findings) {
        md += `- **${f.title}** (${f.kind}${f.severity ? ', ' + f.severity : ''})\n`;
        if (f.body) md += '```\n' + f.body + '\n```\n';
      }
    }
    // Render the item tree: one heading per section, children indented under their
    // parent rather than dumped flat at the end (they sort last, which used to
    // re-open sections and lose the trigger/select structure entirely).
    const kids = {};
    for (const i of a.items) if (i.parent_id != null) (kids[i.parent_id] ||= []).push(i);
    const line = (i, depth) => {
      let s = `${'  '.repeat(depth)}- ${icon[i.status] || '⬜'} ${i.title}`;
      if (i.answer) s += ` — _${i.answer}_`;
      s += `\n`;
      for (const k of (kids[i.id] || [])) s += line(k, depth + 1);
      return s;
    };
    const sections = [];
    for (const i of a.items) {
      if (i.parent_id != null) continue;
      const s = sections[sections.length - 1];
      if (!s || s.key !== i.group_key) sections.push({ key: i.group_key, title: i.group_title, items: [i] });
      else s.items.push(i);
    }
    for (const s of sections) {
      md += `\n### ${s.title}\n`;
      for (const i of s.items) md += line(i, 0);
    }
  }
  res.type('text/markdown').send(md);
});

// Never leak a stack trace or SQL error to the client.
app.use('/api', (err, req, res, _next) => {
  console.error(`  [error] ${req.method} ${req.path}:`, err.message);
  res.status(500).json({ error: 'internal error' });
});

// Exported so the desktop app can dispatch requests straight into Express without
// ever opening a socket. MAGI_EMBED=1 tells this module not to listen.
export default app;

if (process.env.MAGI_EMBED !== '1') {
  // admin/admin is fine for a local lock screen; it is not fine on a network.
  if (HOST !== '127.0.0.1' && HOST !== 'localhost' && usingDefaultPassword()) {
    console.error(`\n  Refusing to listen on ${HOST} while the password is still the default.`);
    console.error(`  Change it in the app first, or start with MAGI_PASS=<something long>.\n`);
    process.exit(1);
  }
  app.listen(PORT, HOST, () => {
    console.log(`\n  MAGI  ·  the pentester's familiar`);
    console.log(`  http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
    if (HOST !== '127.0.0.1') {
      console.log(`\n  !! Listening on ${HOST} — this app is reachable from the network.`);
      console.log(`     It holds client credentials, raw requests and findings. Only do this on a`);
      console.log(`     trusted network, with a strong password set.\n`);
    } else {
      console.log(`  Bound to localhost only. Set MAGI_HOST=0.0.0.0 to share it.\n`);
    }
  });
}
