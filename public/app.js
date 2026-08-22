// MAGI — the pentester's familiar.
// Vanilla-JS SPA. Markup here, styling entirely in style.css.

// ---------- tiny helpers ----------
const $ = (s, r = document) => r.querySelector(s);
const el = (tag, props = {}, ...kids) => {
  const n = Object.assign(document.createElement(tag), props);
  for (const k of kids.flat()) if (k != null && k !== false) n.append(k?.nodeType ? k : document.createTextNode(k));
  return n;
};
const NS = 'http://www.w3.org/2000/svg';
// icon set lifted from the design: 16x16 grid, stroked, currentColor
const ICON = {
  check: ['M3.5 8.5l3 3 6-7', 2],
  flag: ['M4 14V3l8 2.5L4 8', 1.7],
  na: ['M4 8h8', 1.7],
  edit: ['M11 2.5l2.5 2.5L5.5 13H3v-2.5z', 1.4],
  x: ['M4 4l8 8M12 4l-8 8', 1.4],
  plus: ['M8 3v10M3 8h10', 1.7],
  trash: ['M3 4.5h10M6.5 4.5V3h3v1.5M4.5 4.5l.7 8.5h5.6l.7-8.5', 1.4],
  lines: ['M2 4h12M2 8h8M2 12h5', 1.4],
  exit: ['M6 2H3v12h3M10 5l3 3-3 3M13 8H6', 1.4],
  down: ['M8 3v8M4.5 7.5L8 11l3.5-3.5', 1.5],
  up: ['M8 13V5M4.5 8.5L8 5l3.5 3.5', 1.5],
  image: ['M2.5 3.5h11v9h-11zM2.5 10l3-3 3 3M9 8.5l2-2 2.5 2.5', 1.3],
  key: ['M10.5 2.5a3.5 3.5 0 100 7 3.5 3.5 0 000-7zM8 8l-5.5 5.5V15h2l4-4', 1.3],
  server: ['M2.5 4h11v3.4h-11zM2.5 8.6h11V12h-11zM4.6 5.7h.01M4.6 10.3h.01', 1.3],
};
function icon(name, size = 13) {
  const [d, w] = ICON[name];
  const s = document.createElementNS(NS, 'svg');
  s.setAttribute('width', size); s.setAttribute('height', size);
  s.setAttribute('viewBox', '0 0 16 16'); s.setAttribute('fill', 'none');
  s.setAttribute('stroke', 'currentColor'); s.setAttribute('stroke-width', w);
  s.setAttribute('stroke-linecap', 'round'); s.setAttribute('stroke-linejoin', 'round');
  const p = document.createElementNS(NS, 'path');
  p.setAttribute('d', d); s.append(p);
  return s;
}
function magiMark(size) {
  const s = document.createElementNS(NS, 'svg');
  s.setAttribute('viewBox', '0 0 32 32'); s.setAttribute('width', size);
  s.setAttribute('height', size); s.setAttribute('fill', 'none');
  s.innerHTML = `<circle cx="16" cy="16" r="13.5" stroke="#E8B65A" stroke-width=".9" opacity=".8"/>
    <circle cx="16" cy="16" r="10.6" stroke="#E8B65A" stroke-width=".4" opacity=".3"/>
    <rect x="7.5" y="7.5" width="17" height="17" stroke="#E8B65A" stroke-width=".9"/>
    <rect x="7.5" y="7.5" width="17" height="17" stroke="#E8B65A" stroke-width=".9" transform="rotate(45 16 16)"/>
    <circle cx="16" cy="16" r="2.2" fill="#E8B65A" opacity=".6"/>
    <circle cx="16" cy="2.5" r="2.5" fill="#3D6FF0"/>
    <circle cx="16" cy="29.5" r="2.5" fill="#E2453C"/>`;
  return s;
}

async function api(path, opts) {
  const r = await fetch('/api' + path, {
    headers: { 'content-type': 'application/json' },
    ...opts, body: opts?.body ? JSON.stringify(opts.body) : undefined,
  });
  // A 401 from a /link/* call is the remote SERVER rejecting our device token (e.g. it was
  // revoked) — NOT our local session expiring. Only a genuine local 401 sends us to login,
  // otherwise a revoked device would trap the app in a login loop.
  if (r.status === 401 && path !== '/me' && path !== '/auth/login' && !path.startsWith('/link')) { showLogin(); throw new Error('Session expired'); }
  if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.error || r.statusText); }
  return r.headers.get('content-type')?.includes('json') ? r.json() : r.text();
}
function toast(msg) {
  $('.toast')?.remove();
  const t = el('div', { className: 'toast', textContent: msg });
  document.body.append(t); setTimeout(() => t.remove(), 1800);
}
const pct = (a, b) => (b ? Math.round((a / b) * 100) : 0);
const fmtDate = (d) => { if (!d) return ''; const t = new Date(d + 'T00:00:00'); return isNaN(t) ? d : t.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }); };
const fmtDateRange = (s, e) => (s && e ? `${fmtDate(s)} → ${fmtDate(e)}` : s ? `from ${fmtDate(s)}` : e ? `until ${fmtDate(e)}` : '');
const pad = (n) => String(n).padStart(2, '0');
const HANDLED = ['done', 'na', 'yes', 'no'];
const ACTIONABLE = (i) => !['select', 'group'].includes(i.kind);
const KIND_OPTS = [
  { value: 'check', label: 'Check' }, { value: 'question', label: 'Question / input' },
  { value: 'input', label: 'Input value' }, { value: 'trigger', label: 'Trigger (yes/no + follow-up)' },
  { value: 'select', label: 'Select (option chips)' }];
const daysSince = (iso) => Math.max(1, Math.round((Date.now() - new Date(iso.replace(' ', 'T') + 'Z')) / 864e5));

let TYPES = [];
// Engagement-group order/labels for the grouped add-target picker (mirrors ENGAGEMENT_GROUPS).
const GROUP_ORDER = [
  { key: 'internal', label: 'Internal' }, { key: 'external', label: 'External' },
  { key: 'mobile', label: 'Mobile' }, { key: 'wireless', label: 'Wireless' },
  { key: 'otiot', label: 'OT / IoT' }, { key: 'additional', label: 'Additional' },
];

// Fill {url}/{ip}/{domain}/… placeholders from the target's identifier, so payloads and
// guidance show the real target. Best-effort and non-destructive: unknown tokens are left
// as-is, and attacker-controlled ones like {callback} are never substituted.
let SUBST_MAP = {};
function substMap(a) {
  const raw = (a?.label || '').trim();
  const m = { target: raw, label: raw };
  let host = raw, u = null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) { try { u = new URL(raw); } catch {} }
  else if (/^[a-z0-9.-]+\.[a-z]{2,}(:\d+)?(\/|$)/i.test(raw)) { try { u = new URL('https://' + raw); } catch {} }
  if (u) { host = u.hostname; m.url = /:\/\//.test(raw) ? raw : 'https://' + raw; m.base = m.url; m.domain = host; }
  const ipm = raw.match(/^(\d{1,3}(?:\.\d{1,3}){3})(\/\d{1,2})?$/);
  if (ipm) { m.ip = ipm[1]; host = ipm[1]; m.target = raw; if (ipm[2]) m.cidr = raw; }
  m.host = host;
  for (const k of ['url', 'domain', 'ip', 'host', 'base', 'cidr', 'pkg', 'image', 'ssid', 'bssid', 'model', 'fw', 'system', 'proto', 'dc'])
    if (!(k in m)) m[k] = raw;
  return m;
}
const subst = (text) => String(text ?? '').replace(/\{([a-z_]+)\}/gi, (full, k) => (k in SUBST_MAP ? SUBST_MAP[k] : full));
let CURRENT_USER = null;
let ME = null;                // { username, role, display_name } from /api/me
let LINK = { linked: false }; // team-server link status, refreshed from /api/link
let ADMIN_PENDING = 0;        // number of pending join requests (for the Admin badge)
let BACKUP_DUE = false;       // a scheduled backup is due — also lights the Admin badge

// Where the admin API lives for the signed-in identity, or null if not an admin:
//  - on the server's own web UI: /api/admin directly (session admin)
//  - on a client linked as an admin device: proxied through /api/link/admin
function adminCtx() {
  if (LINK?.linked && LINK.link?.role === 'admin') return { base: '/link/admin' };
  if (LINK?.unavailable && ME?.role === 'admin') return { base: '/admin' };
  return null;
}

// ---------- modal ----------
// kicker + title + optional note, fields, optional danger box, gold/red CTA
function modal(opts) {
  const { kicker = 'Form', title, note, build, onSubmit, cta = 'Save', danger = false } = opts;
  const root = $('#modalRoot');
  const form = el('form', { className: 'modal' + (danger ? ' danger' : '') });
  const body = el('div', { className: 'modal-body' }, el('h3', {}, title), note ? el('p', { className: 'modal-note' }, note) : null);
  if (build) build(body);
  const errEl = el('div', { className: 'modal-err' });
  body.append(errEl);
  const close = () => root.replaceChildren();
  const x = el('button', { type: 'button', className: 'modal-x', title: 'Close', onclick: close }, icon('x'));
  const submit = el('button', { type: 'submit', className: 'btn ' + (danger ? 'dangerfill' : 'gold') }, cta);
  form.append(
    el('div', { className: 'modal-head' }, el('span', { className: 'modal-kicker' }, kicker), x),
    body,
    el('div', { className: 'actions' },
      el('button', { type: 'button', className: 'btn', onclick: close }, 'Cancel'), submit));
  form.onsubmit = async (e) => {
    e.preventDefault();
    errEl.textContent = ''; submit.disabled = true;   // inline error, not a focus-stealing alert()
    try { await onSubmit(new FormData(form)); close(); }
    catch (err) { errEl.textContent = err.message || String(err); form.querySelector('input,textarea,select')?.focus(); }
    finally { submit.disabled = false; }
  };
  root.replaceChildren(el('div', { className: 'overlay', onclick: (e) => { if (e.target.classList.contains('overlay')) close(); } }, form));
  form.querySelector('input,textarea,select')?.focus();
}
function field(parent, label, name, { type = 'text', value = '', ph = '', textarea = false, options } = {}) {
  parent.append(el('label', {}, label));
  let input;
  if (options) { input = el('select', { name }); for (const o of options) input.append(el('option', { value: o.value, selected: o.value === value }, o.label)); }
  else if (textarea) input = el('textarea', { name, value, placeholder: ph });
  else input = el('input', { name, type, value, placeholder: ph });
  parent.append(input); return input;
}

// ---------- chrome ----------
function setCrumbs(parts) {
  const c = $('#crumbs'); c.replaceChildren();
  parts.forEach((p, i) => {
    c.append(el('span', { className: 'sep' }, '/'));
    c.append(p.go
      ? el('button', { onclick: p.go }, p.label)
      : el('span', { className: 'cur' }, p.label));
  });
}
function renderAccount() {
  const lbl = (t) => el('span', { className: 'lbl' }, t);
  const badge = LINK?.pending
    ? el('button', { className: 'linkbadge pending', title: 'Join request awaiting approval — open settings', onclick: () => location.hash = '/settings' },
        el('span', { className: 'dot' }), lbl('pending'))
    : LINK?.linked
      ? el('button', { className: 'linkbadge on', title: `Linked to ${LINK.link?.server_url} — open settings`, onclick: () => location.hash = '/settings' },
          el('span', { className: 'dot' }), lbl(LINK.link?.display_name || 'linked'))
      : LINK?.unavailable ? null
        : el('button', { className: 'linkbadge', title: 'Working locally — click to connect to a team server', onclick: () => location.hash = '/settings' },
            el('span', { className: 'dot' }), lbl('local'));
  const adminBtn = adminCtx()
    ? el('button', { className: 'btn admin' + (ADMIN_PENDING || BACKUP_DUE ? ' hot' : ''), title: BACKUP_DUE ? 'Admin panel — a backup is due' : 'Admin panel', onclick: () => location.hash = '/admin' },
        icon('server'), lbl('Admin'), ADMIN_PENDING ? el('span', { className: 'count' }, String(ADMIN_PENDING)) : (BACKUP_DUE ? el('span', { className: 'count' }, '!') : null))
    : null;
  $('#account').replaceChildren(el('div', { className: 'acct' },
    badge, adminBtn,
    el('div', { className: 'avatar' }, (CURRENT_USER || '?')[0].toUpperCase()),
    el('span', { className: 'who' }, CURRENT_USER || ''),
    el('button', { className: 'iconbtn', title: 'Change password', onclick: changePassword }, icon('key')),
    el('button', { className: 'iconbtn danger', title: 'Sign out', onclick: logout }, icon('exit'))));
}
async function refreshLink() {
  try { LINK = await api('/link'); } catch { LINK = { linked: false, unavailable: true }; }
  const ctx = adminCtx();
  if (ctx) {
    try { ADMIN_PENDING = (await api(ctx.base + '/requests')).length; } catch { ADMIN_PENDING = 0; }
    // Scheduled-backup reminder: a backup is never taken unattended (we don't store the
    // password), so when one comes due we light the Admin badge and toast admins once.
    try {
      const wasDue = BACKUP_DUE;
      BACKUP_DUE = !!(await api(ctx.base + '/backup')).config?.due;
      if (BACKUP_DUE && !wasDue) toast('A scheduled backup is due — open Admin to run it');
    } catch { /* backups are a server feature; ignore if absent */ }
  } else { ADMIN_PENDING = 0; BACKUP_DUE = false; }
  if (CURRENT_USER) renderAccount();
}
function topActions(...btns) { $('#topActions').replaceChildren(...btns.filter(Boolean)); }
function setRail(node) {
  const r = $('#rail');
  if (!node) { r.hidden = true; r.replaceChildren(); return; }
  r.hidden = false; r.replaceChildren(...node);
}

// ---------- router ----------
async function route() {
  const h = location.hash.slice(1);
  $('#modalRoot').replaceChildren();
  topActions();
  $('#backBtn').hidden = !h; // nothing to go back to from the engagements home
  if (!CURRENT_USER) return;
  try {
    // A server instance can't link anywhere, so its settings page has nothing to show —
    // send it (and any stale #/settings hash left after a refresh) back to engagements.
    if (h === '/settings') { if (ME?.server) { location.hash = ''; return; } return renderSettings(); }
    if (h === '/admin') return renderAdmin();
    if (h === '/editor') return renderEditor();
    const gm = h.match(/^\/group\/(\d+)/); if (gm) return renderGroup(gm[1]);
    const em = h.match(/^\/editor\/([a-z0-9_]+)/); if (em) return renderEditor(em[1]);
    const [, kind, id] = h.match(/^\/(project|asset|target)\/(\d+)/) || [];
    if (kind === 'project') return renderProject(id);
    if (kind === 'asset') return renderAssetFolder(id);
    if (kind === 'target') return renderTarget(id);
    return renderHome();
  } catch (e) {
    setRail(null);
    $('#view').replaceChildren(el('div', { className: 'page' }, el('div', { className: 'empty' }, 'Error: ' + e.message)));
  }
}
window.addEventListener('hashchange', route);
$('#homeBtn').onclick = () => location.hash = '';
// Universal back: walk the hash history, or fall home if this is the first screen.
$('#backBtn').onclick = () => { if (history.length > 1) history.back(); else location.hash = ''; };

// ---------- engagements (home) ----------
async function renderHome() {
  const projects = await api('/projects');
  setRail(null);
  setCrumbs([{ label: 'engagements' }]);
  const view = $('#view');
  const head = el('div', { className: 'page-head' },
    el('div', {}, el('div', { className: 'kicker' }, 'Workspace'), el('h1', {}, 'Engagements')),
    el('div', { style: 'display:flex;gap:7px' },
      el('button', { className: 'btn', onclick: importProjectFile, title: 'Import an engagement from a file' }, icon('up', 12), 'Import'),
      el('button', { className: 'btn gold', onclick: newProject }, icon('plus', 12), 'New engagement')));

  if (!projects.length) {
    return view.replaceChildren(el('div', { className: 'page' }, head,
      el('div', { className: 'empty', style: 'margin-top:26px' },
        el('div', {}, 'No engagements yet. Every target, checklist and finding lives inside one.'),
        el('button', { className: 'btn gold', onclick: newProject }, icon('plus', 12), 'Create the first'))));
  }

  const projectRow = (p) => {
    const cov = pct(p.handled, p.total);
    const del = el('button', { className: 'ibtn del', title: 'Delete engagement' }, icon('trash'));
    del.onclick = (e) => { e.stopPropagation(); delProject(p, p.asset_count, renderHome); };
    const dot = el('span', { className: 'pdot' + (!p.total ? ' idle' : cov > 70 ? '' : ' part') });
    return el('button', { className: 'prow', onclick: () => location.hash = `/project/${p.id}` },
      el('span', { style: 'display:flex;align-items:center;gap:12px;min-width:0' }, dot,
        el('span', { style: 'display:flex;flex-direction:column;gap:3px;min-width:0' },
          el('span', { className: 'pname' }, p.name),
          el('span', { className: 'pmeta' }, `${p.asset_count} targets · ${p.finding_count} findings`))),
      el('span', { className: 'pcell hide-sm' }, p.client || '—'),
      el('span', { className: 'hide-sm', style: 'display:flex;align-items:center;gap:10px' },
        el('span', { className: 'bar' + (cov > 70 ? ' good' : !cov ? ' idle' : '') }, el('span', { style: `width:${cov}%` })),
        el('span', { className: 'pct' + (cov > 70 ? ' good' : cov ? ' some' : '') }, cov + '%')),
      el('span', { className: 'pcell hide-sm' }, fmtDateRange(p.start_date, p.end_date) || new Date(p.created_at).toLocaleDateString(undefined, { day: '2-digit', month: 'short' })),
      del);
  };

  const active = projects.filter(p => p.status !== 'finished');
  const finished = projects.filter(p => p.status === 'finished');

  const table = el('div', { className: 'ptable' },
    el('div', { className: 'ptable-head kicker' },
      el('span', {}, 'Engagement'), el('span', { className: 'hide-sm' }, 'Client'),
      el('span', { className: 'hide-sm' }, 'Coverage'), el('span', { className: 'hide-sm' }, 'Dates'), el('span', {})));
  if (active.length) active.forEach(p => table.append(projectRow(p)));
  else table.append(el('div', { className: 'empty', style: 'border:0' }, 'No active engagements. Finished ones are below.'));
  table.append(el('div', { className: 'end' }));

  const page = el('div', { className: 'page' }, head, table);

  // Finished engagements — collapsed history, searchable by name or client.
  if (finished.length) {
    const ftable = el('div', { className: 'ptable' });
    const paint = (term) => {
      ftable.replaceChildren();
      const t = term.trim().toLowerCase();
      const hits = finished.filter(p => !t || `${p.name} ${p.client || ''}`.toLowerCase().includes(t));
      if (!hits.length) ftable.append(el('div', { className: 'empty', style: 'border:0' }, 'No finished engagements match.'));
      else hits.forEach(p => ftable.append(projectRow(p)));
    };
    const search = el('input', { className: 'searchbox', type: 'search', placeholder: `Search ${finished.length} finished engagement${finished.length === 1 ? '' : 's'}…` });
    search.oninput = () => paint(search.value);
    paint('');
    page.append(el('div', { className: 'srule', style: 'margin-top:30px' },
      el('span', { className: 'kicker' }, `Finished (${finished.length})`), el('span', { className: 'rule' })));
    page.append(search, ftable);
  }
  view.replaceChildren(page);
}

function newProject() {
  modal({
    kicker: 'Create', title: 'New engagement', cta: 'Create',
    build: (b) => {
      field(b, 'Engagement name', 'name', { ph: 'Acme Corp — Q4 External' });
      field(b, 'Client', 'client', { ph: 'Acme Corp' });
      field(b, 'Scope', 'scope', { ph: '*.acme.com, 10.0.0.0/16' });
      const c1 = el('div'), c2 = el('div');
      field(c1, 'Start date', 'start_date', { type: 'date' });
      field(c2, 'End date', 'end_date', { type: 'date' });
      b.append(el('div', { className: 'field-row' }, c1, c2));
      field(b, 'Notes', 'notes', { textarea: true });
    },
    onSubmit: async (fd) => {
      const p = await api('/projects', { method: 'POST', body: Object.fromEntries(fd) });
      location.hash = `/project/${p.id}`;
    },
  });
}
function editProject(p, done) {
  modal({
    kicker: 'Edit', title: 'Engagement details', cta: 'Save',
    build: (b) => {
      field(b, 'Engagement name', 'name', { value: p.name });
      field(b, 'Client', 'client', { value: p.client || '' });
      field(b, 'Scope', 'scope', { value: p.scope || '' });
      const c1 = el('div'), c2 = el('div');
      field(c1, 'Start date', 'start_date', { type: 'date', value: p.start_date || '' });
      field(c2, 'End date', 'end_date', { type: 'date', value: p.end_date || '' });
      b.append(el('div', { className: 'field-row' }, c1, c2));
      field(b, 'Notes', 'notes', { textarea: true, value: p.notes || '' });
    },
    onSubmit: async (fd) => { await api('/projects/' + p.id, { method: 'PATCH', body: Object.fromEntries(fd) }); toast('Saved'); done?.(); },
  });
}
function setProjectStatus(p, status, done) {
  const finishing = status === 'finished';
  modal({
    kicker: 'Engagement', title: finishing ? 'Mark as finished?' : 'Reopen engagement?', cta: finishing ? 'Finish' : 'Reopen',
    note: finishing
      ? 'It moves to Finished engagements — still fully readable and searchable, just out of the active list. You can reopen it any time.'
      : 'It returns to your active engagements.',
    onSubmit: async () => { await api('/projects/' + p.id, { method: 'PATCH', body: { status } }); toast(finishing ? 'Marked finished' : 'Reopened'); done?.(); },
  });
}

// Cascades to targets, checklists and findings — spell it out and make them type the name.
function delProject(p, assetCount, after) {
  modal({
    kicker: 'Destructive', title: `Delete “${p.name}”?`, danger: true, cta: 'Delete forever',
    note: 'Magi keeps no backups of deleted engagements. Everything below goes with it.',
    build: (b) => {
      b.append(el('div', { className: 'dangerbox' },
        el('div', { className: 'kicker' }, 'Irreversible'),
        el('ul', { className: 'dellist' },
          el('li', {}, `${assetCount} target${assetCount === 1 ? '' : 's'} and their checklists`),
          el('li', {}, 'All findings and captured evidence'),
          el('li', {}, 'All answers, payload notes and progress'))));
      field(b, 'Type the engagement name to confirm', 'confirm', { ph: p.name });
    },
    onSubmit: async (fd) => {
      if ((fd.get('confirm') || '').trim() !== p.name) throw new Error('Name does not match — nothing was deleted.');
      await api('/projects/' + p.id, { method: 'DELETE' });
      toast('Engagement deleted'); after();
    },
  });
}

// ---------- rail (targets inside the current asset folder) ----------
const GROUP_ICON = { internal: '🏛️', external: '🌐', mobile: '📱', wireless: '📡', otiot: '🏭', additional: '📦' };
function groupLabel(key) { return (GROUP_ORDER.find(g => g.key === key) || {}).label || key; }
// engagement groups that actually have a selectable (non-soon) target type
function selectableGroups() { return new Set(TYPES.filter(t => !t.soon).map(t => t.grp || 'additional')); }

function railForFolder(folder, activeTargetId) {
  const targets = folder.targets || [];
  const total = targets.reduce((a, x) => a + x.total, 0);
  const handled = targets.reduce((a, x) => a + x.handled, 0);
  const head = el('div', { className: 'rail-head' },
    el('div', { className: 'kicker' }, 'Asset · ' + groupLabel(folder.grp)),
    el('div', { className: 'rail-title' }, `${GROUP_ICON[folder.grp] || ''} ${folder.label}`),
    el('div', { className: 'rail-status' }, el('span', { className: 'pulse' }),
      `${pct(handled, total)}% · ${targets.length} TARGET${targets.length === 1 ? '' : 'S'}`));
  const list = el('div', { className: 'rail-list' });
  for (const a of targets) {
    const p = pct(a.handled, a.total);
    list.append(el('button', {
      className: 'railtarget' + (String(a.id) === String(activeTargetId) ? ' on' : ''),
      onclick: () => location.hash = `/target/${a.id}`,
    },
      el('span', { className: 'rt-top' },
        el('span', { className: 'rt-kind' }, a.type.toUpperCase()),
        el('span', { className: 'rt-pct' }, p + '%')),
      el('span', { className: 'rt-name' }, a.label),
      el('span', { className: 'bar thin' + (p > 70 ? ' good' : !p ? ' idle' : '') }, el('span', { style: `width:${p}%` }))));
  }
  if (!targets.length) list.append(el('div', { className: 'pmeta', style: 'padding:10px' }, 'No targets yet'));
  return [head,
    el('button', { className: 'railback', onclick: () => location.hash = `/project/${folder.project_id}` }, '‹ Back to engagement'),
    el('div', { className: 'rail-label kicker' }, 'Targets'), list,
    el('div', { className: 'rail-foot' },
      el('button', { className: 'dashbtn', onclick: () => addTarget(folder) }, icon('plus', 12), 'Add target'))];
}

// ---------- engagement (project) — lists Asset folders ----------
async function renderProject(id) {
  const p = await api('/projects/' + id);
  setRail(null);
  setCrumbs([{ label: 'engagements', go: () => location.hash = '' }, { label: p.name }]);
  const finished = p.status === 'finished';
  topActions(
    el('button', { className: 'btn', onclick: () => exportProjectMenu(id, p.name) }, icon('down', 12), 'Export'),
    el('button', { className: 'btn', onclick: () => editProject(p, () => renderProject(id)) }, icon('edit', 12), 'Edit'),
    finished
      ? el('button', { className: 'btn', onclick: () => setProjectStatus(p, 'active', () => renderProject(id)) }, 'Reopen')
      : el('button', { className: 'btn', onclick: () => setProjectStatus(p, 'finished', () => renderProject(id)) }, icon('check', 12), 'Finish'),
    el('button', { className: 'btn danger', onclick: () => delProject(p, p.assets.length, () => location.hash = '') }, 'Delete'));

  const total = p.assets.reduce((a, x) => a + x.total, 0);
  const handled = p.assets.reduce((a, x) => a + x.handled, 0);
  const findings = p.assets.reduce((a, x) => a + (x.findings || 0), 0);
  const flags = p.assets.reduce((a, x) => a + x.flags, 0);
  const targets = p.assets.reduce((a, x) => a + (x.targets || 0), 0);

  const stat = (label, value, cls) => el('div', { className: 'stat' },
    el('div', { className: 'kicker' }, label), el('div', { className: 'stat-value ' + (cls || '') }, value));

  const list = el('div', { className: 'tlist' });
  if (!p.assets.length) {
    list.append(el('div', { className: 'empty', style: 'border:0' },
      el('div', {}, 'No assets yet. Create an Internal, External, Mobile, OT/IoT or Additional asset, then add targets inside it.'),
      el('button', { className: 'btn gold', onclick: () => addAsset(id) }, icon('plus', 12), 'Add asset')));
  }
  for (const a of p.assets) {
    const cov = pct(a.handled, a.total);
    const del = el('button', { className: 'ibtn del', title: 'Delete asset' }, icon('trash'));
    del.onclick = (e) => { e.stopPropagation(); delAsset(a, () => renderProject(id)); };
    list.append(el('button', { className: 'trow', onclick: () => location.hash = `/asset/${a.id}` },
      el('span', { className: 'ticon' }, GROUP_ICON[a.grp] || '◇'),
      el('span', { className: 'tgrow' },
        el('span', { className: 'tname' }, a.label),
        el('span', { className: 'tmeta' }, `${groupLabel(a.grp).toUpperCase()} · ${a.targets || 0} target${a.targets === 1 ? '' : 's'} · ${a.handled}/${a.total} handled`)),
      el('span', { className: 'tprog' },
        el('span', { className: 'bar' + (cov > 70 ? ' good' : !cov ? ' idle' : '') }, el('span', { style: `width:${cov}%` })),
        el('span', { className: 'pct' + (cov > 70 ? ' good' : cov ? ' some' : '') }, cov + '%')),
      el('span', { className: 'tflag' + (a.flags ? ' on' : '') }, a.flags ? '⚑ ' + a.flags : '—'),
      del));
  }

  const dateRange = fmtDateRange(p.start_date, p.end_date);
  $('#view').replaceChildren(el('div', { className: 'page narrow' },
    el('div', { style: 'display:flex;align-items:center;gap:10px' },
      el('div', { className: 'kicker' }, 'Engagement'),
      finished ? el('span', { className: 'pill done' }, 'Finished') : null,
      dateRange ? el('span', { className: 'muted small' }, '· ' + dateRange) : null),
    el('h1', {}, p.name),
    p.client || p.scope ? el('div', { className: 'lede' }, [p.client, p.scope].filter(Boolean).join(' · ')) : null,
    el('div', { className: 'stats' },
      stat('Coverage', pct(handled, total) + '%', 'gold'),
      stat('Findings', String(findings + flags), 'red'),
      stat('Assets', String(p.assets.length)),
      stat('Targets', String(targets))),
    el('div', { className: 'srule' },
      el('span', { className: 'kicker' }, 'Assets'), el('span', { className: 'rule' }),
      el('button', { className: 'btn line sm', onclick: () => addAsset(id) }, '+ Add asset')),
    list));
}

// ---------- asset folder — lists its targets ----------
async function renderAssetFolder(id) {
  const f = await api('/assets/' + id);
  setRail(railForFolder(f, null));
  setCrumbs([
    { label: 'engagements', go: () => location.hash = '' },
    { label: f.project?.name || 'project', go: () => location.hash = `/project/${f.project_id}` },
    { label: f.label }]);
  topActions(
    el('button', { className: 'btn danger', onclick: () => delAsset(f, () => location.hash = `/project/${f.project_id}`) }, 'Delete asset'));

  const total = f.targets.reduce((a, x) => a + x.total, 0);
  const handled = f.targets.reduce((a, x) => a + x.handled, 0);

  const list = el('div', { className: 'tlist' });
  if (!f.targets.length) {
    list.append(el('div', { className: 'empty', style: 'border:0' },
      el('div', {}, `No targets in this ${groupLabel(f.grp)} asset yet.`),
      el('button', { className: 'btn gold', onclick: () => addTarget(f) }, icon('plus', 12), 'Add target')));
  }
  for (const a of f.targets) {
    const t = TYPES.find(x => x.type === a.type) || {};
    const cov = pct(a.handled, a.total);
    const del = el('button', { className: 'ibtn del', title: 'Delete target' }, icon('trash'));
    del.onclick = (e) => { e.stopPropagation(); delTarget(a, () => renderAssetFolder(id)); };
    list.append(el('button', { className: 'trow', onclick: () => location.hash = `/target/${a.id}` },
      el('span', { className: 'ticon' }, t.icon || '◇'),
      el('span', { className: 'tgrow' },
        el('span', { className: 'tname' }, a.label),
        el('span', { className: 'tmeta' }, `${(t.label || a.type).toUpperCase()} · ${a.handled}/${a.total} handled`)),
      el('span', { className: 'tprog' },
        el('span', { className: 'bar' + (cov > 70 ? ' good' : !cov ? ' idle' : '') }, el('span', { style: `width:${cov}%` })),
        el('span', { className: 'pct' + (cov > 70 ? ' good' : cov ? ' some' : '') }, cov + '%')),
      el('span', { className: 'tflag' + (a.flags ? ' on' : '') }, a.flags ? '⚑ ' + a.flags : '—'),
      del));
  }

  $('#view').replaceChildren(el('div', { className: 'page narrow' },
    el('div', { className: 'kicker' }, 'Asset · ' + groupLabel(f.grp)),
    el('h1', {}, `${GROUP_ICON[f.grp] || ''} ${f.label}`),
    el('div', { className: 'stats' },
      stat3('Coverage', pct(handled, total) + '%', 'gold'),
      stat3('Targets', String(f.targets.length)),
      stat3('Handled', `${handled}/${total}`)),
    el('div', { className: 'srule' },
      el('span', { className: 'kicker' }, 'Targets'), el('span', { className: 'rule' }),
      el('button', { className: 'btn line sm', onclick: () => addTarget(f) }, '+ Add target')),
    list));
}
function stat3(label, value, cls) {
  return el('div', { className: 'stat' }, el('div', { className: 'kicker' }, label),
    el('div', { className: 'stat-value ' + (cls || '') }, value));
}

// Create an engagement-type Asset folder inside a project.
function addAsset(projectId) {
  const selectable = selectableGroups();
  modal({
    kicker: 'Scope', title: 'Add an asset', cta: 'Add asset',
    note: 'An asset is an engagement type. You add targets (web, host, AD…) inside it.',
    build: (b) => {
      const firstGrp = GROUP_ORDER.find(g => selectable.has(g.key))?.key || 'internal';
      const hidden = el('input', { type: 'hidden', name: 'grp', value: firstGrp });
      const label = el('input', { name: 'label', placeholder: 'e.g. Corporate internal, Acme external' });
      const grid = el('div', { className: 'typegrid' });
      const btns = [];
      for (const g of GROUP_ORDER) {
        const soon = !selectable.has(g.key);
        const btn = el('button', { type: 'button', className: 'type' + (g.key === hidden.value ? ' sel' : '') + (soon ? ' soon' : '') },
          el('span', { className: 'lbl' }, `${GROUP_ICON[g.key] || ''} ${g.label}`),
          el('span', { className: 'hint' }, soon ? 'coming soon' : (g.key === 'internal' ? 'host, subnet, AD'
            : g.key === 'external' ? 'web, api, domain' : g.key === 'otiot' ? 'IoT, OT/ICS'
            : g.key === 'additional' ? 'container / cloud' : g.label.toLowerCase())));
        if (soon) btn.disabled = true;
        else btn.onclick = () => { hidden.value = g.key; for (const x of btns) x.classList.remove('sel'); btn.classList.add('sel'); label.focus(); };
        btns.push(btn); grid.append(btn);
      }
      b.append(el('label', {}, 'Engagement type'), grid, hidden, el('label', {}, 'Name'), label);
    },
    onSubmit: async (fd) => {
      const body = { grp: fd.get('grp'), label: fd.get('label') };
      if (!body.label) throw new Error('Name the asset');
      const f = await api(`/projects/${projectId}/assets`, { method: 'POST', body });
      location.hash = `/asset/${f.id}`;
    },
  });
}

// Create a Target inside an asset folder — types limited to the folder's engagement group.
function addTarget(folder) {
  const types = TYPES.filter(t => (t.grp || 'additional') === folder.grp && !t.soon);
  if (!types.length) return alert('No target types are available for this engagement type yet.');
  modal({
    kicker: 'Target', title: `Add a target — ${groupLabel(folder.grp)}`, cta: 'Add target',
    build: (b) => {
      const hidden = el('input', { type: 'hidden', name: 'type', value: types[0].type });
      const label = el('input', { name: 'label', placeholder: types[0].hint || 'value' });
      const grid = el('div', { className: 'typegrid' });
      const btns = [];
      for (const t of types) {
        const btn = el('button', { type: 'button', className: 'type' + (t.type === hidden.value ? ' sel' : '') },
          el('span', { className: 'lbl' }, `${t.icon || ''} ${t.label}`),
          el('span', { className: 'hint' }, t.hint || t.type));
        btn.onclick = () => { hidden.value = t.type; label.placeholder = t.hint || 'value'; for (const x of btns) x.classList.remove('sel'); btn.classList.add('sel'); label.focus(); };
        btns.push(btn); grid.append(btn);
      }
      b.append(el('label', {}, 'Target type'), grid, hidden, el('label', {}, 'Identifier'), label);
    },
    onSubmit: async (fd) => {
      const body = { type: fd.get('type'), label: fd.get('label') };
      if (!body.label) throw new Error('Enter an identifier');
      const a = await api(`/assets/${folder.id}/targets`, { method: 'POST', body });
      location.hash = `/target/${a.id}`;
    },
  });
}

// Delete an Asset folder and everything inside it.
function delAsset(f, after) {
  const targets = f.targets ?? (Array.isArray(f.targets) ? f.targets.length : 0);
  const n = typeof targets === 'number' ? targets : (f.targets?.length || 0);
  modal({
    kicker: 'Destructive', title: `Delete asset “${f.label}”?`, danger: true, cta: 'Delete forever',
    note: 'The engagement is kept. This asset and every target inside it are removed.',
    build: (b) => b.append(el('div', { className: 'dangerbox' },
      el('div', { className: 'kicker' }, 'Irreversible'),
      el('ul', { className: 'dellist' },
        el('li', {}, `${n} target${n === 1 ? '' : 's'} and their checklists`),
        el('li', {}, 'All findings, evidence and progress inside them')))),
    onSubmit: async () => {
      await api('/assets/' + f.id, { method: 'DELETE' });
      curAssetId = null; toast('Asset deleted');
      if (after) after();
    },
  });
}

// Delete a single Target.
function delTarget(a, after) {
  const items = a.total ?? a.items?.length ?? 0;
  const findings = a.findings?.length ?? a.findings ?? 0;
  const done = a.handled ?? a.items?.filter(i => HANDLED.includes(i.status)).length ?? 0;
  modal({
    kicker: 'Destructive', title: `Delete target “${a.label}”?`, danger: true, cta: 'Delete forever',
    note: 'The asset is kept. Everything recorded against this target is not.',
    build: (b) => b.append(el('div', { className: 'dangerbox' },
      el('div', { className: 'kicker' }, 'Irreversible'),
      el('ul', { className: 'dellist' },
        el('li', {}, `${items} checklist item${items === 1 ? '' : 's'}${done ? ` (${done} already handled)` : ''}`),
        el('li', {}, findings ? `${findings} finding${findings === 1 ? '' : 's'} and captured evidence` : 'Any findings and evidence recorded against it'),
        el('li', {}, 'All answers and progress')))),
    onSubmit: async () => {
      await api('/targets/' + a.id, { method: 'DELETE' });
      curAssetId = null; toast('Target deleted');
      if (after) after(); else location.hash = `/asset/${a.folder?.id || a.folder_id}`;
    },
  });
}

// ---------- target checklist ----------
let curAssetId = null;
const openGroups = new Set();
const openPayloads = new Set();
let FILTER = 'all';

const MATCH = {
  all: () => true,
  open: (i) => i.status === 'todo',
  flag: (i) => i.status === 'flag',
  done: (i) => HANDLED.includes(i.status),
};

async function renderTarget(id) {
  id = String(id);
  const a = await api('/targets/' + id);
  SUBST_MAP = substMap(a);
  const t = TYPES.find(x => x.type === a.type) || {};
  if (curAssetId !== id) { curAssetId = id; openGroups.clear(); openPayloads.clear(); FILTER = 'all'; }

  const folder = await api('/assets/' + a.folder_id);   // full folder → sibling targets for the rail
  setRail(railForFolder(folder, id));
  setCrumbs([
    { label: 'engagements', go: () => location.hash = '' },
    { label: folder.project?.name || 'project', go: () => location.hash = `/project/${folder.project_id}` },
    { label: folder.label, go: () => location.hash = `/asset/${folder.id}` },
    { label: a.label }]);
  topActions(
    el('button', { className: 'btn danger', onclick: () => delTarget(a) }, 'Delete target'));

  const childrenBy = {}, byGroup = {};
  for (const it of a.items) {
    (byGroup[it.group_key] ||= []).push(it);
    if (it.parent_id != null) (childrenBy[it.parent_id] ||= []).push(it);
  }
  // An item survives the filter if it matches, or anything beneath it does.
  // select/group rows are containers rather than work: they carry no status, so in the
  // unfiltered view they always stay (otherwise a select with nothing chosen vanishes,
  // taking its option chips with it), and under a filter only if a child matches.
  const survives = (it) => ACTIONABLE(it)
    ? MATCH[FILTER](it) || (childrenBy[it.id] || []).some(survives)
    : FILTER === 'all' || (childrenBy[it.id] || []).some(survives);

  const groups = [];
  for (const it of a.items) {
    if (it.parent_id != null) continue;
    const g = groups[groups.length - 1];
    if (!g || g.key !== it.group_key) groups.push({ key: it.group_key, title: it.group_title, roots: [it] });
    else g.roots.push(it);
  }

  const actionable = a.items.filter(ACTIONABLE);
  const handled = actionable.filter(i => HANDLED.includes(i.status)).length;
  const flagged = actionable.filter(i => i.status === 'flag').length;
  const openCount = actionable.filter(i => i.status === 'todo').length;

  // ── sticky header
  const segbar = el('div', { className: 'segbar' });
  for (const g of groups) {
    const all = (byGroup[g.key] || []).filter(ACTIONABLE);
    const done = all.filter(i => HANDLED.includes(i.status)).length;
    const gf = all.filter(i => i.status === 'flag').length;
    segbar.append(el('span', {
      className: gf ? 'has-flag' : '', title: `${g.title} — ${done}/${all.length}`,
      style: `flex:${Math.max(all.length, 1)}`,
    }, el('span', { style: `width:${pct(done, all.length)}%` })));
  }

  const filters = el('div', { className: 'filters' });
  for (const f of [{ k: 'all', l: 'All', n: actionable.length }, { k: 'open', l: 'Open', n: openCount },
  { k: 'flag', l: 'Findings', n: flagged }, { k: 'done', l: 'Handled', n: handled }]) {
    filters.append(el('button', {
      className: 'filt' + (FILTER === f.k ? ' on' : ''),
      onclick: () => {
        FILTER = f.k;
        if (f.k !== 'all') groups.forEach(g => openGroups.add(g.key)); // show what you filtered for
        renderTarget(id);
      },
    }, f.l, el('span', {}, String(f.n))));
  }

  const head = el('div', { className: 'target-head' },
    el('div', { style: 'display:flex;align-items:flex-start;gap:16px' },
      el('div', { style: 'min-width:0;flex:1' },
        el('div', { className: 'kicker' }, t.label || a.type),
        el('h1', {}, a.label)),
      el('div', { className: 'target-actions' },
        el('button', { className: 'btn', onclick: () => { groups.forEach(g => openGroups.add(g.key)); renderTarget(id); } }, 'Expand all'),
        el('button', { className: 'btn', onclick: () => { openGroups.clear(); renderTarget(id); } }, 'Collapse'),
        el('button', { className: 'btn line', onclick: () => itemModal(id) }, '+ Item'))),
    el('div', { className: 'seg' }, segbar,
      el('span', { className: 'count' }, String(handled), el('b', {}, '/' + actionable.length)),
      flagged ? el('span', { className: 'flagcount' }, icon('flag', 11), String(flagged)) : null),
    filters);

  // ── checklist
  const list = el('div', { className: 'checklist' });
  let shown = 0;
  groups.forEach((g, gi) => {
    const all = (byGroup[g.key] || []).filter(ACTIONABLE);
    const done = all.filter(i => HANDLED.includes(i.status)).length;
    const gf = all.filter(i => i.status === 'flag').length;
    const roots = g.roots.filter(survives);
    if (!roots.length) return;
    shown += roots.length;
    const open = openGroups.has(g.key);
    const hdr = el('button', { className: 'ghdr' + (open ? ' open' : '') },
      el('span', { className: 'gnum' }, pad(gi + 1)),
      el('span', { className: 'gchev' }, '▶'),
      el('span', { className: 'gtitle' }, g.title),
      gf ? el('span', { className: 'gflag' }, '⚑ ' + gf) : null,
      el('span', { className: 'gcount' }, String(done), el('b', {}, '/' + all.length)),
      el('span', { className: 'bar' + (pct(done, all.length) > 70 ? ' good' : '') }, el('span', { style: `width:${pct(done, all.length)}%` })));
    hdr.onclick = () => { open ? openGroups.delete(g.key) : openGroups.add(g.key); renderTarget(id); };
    const box = el('div', { className: 'group' }, hdr);
    if (open) {
      const body = el('div', { className: 'gbody' });
      let n = 0;
      const walk = (it, depth) => {
        if (!survives(it)) return;
        body.append(renderItem(it, id, ++n, depth, childrenBy));
        for (const k of (childrenBy[it.id] || []).sort((x, y) => x.sort - y.sort)) walk(k, depth + 1);
      };
      for (const it of roots) walk(it, 0);
      box.append(body);
    }
    list.append(box);
  });
  if (!shown) list.append(el('div', { className: 'empty', style: 'margin-top:26px' },
    `Nothing matches “${FILTER}”.`));

  // ── evidence dock
  const dock = el('aside', { className: 'dock' },
    el('div', { className: 'dock-head' },
      el('span', { className: 'kicker' }, 'Evidence log'),
      el('button', { className: 'btn line sm', style: 'margin-left:auto', onclick: () => addFinding(id) }, '+ Capture')));
  const dbody = el('div', { className: 'dock-body' });
  if (!a.findings.length) dbody.append(el('div', { className: 'pmeta', style: 'padding:4px 2px;line-height:1.7' },
    'Nothing captured yet. Save raw requests, credentials and confirmed vulnerabilities here — the export is built from them.'));
  for (const f of a.findings) {
    const tools = el('div', { className: 'f-tools' },
      el('button', { className: 'ibtn', title: 'Add image', onclick: () => uploadToFinding(f.id, id) }, icon('image', 11)),
      el('button', { className: 'ibtn', title: 'Edit', onclick: () => editFinding(f, id) }, icon('edit', 11)),
      el('button', { className: 'ibtn del', title: 'Delete', onclick: async () => { if (confirm('Delete this finding and its images?')) { await api('/findings/' + f.id, { method: 'DELETE' }); renderTarget(id); } } }, icon('x', 11)));
    const shots = el('div', { className: 'f-shots' });
    for (const im of (f.attachments || [])) {
      const thumb = el('img', { src: '/api/attachments/' + im.id, title: im.filename, loading: 'lazy' });
      thumb.onclick = () => lightbox('/api/attachments/' + im.id, im.filename);
      const x = el('button', { className: 'shotx', title: 'Remove image', onclick: async (e) => { e.stopPropagation(); await api('/attachments/' + im.id, { method: 'DELETE' }); renderTarget(id); } }, '✕');
      shots.append(el('span', { className: 'f-shot' }, thumb, x));
    }
    dbody.append(el('div', { className: 'finding sev-' + (f.severity || 'info') },
      el('div', { className: 'f-top' },
        f.severity ? el('span', { className: 'f-sev' }, f.severity) : null,
        el('span', { className: 'f-kind' }, f.kind), tools),
      el('div', { className: 'f-title' }, f.title),
      f.body ? el('pre', {}, f.body) : null,
      (f.attachments || []).length ? shots : null));
  }
  dock.append(dbody);

  const y = $('.target-col')?.scrollTop || 0;
  $('#view').replaceChildren(el('div', { className: 'target' },
    el('div', { className: 'target-col' }, head, list), dock));
  const col = $('.target-col'); if (col) col.scrollTop = y;
}

function renderItem(it, assetId, num, depth, childrenBy = {}) {
  const isTrigger = it.kind === 'trigger';
  const isSelect = it.kind === 'select';
  const isGroup = it.kind === 'group';
  const kids = childrenBy[it.id] || [];
  const hasGroup = kids.some(k => k.kind === 'group');
  const node = el('div', {
    className: 'item' + (depth ? ' child' : '')
      + (it.status === 'done' || it.status === 'yes' ? ' done' : '')
      + (it.status === 'na' || it.status === 'no' ? ' na' : '')
      + (it.status === 'flag' ? ' flag' : ''),
    style: depth ? `margin-left:${Math.min(depth, 3) * 30}px` : '',
  });

  const body = el('div', { className: 'ibody' });
  const row = el('div', { className: 'irow' }, el('span', { className: 'ititle' }, it.title));
  if (it.kind !== 'check') row.append(el('span', { className: 'tag ' + it.kind }, it.kind));
  const pcount = it.payloads?.length || 0;
  const pOpen = openPayloads.has(it.id);
  if (pcount) row.append(el('button', {
    className: 'ptoggle',
    onclick: () => { pOpen ? openPayloads.delete(it.id) : openPayloads.add(it.id); renderTarget(assetId); },
  }, `${pOpen ? '▾' : '▸'} ${pcount} payload${pcount > 1 ? 's' : ''}`));
  body.append(row);
  if (it.detail) body.append(el('p', { className: 'detail' }, subst(it.detail)));

  if (isSelect) {
    const chosen = new Set(kids.map(k => k.opt_key));
    const chips = el('div', { className: 'chips' });
    for (const o of (it.options || [])) {
      const on = chosen.has(o.key);
      chips.append(el('button', {
        className: 'chip' + (on ? ' on' : ''),
        onclick: async () => { await api('/items/' + it.id + '/select', { method: 'POST', body: { key: o.key } }); renderTarget(assetId); },
      }, (on ? '✓ ' : '') + o.label));
    }
    body.append(chips);
  }

  if (pcount && pOpen) {
    const box = el('div', { className: 'payloads' });
    for (const p of it.payloads) {
      const val = subst(p);
      const c = el('code', { title: 'click to copy' }, val);
      c.onclick = () => { navigator.clipboard?.writeText(val); toast('Copied'); };
      box.append(c);
    }
    body.append(box);
  }

  if (it.kind === 'question' || it.kind === 'input') {
    const ta = el('input', { className: 'answer', value: it.answer || '', placeholder: 'record answer…' });
    let tmr;
    ta.oninput = () => { clearTimeout(tmr); tmr = setTimeout(() => api('/items/' + it.id, { method: 'PATCH', body: { answer: ta.value } }), 500); };
    body.append(ta);
  }

  if (isTrigger && it.spawns) {
    body.append(el('div', { className: 'spawnbtn' },
      el('button', { className: 'btn line sm', onclick: () => doSpawn(it, assetId) },
        hasGroup ? '+ Add another follow-up' : '+ Add follow-up checklist')));
  }

  // status + tools
  const actions = el('div', { className: 'iactions' });
  if (!isSelect && !isGroup) {
    const stBox = el('div', { className: 'status' });
    const opts = isTrigger
      ? [{ k: 'yes', i: 'check', c: 'done', t: 'Yes' }, { k: 'no', i: 'na', c: 'na', t: 'No' }, { k: 'flag', i: 'flag', c: 'flag', t: 'Finding' }]
      : [{ k: 'done', i: 'check', c: 'done', t: 'Handled' }, { k: 'flag', i: 'flag', c: 'flag', t: 'Finding' }, { k: 'na', i: 'na', c: 'na', t: 'Not applicable' }];
    for (const s of opts) {
      const b = el('button', { className: 'st ' + s.c + (it.status === s.k ? ' on-' + s.c : ''), title: s.t }, icon(s.i, 12));
      b.onclick = async () => {
        const next = it.status === s.k ? 'todo' : s.k;
        await api('/items/' + it.id, { method: 'PATCH', body: { status: next } });
        it.status = next;
        if (isTrigger && next === 'yes' && it.spawns && !hasGroup) return doSpawn(it, assetId);
        renderTarget(assetId);
      };
      stBox.append(b);
    }
    actions.append(stBox);
  }
  actions.append(el('div', { className: 'itools' },
    el('button', { className: 'ibtn', title: 'Add sub-item', onclick: () => itemModal(assetId, null, it.id) }, icon('plus', 12)),
    el('button', { className: 'ibtn', title: 'Edit', onclick: () => itemModal(assetId, it) }, icon('edit', 12)),
    el('button', {
      className: 'ibtn del', title: 'Delete',
      onclick: async () => { if (confirm(kids.length ? 'Delete this item and everything under it?' : 'Delete this item?')) { await api('/items/' + it.id, { method: 'DELETE' }); renderTarget(assetId); } },
    }, icon('x', 12))));

  node.append(el('span', { className: 'inum' }, pad(num)), body, actions);
  return node;
}

async function doSpawn(it, assetId) {
  const r = await api('/items/' + it.id + '/spawn', { method: 'POST' });
  toast(r.instance > 1 ? `Added follow-up #${r.instance}` : `Added ${r.added} items`);
  renderTarget(assetId);
}

function itemModal(assetId, item = null, parentId = null) {
  const editing = !!item;
  const kinds = KIND_OPTS.filter(k => k.value !== 'select' || item?.kind === 'select');
  modal({
    kicker: editing ? 'Edit' : 'Checklist',
    title: editing ? 'Edit item' : (parentId ? 'Add sub-item' : 'Add checklist item'),
    cta: editing ? 'Save' : 'Add item',
    build: (b) => {
      field(b, 'Title', 'title', { value: item?.title || '', ph: 'What are you checking?' });
      if (!parentId) field(b, 'Section', 'group_title', { value: item?.group_title || 'Custom / Notes' });
      field(b, 'Detail', 'detail', { value: item?.detail || '', textarea: true, ph: 'How to check it, and what counts as a finding' });
      field(b, 'Payloads (one per line)', 'payloads', { value: (item?.payloads || []).join('\n'), textarea: true });
      field(b, 'Kind', 'kind', { value: item?.kind || 'check', options: kinds });
    },
    onSubmit: async (fd) => {
      const o = Object.fromEntries(fd);
      o.payloads = (o.payloads || '').split('\n').map(s => s.trim()).filter(Boolean);
      if (editing) await api('/items/' + item.id, { method: 'PATCH', body: o });
      else {
        if (parentId) o.parent_id = parentId;
        else openGroups.add(o.group_title === 'Custom / Notes' ? 'custom' : o.group_title);
        await api(`/assets/${assetId}/items`, { method: 'POST', body: o });
      }
      renderTarget(assetId);
    },
  });
}

const FINDING_KINDS = [{ value: 'note', label: 'Note' }, { value: 'credential', label: 'Credential' },
{ value: 'vuln', label: 'Vulnerability' }];
const SEVERITIES = [{ value: '', label: '—' }, { value: 'info', label: 'Info' }, { value: 'low', label: 'Low' },
{ value: 'medium', label: 'Medium' }, { value: 'high', label: 'High' }, { value: 'critical', label: 'Critical' }];

// A multi-image picker that collects files into `bucket` (handled outside FormData).
function fileField(parent, label, bucket) {
  parent.append(el('label', {}, label));
  const inp = el('input', { type: 'file', accept: 'image/*', multiple: true });
  const info = el('div', { className: 'muted small' });
  inp.onchange = () => { bucket.length = 0; bucket.push(...inp.files); info.textContent = bucket.length ? `${bucket.length} image(s) selected` : ''; };
  parent.append(inp, info);
}

// Add (finding=null) or edit a finding. The fields shown depend on the kind:
//   note        → title + details (no severity, no images)
//   credential  → title + username / password / server
//   vuln        → title + severity + location + explanation + images
function findingModal(assetId, finding = null) {
  const editing = !!finding;
  const startKind = finding?.kind === 'request' ? 'note' : (finding?.kind || 'note');
  const images = []; // selected images for a new vuln
  modal({
    kicker: 'Evidence', title: editing ? 'Edit finding' : 'Capture evidence', cta: 'Save',
    note: editing ? 'Update the finding. Attached images stay put.'
      : 'Notes, credentials and confirmed vulnerabilities — these become the findings in the report.',
    build: (b) => {
      const kindSel = field(b, 'Type', 'kind', { value: startKind, options: FINDING_KINDS });
      const fields = el('div', { className: 'kindfields' });
      b.append(fields);
      const rebuild = () => {
        fields.replaceChildren();
        const k = kindSel.value;
        if (k === 'note') {
          field(fields, 'Title', 'title', { value: finding?.title || '', ph: 'What you found' });
          field(fields, 'Details', 'body', { value: finding?.body || '', textarea: true, ph: 'notes…' });
        } else if (k === 'credential') {
          field(fields, 'Title', 'title', { value: finding?.title || '', ph: 'e.g. admin panel login' });
          field(fields, 'Username', 'cred_user', { ph: 'user' });
          field(fields, 'Password', 'cred_pass', { ph: 'pass' });
          field(fields, 'Server / URL', 'cred_server', { ph: 'https://…  or  host' });
        } else {
          field(fields, 'Title', 'title', { value: finding?.title || '', ph: 'e.g. SQL injection in /search' });
          field(fields, 'Severity', 'severity', { value: finding?.severity || 'medium', options: SEVERITIES.filter(s => s.value) });
          field(fields, 'Location (URL / domain)', 'location', { ph: 'https://app/search?q=' });
          field(fields, 'Explanation', 'body', { value: finding?.body || '', textarea: true, ph: 'how it was found / impact' });
          if (!editing) fileField(fields, 'Images (screenshots)', images);
        }
      };
      kindSel.onchange = rebuild;
      rebuild();
    },
    onSubmit: async (fd) => {
      const raw = Object.fromEntries(fd);
      const kind = raw.kind;
      let body = raw.body || '', severity = null;
      if (kind === 'credential') {
        body = `Username: ${raw.cred_user || ''}\nPassword: ${raw.cred_pass || ''}\nServer: ${raw.cred_server || ''}`;
      } else if (kind === 'vuln') {
        severity = raw.severity || null;
        body = (raw.location ? `Location: ${raw.location}\n\n` : '') + (raw.body || '');
      }
      const title = raw.title || (kind === 'credential' ? 'Credentials' : kind === 'vuln' ? 'Vulnerability' : 'Note');
      const payload = { title, kind, severity, body };
      if (editing) { await api('/findings/' + finding.id, { method: 'PATCH', body: payload }); }
      else {
        const f = await api(`/assets/${assetId}/findings`, { method: 'POST', body: payload });
        for (const file of images) {
          if (!file.type.startsWith('image/')) continue;
          try {
            await fetch(`/api/findings/${f.id}/attachments`, { method: 'POST',
              headers: { 'content-type': file.type, 'x-filename': encodeURIComponent(file.name) }, body: await file.arrayBuffer() });
          } catch { /* one bad image shouldn't lose the finding */ }
        }
      }
      renderTarget(assetId);
    },
  });
}
const addFinding = (assetId) => findingModal(assetId, null);
const editFinding = (finding, assetId) => findingModal(assetId, finding);

// Upload one or more images to a finding via the raw endpoint (no base64 bloat).
function uploadToFinding(findingId, assetId) {
  const picker = el('input', { type: 'file', accept: 'image/*', multiple: true, style: 'display:none' });
  picker.onchange = async () => {
    const files = [...picker.files]; picker.remove();
    if (!files.length) return;
    try {
      for (const f of files) {
        if (!f.type.startsWith('image/')) { toast(`${f.name}: not an image, skipped`); continue; }
        const r = await fetch(`/api/findings/${findingId}/attachments`, {
          method: 'POST',
          headers: { 'content-type': f.type || 'application/octet-stream', 'x-filename': encodeURIComponent(f.name) },
          body: await f.arrayBuffer(),
        });
        if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.statusText);
      }
      toast(files.length > 1 ? `Added ${files.length} images` : 'Image added');
    } catch (e) { alert('Upload failed: ' + e.message); }
    renderTarget(assetId);
  };
  document.body.append(picker); picker.click();
}

// Full-size image overlay.
function lightbox(src, caption) {
  const root = $('#modalRoot');
  const close = () => root.replaceChildren();
  root.replaceChildren(el('div', { className: 'lightbox', onclick: close },
    el('img', { src }),
    caption ? el('div', { className: 'lb-cap' }, caption) : null));
}

function download(body, filename, mime) {
  const blob = new Blob([body], { type: mime });
  const url = URL.createObjectURL(blob);
  const link = el('a', { href: url, download: filename });
  document.body.append(link); link.click(); link.remove(); URL.revokeObjectURL(url);
}

// Two kinds of export: a human-readable report, and a re-importable project file.
function exportProjectMenu(id, name) {
  const safe = (name || 'project').replace(/[^a-z0-9._-]+/gi, '-').slice(0, 60);
  modal({
    kicker: 'Export', title: 'Export engagement',
    note: 'A report is for reading and sharing findings. A project file round-trips back into Magi — it carries the whole engagement, including credentials and raw requests, so treat it as client-confidential.',
    cta: 'Close', build: (b) => {
      const row = (title, sub, fn) => {
        const el2 = el('button', { type: 'button', className: 'type', style: 'width:100%;margin-top:10px', onclick: async () => { await fn(); $('#modalRoot').replaceChildren(); } },
          el('span', { className: 'lbl' }, title), el('span', { className: 'hint' }, sub));
        return el2;
      };
      b.append(
        row('HTML findings report', 'A polished, self-contained page of your notes and vulnerabilities, screenshots embedded. Opens anywhere.',
          async () => {
            const html = await api(`/projects/${id}/report.html`);
            download(typeof html === 'string' ? html : String(html), `magi-findings-${safe}.html`, 'text/html');
            toast('HTML report exported');
          }),
        row('Markdown report', 'A readable summary of targets, checklist state and findings.',
          async () => { download(await api(`/projects/${id}/export`), `magi-report-${safe}.md`, 'text/markdown'); toast('Report exported'); }),
        row('Project file (.json)', 'The complete engagement, re-importable into another Magi. Confidential.',
          async () => {
            const text = await api(`/projects/${id}/bundle`);
            download(typeof text === 'string' ? text : JSON.stringify(text, null, 2), `magi-project-${safe}.json`, 'application/json');
            toast('Project file exported');
          }));
    },
    onSubmit: async () => { },   // the two rows do the work; the CTA just closes
  });
}

// Pick a project .json, preview it, then import as a brand-new engagement.
function importProjectFile() {
  const picker = el('input', { type: 'file', accept: '.json,application/json', style: 'display:none' });
  picker.onchange = async () => {
    const file = picker.files[0]; picker.remove();
    if (!file) return;
    let bundle;
    try { bundle = JSON.parse(await file.text()); }
    catch { return alert('That file is not valid JSON.'); }
    let pv;
    try { pv = await api('/projects/import/preview', { method: 'POST', body: bundle }); }
    catch (e) { return alert('Not a Magi project file: ' + e.message); }

    modal({
      kicker: 'Import', title: 'Import engagement',
      note: `${file.name}${pv.exported ? ' · exported ' + new Date(pv.exported).toLocaleDateString() : ''}`,
      cta: 'Import', build: (b) => {
        b.append(el('div', { className: 'tpl-panel', style: 'margin:14px 0' },
          el('div', { className: 'tpl-row' },
            el('span', { className: 'num' }, '◆'),
            el('div', { className: 'body' },
              el('div', { className: 't' }, pv.name + (pv.client ? '  ·  ' + pv.client : '')),
              el('div', { className: 'd' }, `${pv.assets} target(s) · ${pv.items} checklist item(s) · ${pv.findings} finding(s)`)))));
        field(b, 'Import as (leave blank to keep the name)', 'name', { value: '', ph: pv.name });
        b.append(el('p', { className: 'modal-note' }, 'This always creates a new engagement — it never touches an existing one.'));
      },
      onSubmit: async (fd) => {
        const r = await api('/projects/import', { method: 'POST', body: { bundle, name: (fd.get('name') || '').trim() || undefined } });
        toast(`Imported ${r.assets} target(s)`);
        location.hash = `/project/${r.projectId}`;
      },
    });
  };
  document.body.append(picker); picker.click();
}

// ---------- template library ----------
async function renderEditor(type) {
  const types = await api('/templates');
  const active = type || types[0]?.type;
  setRail(null);
  setCrumbs([{ label: 'library' }]);
  topActions(
    el('button', { className: 'btn', onclick: importTemplates, title: 'Import checklist templates from a file' }, icon('up', 12), 'Import'),
    el('button', { className: 'btn', onclick: () => exportTemplates(), title: 'Export every asset type as one file' }, icon('down', 12), 'Export all'),
    el('button', { className: 'btn line', onclick: newType }, icon('plus', 12), 'Asset type'));

  const side = el('div', { className: 'tpl-side' });
  const typeBtn = (t) => el('button', {
    className: 'tpl-type' + (t.type === active ? ' on' : ''),
    onclick: () => location.hash = `/editor/${t.type}`,
  }, el('span', { className: 'tt-label' }, `${t.icon || ''} ${t.label}`),
    el('span', { className: 'tt-count' }, String(t.item_count)));
  for (const g of GROUP_ORDER) {
    const inG = types.filter(t => (t.grp || 'additional') === g.key);
    if (!inG.length) continue;
    side.append(el('div', { className: 'kicker', style: 'padding:10px 12px 4px' }, g.label));
    for (const t of inG) side.append(typeBtn(t));
  }
  // any types with an unknown group still show up
  const shown = new Set(GROUP_ORDER.map(g => g.key));
  const orphans = types.filter(t => !shown.has(t.grp || 'additional'));
  for (const t of orphans) side.append(typeBtn(t));
  side.append(el('button', { className: 'dashbtn', style: 'margin-top:8px', onclick: newType }, '+ New asset type'));

  const panel = el('div', { className: 'tpl-panel' });
  if (active) {
    const t = await api('/templates/' + active);
    const sections = [];
    for (const it of t.items) {
      const s = sections[sections.length - 1];
      if (!s || s.title !== it.group_title) sections.push({ title: it.group_title, items: [it] });
      else s.items.push(it);
    }
    panel.append(el('div', { className: 'tpl-head' },
      el('h2', {}, `${t.icon || ''} ${t.label}`),
      el('span', { className: 'meta' }, `${t.items.length} items · ${sections.length} sections · ${t.catalogs.length} catalogs`),
      el('div', { style: 'display:flex;gap:6px;margin-left:auto' },
        el('button', { className: 'btn sm', onclick: () => editType(t) }, 'Edit'),
        el('button', { className: 'btn sm', onclick: () => tplItemModal(t.type) }, '+ Item'),
        el('button', { className: 'btn sm', onclick: () => exportTemplates(t.type), title: 'Export this asset type to a file' }, '⬇ Export'),
        el('button', { className: 'btn sm', onclick: () => resetTypeDefaults(t) }, '↺ Defaults'),
        el('button', { className: 'btn sm danger', onclick: () => delType(t) }, 'Delete'))));

    sections.forEach((s, si) => {
      panel.append(el('div', { className: 'tpl-sec' }, el('span', { className: 'kicker' }, `${pad(si + 1)} · ${s.title}`)));
      for (const it of s.items) {
        panel.append(el('div', { className: 'tpl-row' },
          el('span', { className: 'num' }, ''),
          el('div', { className: 'body' },
            el('div', { style: 'display:flex;align-items:baseline;gap:8px;flex-wrap:wrap' },
              el('span', { className: 't' }, it.title),
              it.kind !== 'check' ? el('span', { className: 'tag ' + it.kind }, it.kind) : null,
              it.spawns ? el('span', { className: 'tag' }, 'spawns:' + it.spawns) : null,
              it.catalog ? el('span', { className: 'tag select' }, 'catalog:' + it.catalog) : null),
            it.detail ? el('div', { className: 'd' }, it.detail) : null),
          el('span', { className: 'tpl-count' }, it.payloads.length ? `${it.payloads.length} pl` : ''),
          el('div', { className: 'itools' },
            el('button', { className: 'ibtn', title: 'Edit', onclick: () => tplItemModal(t.type, it) }, icon('edit', 12)),
            el('button', {
              className: 'ibtn del', title: 'Delete',
              onclick: async () => { if (confirm('Delete this default item?')) { await api('/tpl-items/' + it.id, { method: 'DELETE' }); renderEditor(t.type); } },
            }, icon('x', 12)))));
      }
    });
    if (!t.items.length) panel.append(el('div', { className: 'empty', style: 'border:0' }, 'No items yet.'));

    // follow-up checklists and catalogs
    panel.append(el('div', { className: 'tpl-sec' },
      el('span', { className: 'kicker' }, 'Follow-ups & catalogs'),
      el('button', { className: 'btn line sm', style: 'float:right;margin-top:-4px', onclick: () => groupModal(t.type) }, '+ Group')));
    for (const g of t.groups) {
      panel.append(el('div', { className: 'tpl-row', style: 'cursor:pointer', onclick: () => location.hash = `/group/${g.id}` },
        el('span', { className: 'num' }, g.kind === 'spawn' ? '↳' : '◆'),
        el('div', { className: 'body' },
          el('div', { style: 'display:flex;align-items:baseline;gap:8px;flex-wrap:wrap' },
            el('span', { className: 't' }, g.title),
            el('span', { className: 'tag ' + (g.kind === 'spawn' ? 'trigger' : 'select') },
              g.kind === 'spawn' ? 'spawns:' + g.gkey : `${g.catalog}:${g.gkey}`))),
        el('span', { className: 'tpl-count' }, `${g.item_count} items`)));
    }
    if (!t.groups.length) panel.append(el('div', { className: 'tpl-row' },
      el('span', { className: 'num' }, ''), el('div', { className: 'body' },
        el('div', { className: 'd' }, 'No follow-up checklists or catalogs for this type yet.'))));
  }

  $('#view').replaceChildren(el('div', { className: 'page' },
    el('div', { className: 'kicker' }, 'Library'),
    el('h1', {}, 'Checklist templates'),
    el('p', { className: 'lede' }, 'Every new target is seeded from its asset type. Edit once — every future engagement inherits it. Existing targets are never changed.'),
    el('div', { className: 'tpl-layout' }, side, panel)));
}

function newType() {
  modal({
    kicker: 'Library', title: 'New asset type', cta: 'Create',
    build: (b) => {
      field(b, 'Key (lowercase, no spaces)', 'type', { ph: 'thickclient' });
      field(b, 'Label', 'label', { ph: 'Thick Client' });
      field(b, 'Engagement group', 'grp', { value: 'additional', options: GROUP_ORDER.map(g => ({ value: g.key, label: g.label })) });
      field(b, 'Icon (emoji)', 'icon', { ph: '▣' });
      field(b, 'Example hint', 'hint', { ph: 'app.exe' });
    },
    onSubmit: async (fd) => {
      const t = await api('/templates', { method: 'POST', body: Object.fromEntries(fd) });
      location.hash = `/editor/${t.type}`;
    },
  });
}
function editType(t) {
  modal({
    kicker: 'Edit', title: 'Edit asset type', cta: 'Save',
    build: (b) => {
      field(b, 'Label', 'label', { value: t.label });
      field(b, 'Icon', 'icon', { value: t.icon || '' });
      field(b, 'Example hint', 'hint', { value: t.hint || '' });
    },
    onSubmit: async (fd) => { await api('/templates/' + t.type, { method: 'PATCH', body: Object.fromEntries(fd) }); renderEditor(t.type); },
  });
}
function delType(t) {
  modal({
    kicker: 'Destructive', title: `Delete asset type “${t.label}”?`, danger: true, cta: 'Delete',
    note: 'Targets you already created keep their checklists. Only the template is removed.',
    onSubmit: async () => { await api('/templates/' + t.type, { method: 'DELETE' }); location.hash = '/editor'; },
  });
}
async function resetTypeDefaults(t) {
  modal({
    kicker: 'Restore', title: `Restore defaults for “${t.label}”?`, danger: true, cta: 'Restore',
    note: 'Reinstalls the shipped checklist for this type. Your template edits for it are discarded. Existing targets are not changed.',
    onSubmit: async () => {
      const r = await api(`/templates/${t.type}/reset`, { method: 'POST' });
      toast(`Restored ${r.items} items`); renderEditor(t.type);
    },
  });
}
// ---- share templates ----
// Download the given type (or everything, when type is omitted) as a portable bundle.
async function exportTemplates(type) {
  const path = type ? `/templates/${type}/export` : '/templates/export';
  const text = await api(path);                    // api() returns text for non-JSON content types
  const body = typeof text === 'string' ? text : JSON.stringify(text, null, 2);
  const blob = new Blob([body], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = el('a', { href: url, download: type ? `magi-template-${type}.json` : 'magi-templates.json' });
  document.body.append(link); link.click(); link.remove(); URL.revokeObjectURL(url);
  toast(type ? `Exported ${type}` : 'Exported all templates');
}

// Pick a .json file, preview what it would do, let the user choose the conflict mode.
function importTemplates() {
  const picker = el('input', { type: 'file', accept: '.json,application/json', style: 'display:none' });
  picker.onchange = async () => {
    const file = picker.files[0]; picker.remove();
    if (!file) return;
    let bundle;
    try { bundle = JSON.parse(await file.text()); }
    catch { return alert('That file is not valid JSON.'); }
    let preview;
    try { preview = await api('/templates/import/preview', { method: 'POST', body: bundle }); }
    catch (e) { return alert('Not a Magi template file: ' + e.message); }

    const anyConflict = preview.types.some(t => t.exists);
    modal({
      kicker: 'Import', title: 'Import checklist templates',
      note: `${file.name} · ${preview.types.length} asset type${preview.types.length === 1 ? '' : 's'}`
        + (preview.exported ? ` · exported ${new Date(preview.exported).toLocaleDateString()}` : ''),
      cta: 'Import', build: (b) => {
        const list = el('div', { className: 'tpl-panel', style: 'margin:14px 0' });
        for (const t of preview.types) {
          list.append(el('div', { className: 'tpl-row' },
            el('span', { className: 'num' }, t.icon || '◆'),
            el('div', { className: 'body' },
              el('div', { className: 't' }, t.label + '  '),
              el('div', { className: 'd' }, `${t.items} items · ${t.groups} follow-up/catalog groups`)),
            el('span', { className: t.exists ? 'tag trigger' : 'tag' }, t.exists ? 'already exists' : 'new')));
        }
        b.append(list);
        if (anyConflict) {
          field(b, 'Some of these already exist — what should happen?', 'onConflict', {
            value: 'skip', options: [
              { value: 'skip', label: 'Skip the ones that already exist' },
              { value: 'rename', label: 'Import them under a new key (keep both)' },
              { value: 'replace', label: 'Overwrite the existing ones' }],
          });
          b.append(el('p', { className: 'modal-note' }, 'Overwriting discards your current version of that asset type. Existing targets already created from it are never changed.'));
        }
      },
      onSubmit: async (fd) => {
        const onConflict = fd.get('onConflict') || 'skip';
        const r = await api('/templates/import', { method: 'POST', body: { bundle, onConflict } });
        const made = r.results.filter(x => x.action !== 'skipped (already exists)').length;
        toast(made ? `Imported ${made} asset type${made === 1 ? '' : 's'}` : 'Nothing imported (all skipped)');
        renderEditor();
      },
    });
  };
  document.body.append(picker); picker.click();
}

function groupModal(type) {
  modal({
    kicker: 'Library', title: 'New follow-up or catalog', cta: 'Create',
    note: 'A follow-up is what a trigger item spawns. A catalog entry is what one option of a select item unfolds.',
    build: (b) => {
      field(b, 'Purpose', 'kind', {
        value: 'spawn', options: [
          { value: 'spawn', label: 'Follow-up checklist (a trigger spawns it)' },
          { value: 'catalog', label: 'Catalog entry (a select option unfolds it)' }]
      });
      field(b, 'Catalog name (catalog entries only)', 'catalog', { ph: 'tech' });
      field(b, 'Key', 'gkey', { ph: 'login' });
      field(b, 'Title', 'title', { ph: 'Login attack checklist' });
    },
    onSubmit: async (fd) => {
      const g = await api(`/templates/${type}/groups`, { method: 'POST', body: Object.fromEntries(fd) });
      location.hash = `/group/${g.id}`;
    },
  });
}

async function renderGroup(id) {
  const g = await api('/tpl-groups/' + id);
  setRail(null);
  setCrumbs([
    { label: 'library', go: () => location.hash = '/editor' },
    { label: g.type, go: () => location.hash = `/editor/${g.type}` },
    { label: g.gkey }]);
  topActions(
    el('button', { className: 'btn', onclick: () => editGroup(g) }, 'Rename'),
    el('button', { className: 'btn line', onclick: () => groupItemModal(g.id) }, '+ Item'),
    el('button', { className: 'btn danger', onclick: () => delGroup(g) }, 'Delete'));

  const wiring = g.kind === 'spawn'
    ? `Used by any trigger item whose “spawns” is set to ${g.gkey}.`
    : `Used by a select item with catalog “${g.catalog}” and an option keyed ${g.gkey}.`;
  const panel = el('div', { className: 'tpl-panel', style: 'margin-top:22px' });
  for (const it of g.items) {
    panel.append(el('div', { className: 'tpl-row' },
      el('span', { className: 'num' }, ''),
      el('div', { className: 'body' },
        el('div', { style: 'display:flex;align-items:baseline;gap:8px;flex-wrap:wrap' },
          el('span', { className: 't' }, it.title),
          it.kind !== 'check' ? el('span', { className: 'tag ' + it.kind }, it.kind) : null,
          it.spawns ? el('span', { className: 'tag trigger' }, 'spawns:' + it.spawns) : null),
        it.detail ? el('div', { className: 'd' }, it.detail) : null),
      el('span', { className: 'tpl-count' }, it.payloads.length ? `${it.payloads.length} pl` : ''),
      el('div', { className: 'itools' },
        el('button', { className: 'ibtn', title: 'Edit', onclick: () => groupItemModal(g.id, it) }, icon('edit', 12)),
        el('button', {
          className: 'ibtn del', title: 'Delete',
          onclick: async () => { if (confirm('Delete this item?')) { await api('/tpl-group-items/' + it.id, { method: 'DELETE' }); renderGroup(id); } },
        }, icon('x', 12)))));
  }
  if (!g.items.length) panel.append(el('div', { className: 'empty', style: 'border:0' }, 'No items yet.'));

  $('#view').replaceChildren(el('div', { className: 'page' },
    el('div', { className: 'kicker' }, g.kind === 'spawn' ? 'Follow-up checklist' : 'Catalog entry'),
    el('h1', {}, g.title),
    el('p', { className: 'lede' }, wiring),
    panel));
}
function editGroup(g) {
  modal({
    kicker: 'Edit', title: 'Rename', cta: 'Save',
    build: (b) => field(b, 'Title', 'title', { value: g.title }),
    onSubmit: async (fd) => { await api('/tpl-groups/' + g.id, { method: 'PATCH', body: Object.fromEntries(fd) }); renderGroup(g.id); },
  });
}
function delGroup(g) {
  modal({
    kicker: 'Destructive', title: `Delete “${g.title}”?`, danger: true, cta: 'Delete',
    note: `Triggers pointing at “${g.gkey}” will stop spawning anything.`,
    build: (b) => b.append(el('div', { className: 'dangerbox' },
      el('div', { className: 'kicker' }, 'Irreversible'),
      el('ul', { className: 'dellist' }, el('li', {}, `${g.items.length} template items`)))),
    onSubmit: async () => { await api('/tpl-groups/' + g.id, { method: 'DELETE' }); location.hash = `/editor/${g.type}`; },
  });
}
function groupItemModal(groupId, item = null) {
  const editing = !!item;
  modal({
    kicker: editing ? 'Edit' : 'Checklist', title: editing ? 'Edit item' : 'Add item',
    cta: editing ? 'Save' : 'Add',
    build: (b) => {
      field(b, 'Title', 'title', { value: item?.title || '' });
      field(b, 'Detail', 'detail', { value: item?.detail || '', textarea: true });
      field(b, 'Payloads (one per line)', 'payloads', { value: (item?.payloads || []).join('\n'), textarea: true });
      field(b, 'Kind', 'kind', { value: item?.kind || 'check', options: KIND_OPTS.filter(k => k.value !== 'select') });
      field(b, 'Spawns (nested follow-up key)', 'spawns', { value: item?.spawns || '' });
    },
    onSubmit: async (fd) => {
      const o = Object.fromEntries(fd);
      o.payloads = (o.payloads || '').split('\n').map(s => s.trim()).filter(Boolean);
      if (editing) await api('/tpl-group-items/' + item.id, { method: 'PATCH', body: o });
      else await api(`/tpl-groups/${groupId}/items`, { method: 'POST', body: o });
      renderGroup(groupId);
    },
  });
}
function tplItemModal(type, item = null) {
  const editing = !!item;
  modal({
    kicker: editing ? 'Edit' : 'Library', title: editing ? 'Edit default item' : 'Add default item',
    cta: editing ? 'Save' : 'Add',
    build: (b) => {
      field(b, 'Title', 'title', { value: item?.title || '' });
      field(b, 'Section', 'group_title', { value: item?.group_title || 'Custom' });
      field(b, 'Detail', 'detail', { value: item?.detail || '', textarea: true });
      field(b, 'Payloads (one per line)', 'payloads', { value: (item?.payloads || []).join('\n'), textarea: true });
      field(b, 'Kind', 'kind', { value: item?.kind || 'check', options: KIND_OPTS });
      field(b, 'Spawns (trigger → follow-up key)', 'spawns', { value: item?.spawns || '', ph: 'login' });
      field(b, 'Catalog (select → catalog key)', 'catalog', { value: item?.catalog || '', ph: 'tech' });
      field(b, 'Options for select (key:Label per line)', 'options', { value: (item?.options || []).map(o => `${o.key}:${o.label}`).join('\n'), textarea: true });
    },
    onSubmit: async (fd) => {
      const o = Object.fromEntries(fd);
      o.payloads = (o.payloads || '').split('\n').map(s => s.trim()).filter(Boolean);
      o.options = (o.options || '').split('\n').map(s => s.trim()).filter(Boolean)
        .map(l => { const i = l.indexOf(':'); return i < 0 ? { key: l, label: l } : { key: l.slice(0, i).trim(), label: l.slice(i + 1).trim() }; });
      if (editing) await api('/tpl-items/' + item.id, { method: 'PATCH', body: o });
      else await api(`/templates/${type}/items`, { method: 'POST', body: o });
      renderEditor(type);
    },
  });
}

// ---------- settings: team server link ----------
async function renderSettings() {
  setRail(null);
  setCrumbs([{ label: 'engagements', go: () => location.hash = '' }, { label: 'settings' }]);
  topActions();
  try { LINK = await api('/link'); } catch { LINK = { linked: false, unavailable: true }; }
  renderAccount();
  const view = $('#view');
  const page = el('div', { className: 'page' });
  page.append(el('div', { className: 'page-head' },
    el('div', {}, el('div', { className: 'kicker' }, 'Settings'), el('h1', {}, 'Team server'))));

  if (LINK.unavailable) {
    page.append(el('div', { className: 'empty' }, 'This instance is running as a server — linking is for client installs.'));
    return view.replaceChildren(page);
  }
  const kv = (k, v) => el('div', { className: 'kv' }, el('span', { className: 'k' }, k), el('span', { className: 'v' }, v));

  if (LINK.pending) {
    const L = LINK.link || {};
    page.append(el('div', { className: 'setcard' },
      el('div', { className: 'setcard-hd' }, el('span', { className: 'linkbadge pending' }, el('span', { className: 'dot' }), 'Waiting for approval')),
      el('p', { className: 'muted' }, 'Your request to join was sent. An admin on the server has to approve it before you are connected — this screen updates on its own when they do.'),
      kv('Server', L.server_url),
      kv('Requested as', `${L.display_name} · ${L.username}`),
      el('div', { className: 'setcard-actions' },
        el('button', { className: 'btn', onclick: checkApproval }, 'Check now'),
        el('button', { className: 'btn danger', onclick: cancelPending }, icon('x'), 'Cancel request'))));
    clearTimeout(window.__pendPoll);
    window.__pendPoll = setTimeout(() => { if (location.hash.startsWith('#/settings')) renderSettings(); }, 3000);
  } else if (!LINK.linked) {
    page.append(el('div', { className: 'setcard' },
      el('div', { className: 'setcard-hd' }, el('span', { className: 'linkbadge' }, el('span', { className: 'dot' }), 'Working locally')),
      el('p', { className: 'muted' }, 'Everything you create stays in this install. Connect to a team server to share engagements — you will need the server address, a one-time code from an admin, and a name. The admin then approves your request.'),
      el('div', { className: 'setcard-actions' },
        el('button', { className: 'btn gold', onclick: connectDialog }, icon('server'), 'Connect to a server'))));
  } else {
    const L = LINK.link || {};
    const atRest = L.token_at_rest === 'encrypted' ? el('span', { className: 'pill ok' }, 'encrypted · OS keychain')
      : L.token_at_rest === 'unencrypted' ? el('span', { className: 'pill warn' }, 'stored unencrypted — no keychain here')
        : el('span', { className: 'pill' }, L.token_at_rest || 'unknown');
    page.append(el('div', { className: 'setcard' },
      el('div', { className: 'setcard-hd' }, el('span', { className: 'linkbadge on' }, el('span', { className: 'dot' }), 'Linked')),
      kv('Server', L.server_url),
      kv('Signed as', `${L.display_name} · ${L.username} · ${L.role}`),
      kv('This device', L.device_id),
      kv('Fingerprint', el('code', { className: 'fp' }, L.fingerprint || '—')),
      el('div', { className: 'kv' }, el('span', { className: 'k' }, 'Token at rest'), el('span', { className: 'v' }, atRest)),
      kv('Connected', L.connected_at ? new Date(L.connected_at).toLocaleString() : '—'),
      kv('Last sync', L.last_sync ? new Date(L.last_sync).toLocaleString() : 'not yet'),
      el('p', { className: 'muted' }, 'Your work saves locally and syncs in the background. Offline changes are kept and sent when the server is reachable again.'),
      el('div', { className: 'setcard-actions' },
        el('button', { className: 'btn gold', onclick: syncNowUI }, icon('down'), 'Sync now'),
        el('button', { className: 'btn', onclick: pingLink }, 'Check connection'),
        el('button', { className: 'btn danger', onclick: disconnectDialog }, icon('exit'), 'Disconnect'))));
  }
  view.replaceChildren(page);
}
function connectDialog() {
  modal({
    kicker: 'Team server', title: 'Request to join a server', cta: 'Send request',
    note: 'Get the address and a one-time code from an admin; they approve your request before you are connected. Your local engagements are set aside on approval and restored if you disconnect.',
    build: (b) => {
      field(b, 'Server address', 'server_url', { ph: 'https://magi.corp.local:8443' });
      field(b, 'One-time code', 'code', { ph: 'from your admin' });
      field(b, 'Username', 'username', { ph: 'a new login name' });
      field(b, 'Your display name', 'display_name', { ph: 'shown on your changes, e.g. Ana R.' });
    },
    onSubmit: async (fd) => {
      const link = await api('/link/connect', { method: 'POST', body: Object.fromEntries(fd) });
      LINK = link.pending ? { linked: false, pending: true, link } : { linked: true, link };
      toast(link.pending ? 'Request sent — waiting for an admin to approve' : ('Linked to ' + link.server_url));
      renderSettings();
    },
  });
}
async function checkApproval() {
  try { await api('/link/approval'); } catch {}
  renderSettings();
}
function cancelPending() {
  modal({
    kicker: 'Team server', title: 'Cancel the join request?', cta: 'Yes, cancel', danger: true,
    note: 'Removes the pending request from this device. You can request again later.',
    onSubmit: async () => { await api('/link/disconnect', { method: 'POST' }); LINK = { linked: false }; toast('Request cancelled'); renderSettings(); },
  });
}
async function pingLink() {
  try {
    const r = await api('/link/ping');
    toast(r.online ? 'Server reachable'
      : r.revoked ? 'This device was revoked by the server — use Disconnect to return to local mode'
        : ('Server not reachable' + (r.error ? ` — ${r.error}` : '')));
    renderSettings();
  } catch (e) { toast('Ping failed: ' + e.message); }
}
async function syncNowUI() {
  try {
    const r = await api('/link/sync', { method: 'POST' });
    toast(r.ok ? (r.applied ? `Synced — ${r.applied} update(s) in` : 'Synced — up to date') : `Sync failed${r.error ? ' — ' + r.error : ''}`);
    renderSettings();
  } catch (e) { toast('Sync failed: ' + e.message); }
}
function disconnectDialog() {
  modal({
    kicker: 'Team server', title: 'Disconnect from the server?', cta: 'Disconnect', danger: true,
    note: 'Removes the stored credentials and the cached server data from this device, and restores the local engagements you had before connecting. The server keeps its copy.',
    onSubmit: async () => {
      await api('/link/disconnect', { method: 'POST' });
      LINK = { linked: false };
      toast('Disconnected');
      renderSettings();
    },
  });
}

// ---------- admin panel (server web + linked admin clients) ----------
let LAST_CODE = null; // a just-minted code to show once at the top of the panel
async function renderAdmin() {
  const ctx = adminCtx();
  if (!ctx) { location.hash = '/settings'; return; } // not an admin here
  setRail(null);
  setCrumbs([{ label: 'engagements', go: () => location.hash = '' }, { label: 'admin' }]);
  topActions(
    el('button', { className: 'btn', onclick: renderAdmin }, icon('down', 12), el('span', { className: 'lbl' }, 'Refresh')),
    el('button', { className: 'btn gold', onclick: () => mintCodeDialog(ctx) }, icon('plus', 12), el('span', { className: 'lbl' }, 'New code')));
  const view = $('#view');
  const page = el('div', { className: 'page' });
  page.append(el('div', { className: 'page-head' }, el('div', {}, el('div', { className: 'kicker' }, 'Team server'), el('h1', {}, 'Admin'))));
  const A = (p, o) => api(ctx.base + p, o);

  let requests = [], devices = [], codes = [], audit = [];
  try { [requests, devices, codes, audit] = await Promise.all([A('/requests'), A('/devices'), A('/enroll-codes'), A('/audit?limit=10')]); }
  catch (e) { page.append(el('div', { className: 'empty' }, 'Could not load admin data: ' + e.message)); return view.replaceChildren(page); }
  ADMIN_PENDING = requests.length; renderAccount();

  const card = (title) => el('div', { className: 'setcard' }, el('div', { className: 'setcard-hd' }, el('h3', {}, title)));
  const row = (info, ...actions) => el('div', { className: 'reqrow' }, el('div', { className: 'reqinfo' }, ...info), el('div', { className: 'reqactions' }, ...actions.filter(Boolean)));

  // Join requests
  const reqCard = card(`Join requests (${requests.length})`);
  if (!requests.length) reqCard.append(el('p', { className: 'muted' }, 'No pending requests.'));
  for (const r of requests) reqCard.append(row(
    [el('strong', {}, r.display_name), el('span', { className: 'muted' }, ' wants to join as '), el('span', { className: 'pill' }, r.role),
      el('div', { className: 'muted small' }, `username ${r.username} · device ${String(r.device_id).slice(0, 8)}… · ${new Date(r.created_at).toLocaleString()}`)],
    el('button', { className: 'btn gold', onclick: () => decide(ctx, r.id, 'approve', r.display_name) }, icon('check', 12), 'Approve'),
    el('button', { className: 'btn danger', onclick: () => decide(ctx, r.id, 'reject', r.display_name) }, icon('x', 12), 'Reject')));
  page.append(reqCard);

  // Devices
  const devCard = card(`Devices (${devices.filter(d => !d.revoked).length})`);
  if (!devices.length) devCard.append(el('p', { className: 'muted' }, 'No devices enrolled yet.'));
  for (const d of devices) devCard.append(row(
    [el('strong', { style: d.revoked ? 'text-decoration:line-through;opacity:.55' : '' }, d.display_name),
      el('span', { className: 'muted' }, ` · ${d.username} · `), el('span', { className: 'pill' }, d.role),
      el('div', { className: 'muted small' }, `last seen ${d.last_seen ? new Date(d.last_seen).toLocaleString() : 'never'}`)],
    ...(d.revoked
      ? [el('span', { className: 'pill warn' }, 'revoked'), el('button', { className: 'btn danger', onclick: () => removeDevice(ctx, d.id, d.display_name) }, icon('trash', 12), 'Remove')]
      : [el('button', { className: 'btn danger', onclick: () => revokeDevice(ctx, d.id, d.display_name) }, 'Revoke')])));
  page.append(devCard);

  // Codes
  const codeCard = card('Enrollment codes');
  const now = Date.now();
  const active = codes.filter(c => !c.used_at && !(c.expires_at && new Date(c.expires_at).getTime() < now));
  const usedCount = codes.length - active.length;
  // The "copy it now" banner is only relevant while the code is still active — once it has been
  // redeemed, killed or expired, drop it so a stale, already-used code stops showing.
  if (LAST_CODE && !active.some(c => c.id === LAST_CODE.id)) LAST_CODE = null;
  if (LAST_CODE) {
    codeCard.append(el('div', { className: 'codebanner' },
      el('div', {}, el('div', { className: 'muted small' }, `New ${LAST_CODE.role} code — copy it now, it is not shown again`), el('code', { className: 'codebox' }, LAST_CODE.code)),
      el('div', { style: 'display:flex;gap:7px' },
        el('button', { className: 'btn', onclick: () => { navigator.clipboard?.writeText(LAST_CODE.code); toast('Code copied'); } }, 'Copy'),
        el('button', { className: 'btn', title: 'Dismiss', onclick: () => { LAST_CODE = null; renderAdmin(); } }, icon('x', 12)))));
  }
  codeCard.append(el('p', { className: 'muted' }, `${active.length} active code${active.length === 1 ? '' : 's'}. Codes are stored hashed — a value shows once when minted (above, or in the terminal). Mint with “New code”, then approve the request here.`));
  for (const c of active) codeCard.append(row(
    [el('strong', {}, c.role), c.note ? el('span', { className: 'muted' }, ` · ${c.note}`) : null,
      el('div', { className: 'muted small' }, `minted ${new Date(c.created_at).toLocaleString()}${c.expires_at ? ' · expires ' + new Date(c.expires_at).toLocaleString() : ''}`)],
    el('button', { className: 'btn danger', onclick: () => killCode(ctx, c.id) }, icon('trash', 12), 'Kill')));
  if (!active.length) codeCard.append(el('p', { className: 'muted small' }, 'No active codes right now.'));
  if (usedCount) codeCard.append(el('div', { className: 'setcard-actions', style: 'margin-top:10px' },
    el('button', { className: 'btn', onclick: () => clearUsedCodes(ctx, usedCount) }, icon('trash', 12), `Clear ${usedCount} used/expired`)));
  page.append(codeCard);

  // Backups (server feature — absent on a purely local install)
  try {
    const bk = await A('/backup');
    const bc = bk.config || {};
    const bcard = card('Backups');
    if (bc.due) bcard.append(el('div', { className: 'duebanner' },
      el('div', {}, el('strong', {}, '⏰ Scheduled backup is due'), el('div', { className: 'muted small' }, 'Enter your backup password to run it now — the password is never stored, so a backup only happens when you do this.')),
      el('button', { className: 'btn gold', onclick: () => backupNow(ctx) }, 'Back up now')));
    bcard.append(el('p', { className: 'muted' },
      `${bc.enabled ? `Reminds you every ${bc.interval_hours}h` : 'No schedule set'}${bc.last_backup_at ? ' · last backup ' + new Date(bc.last_backup_at).toLocaleString() : ' · never backed up'}. Each backup is a full, self-contained snapshot (findings’ screenshots included), encrypted with a password you type each time — nothing is stored. Only the newest ${bc.retain || 5} are kept.`));
    bcard.append(el('div', { className: 'setcard-actions' },
      el('button', { className: 'btn gold', onclick: () => backupNow(ctx) }, icon('down', 12), 'Back up now'),
      el('button', { className: 'btn', onclick: () => backupConfigDialog(ctx, bc) }, bc.enabled ? 'Schedule…' : 'Set reminder…'),
      el('button', { className: 'btn', onclick: () => restoreDialog(ctx) }, icon('up', 12), 'Restore…')));
    // Per-file download, so an admin can keep a snapshot off-box and upload it back later.
    for (const f of bk.backups) bcard.append(row(
      [el('strong', {}, f.file), el('div', { className: 'muted small' }, `${(f.size / 1024).toFixed(1)} KB · ${new Date(f.at).toLocaleString()}`)],
      el('button', { className: 'btn', onclick: () => downloadBackup(ctx, f.file) }, icon('down', 12), 'Download')));
    page.append(bcard);
    BACKUP_DUE = !!bc.due; // keep the top-bar Admin badge in sync while the panel is open
  } catch { /* backups only exist on a server */ }

  // Recent activity (last 10; the full history is in magi-audit.log on the server)
  const auditCard = card('Recent activity');
  if (!audit.length) auditCard.append(el('p', { className: 'muted' }, 'Nothing yet.'));
  for (const a of audit.slice(0, 10)) auditCard.append(el('div', { className: 'auditrow' },
    el('span', { className: 'muted small' }, new Date(a.at).toLocaleTimeString()),
    el('span', { className: 'aud-who' }, ` ${a.display_name || a.username || '—'} `),
    el('span', { className: 'muted' }, a.action || `${a.method} ${a.path}`)));
  if (audit.length) auditCard.append(el('p', { className: 'muted small', style: 'margin-top:8px' }, 'Showing the last 10 — the full log is saved to magi-audit.log on the server.'));
  page.append(auditCard);

  view.replaceChildren(page);
  // Live-refresh while the panel is open (so new requests appear without a manual reload),
  // but don't yank the view out from under an open dialog.
  clearTimeout(window.__adminPoll);
  window.__adminPoll = setTimeout(() => { if (location.hash.startsWith('#/admin') && !$('#modalRoot').hasChildNodes()) renderAdmin(); }, 5000);
}
async function decide(ctx, id, action, name) {
  try {
    await api(`${ctx.base}/requests/${id}/${action}`, { method: 'POST' });
    toast(`${action === 'approve' ? 'Approved' : 'Rejected'} ${name}`);
    renderAdmin();
  } catch (e) { toast('Failed: ' + e.message); }
}
function revokeDevice(ctx, id, name) {
  modal({
    kicker: 'Admin', title: `Revoke ${name}?`, cta: 'Revoke', danger: true,
    note: 'Their token stops working immediately. They keep whatever is on their device but can no longer sync. The entry stays in the list; use Remove to delete it.',
    onSubmit: async () => { await api(`${ctx.base}/devices/${encodeURIComponent(id)}`, { method: 'DELETE' }); toast('Revoked'); renderAdmin(); },
  });
}
function removeDevice(ctx, id, name) {
  modal({
    kicker: 'Admin', title: `Remove ${name}?`, cta: 'Remove', danger: true,
    note: 'Deletes this device (and its account, if it has no other devices) from the server. Already revoked, so no active access is affected. Their synced work stays on the server; this only tidies the list.',
    onSubmit: async () => { await api(`${ctx.base}/devices/${encodeURIComponent(id)}?hard=1`, { method: 'DELETE' }); toast('Removed'); renderAdmin(); },
  });
}
function mintCodeDialog(ctx) {
  modal({
    kicker: 'Admin', title: 'New enrollment code', cta: 'Create',
    note: 'Single-use. Share it with the person joining; you approve their request afterwards.',
    build: (b) => {
      field(b, 'Role', 'role', { options: [{ value: 'worker', label: 'Worker' }, { value: 'admin', label: 'Admin' }] });
      field(b, 'Note (optional)', 'note', { ph: 'e.g. Ana laptop' });
    },
    onSubmit: async (fd) => {
      const r = await api(`${ctx.base}/enroll-codes`, { method: 'POST', body: Object.fromEntries(fd) });
      LAST_CODE = { id: r.id, code: r.code, role: r.role };
      renderAdmin();
    },
  });
}
function killCode(ctx, id) {
  modal({
    kicker: 'Admin', title: 'Kill this code?', cta: 'Kill', danger: true,
    note: 'Invalidates this unused code so it can no longer be redeemed. Any pending request riding on it is dropped.',
    onSubmit: async () => { await api(`${ctx.base}/enroll-codes/${id}`, { method: 'DELETE' }); toast('Code killed'); renderAdmin(); },
  });
}
function clearUsedCodes(ctx, n) {
  modal({
    kicker: 'Admin', title: `Clear ${n} used/expired code${n === 1 ? '' : 's'}?`, cta: 'Clear', danger: true,
    note: 'Removes already-redeemed and expired codes from the history. Active codes and enrolled devices are unaffected.',
    onSubmit: async () => { await api(`${ctx.base}/enroll-codes?used=1`, { method: 'DELETE' }); toast('Cleared'); renderAdmin(); },
  });
}
function backupNow(ctx) {
  modal({
    kicker: 'Backups', title: 'Back up now', cta: 'Back up',
    note: 'A full, encrypted snapshot. Enter your backup password — it is used to encrypt this file and is never stored. Use the SAME password every time so all your backups open with it.',
    build: (b) => { field(b, 'Backup password', 'password', { type: 'password' }); },
    onSubmit: async (fd) => { const r = await api(`${ctx.base}/backup/now`, { method: 'POST', body: { password: Object.fromEntries(fd).password } }); toast(`Backed up ${r.rows} record(s) · keeping ${r.kept}`); renderAdmin(); },
  });
}
function backupConfigDialog(ctx, bc) {
  bc = bc || {};
  modal({
    kicker: 'Backups', title: 'Backup reminder', cta: 'Save',
    note: 'Sets a reminder only — Magi never stores your backup password, so it cannot back up unattended. When one is due, admins are prompted here to enter the password and run it.',
    build: (b) => {
      field(b, 'Remind to back up', 'enabled', { options: [{ value: '', label: 'Off' }, { value: '1', label: 'On' }], value: bc.enabled ? '1' : '' });
      field(b, 'Every (hours)', 'interval_hours', { type: 'number', value: String(bc.interval_hours || 24) });
    },
    onSubmit: async (fd) => {
      const raw = Object.fromEntries(fd);
      await api(`${ctx.base}/backup/config`, { method: 'POST', body: { enabled: !!raw.enabled, interval_hours: raw.interval_hours } });
      toast('Reminder saved'); renderAdmin();
    },
  });
}
async function downloadBackup(ctx, name) {
  const r = await api(`${ctx.base}/backup/file/${encodeURIComponent(name)}`);
  const a = el('a', { href: URL.createObjectURL(new Blob([r.text], { type: 'application/octet-stream' })), download: name });
  document.body.append(a); a.click(); a.remove(); URL.revokeObjectURL(a.href);
}
function restoreDialog(ctx) {
  let fi; // the file input, read at submit time
  modal({
    kicker: 'Backups', title: 'Restore from backup', cta: 'Restore', danger: true,
    note: 'Upload a backup file you saved — one full snapshot is enough — or leave empty to use the server’s own latest backup. It merges back in, newest-wins on any conflict.',
    build: (b) => {
      b.append(el('label', {}, 'Backup file(s) — optional'));
      fi = el('input', { type: 'file', multiple: true, accept: '.enc,.magi,application/octet-stream' });
      b.append(fi);
      field(b, 'Backup password', 'password', { type: 'password' });
    },
    onSubmit: async (fd) => {
      const password = Object.fromEntries(fd).password;
      const files = fi.files && fi.files.length
        ? await Promise.all([...fi.files].map(f => f.text().then(text => ({ name: f.name, text }))))
        : null;
      const r = files
        ? await api(`${ctx.base}/backup/restore-upload`, { method: 'POST', body: { password, files } })
        : await api(`${ctx.base}/backup/restore`, { method: 'POST', body: { password } });
      toast(`Restored ${r.applied} record(s) from ${r.files} file(s)`); renderAdmin();
    },
  });
}

// ---------- auth ----------
function showLogin() {
  CURRENT_USER = null;
  $('#topbar').hidden = true;
  setRail(null);
  $('#account').replaceChildren(); $('#topActions').replaceChildren(); $('#modalRoot').replaceChildren();

  const u = el('input', { name: 'username', placeholder: 'admin', autocomplete: 'username' });
  const p = el('input', { name: 'password', type: 'password', autocomplete: 'current-password' });
  const err = el('div', { className: 'loginerr' });
  const hintLine = el('div', { className: 'login-hint' });
  // /api/me returns this only inside the desktop app, where nothing is on the network.
  fetch('/api/me').then(r => r.json()).then(d => {
    if (d?.hint) hintLine.textContent = `default login — ${d.hint}`;
  }).catch(() => {});

  const card = el('div', { className: 'login-card' },
    el('label', {}, 'Operator'), u,
    el('label', {}, 'Passphrase'), p,
    err,
    el('button', { className: 'btn gold', type: 'submit' }, 'Authenticate'),
    hintLine);

  const form = el('form', { className: 'login-box' },
    el('div', { className: 'login-mark' }, magiMark(72),
      el('div', {}, el('div', { className: 'login-name' }, 'MAGI'),
        el('div', { className: 'login-tag' }, "The pentester's familiar"))),
    card);
  form.onsubmit = async (e) => {
    e.preventDefault();
    err.textContent = '';
    p.style.borderColor = '';
    try { onAuthed(await api('/auth/login', { method: 'POST', body: { username: u.value, password: p.value } })); }
    catch (ex) {
      err.textContent = ex.message.toUpperCase().startsWith('TOO MANY')
        ? ex.message.toUpperCase()
        : `AUTH REJECTED — ${ex.message}.`;
      p.style.borderColor = 'var(--red)';
    }
  };
  $('#view').replaceChildren(el('div', { className: 'login-wrap' }, form));
  u.focus();
}
let LINK_POLL = null, DATA_POLL = null, LAST_REV = null;
// Live-refresh: re-render the current engagement view when background sync brings a
// teammate's changes in. Guarded so it never interrupts a dialog or something you're typing,
// and it restores scroll so the redraw is barely noticeable.
async function pollData() {
  if (!CURRENT_USER) return;
  if ($('#modalRoot').hasChildNodes()) return;                       // a dialog is open
  const ae = document.activeElement;
  if (ae && /^(INPUT|TEXTAREA|SELECT)$/.test(ae.tagName) && $('#view').contains(ae)) return; // user is typing here
  const h = location.hash.slice(1);
  if (!(h === '' || /^\/(project|asset|target)\/\d+/.test(h))) return; // only the engagement views
  let rev;
  try { rev = (await api('/rev')).rev; } catch { return; }
  if (LAST_REV !== null && rev !== LAST_REV) {
    const y = $('#view')?.scrollTop || 0;
    await route();
    if ($('#view')) $('#view').scrollTop = y;
  }
  LAST_REV = rev;
}
function onAuthed(me) {
  CURRENT_USER = me.username;
  ME = me;
  $('#topbar').hidden = false;
  renderAccount();
  (async () => { TYPES = await api('/asset-types'); route(); refreshLink(); })();
  // Keep the link/admin state (pending badge, incoming requests) reasonably fresh…
  clearInterval(LINK_POLL);
  LINK_POLL = setInterval(() => { if (CURRENT_USER) refreshLink(); }, 12000);
  // …and live-refresh the engagement view as changes sync in.
  clearInterval(DATA_POLL);
  DATA_POLL = setInterval(() => { pollData().catch(() => {}); }, 4000);
}
async function logout() { await api('/auth/logout', { method: 'POST' }); showLogin(); }
function changePassword() {
  modal({
    kicker: 'Account', title: 'Change passphrase', cta: 'Change',
    note: 'Signs out every other session. Minimum 10 characters.',
    build: (b) => {
      field(b, 'Current passphrase', 'current', { type: 'password' });
      field(b, 'New passphrase', 'next', { type: 'password' });
    },
    onSubmit: async (fd) => {
      await api('/change-password', { method: 'POST', body: Object.fromEntries(fd) });
      toast('Passphrase changed — other sessions signed out');
    },
  });
}

// The templates button lives in the header, next to the account block.
$('#topbar').insertBefore(
  el('button', { className: 'btn', onclick: () => location.hash = '/editor', title: 'Checklist templates' },
    icon('lines'), el('span', { className: 'lbl' }, 'Templates')),
  $('#account'));

// ---------- boot ----------
(async () => {
  try { onAuthed(await api('/me')); }
  catch { showLogin(); }
})();
