// MAGI — the pentester's familiar.
// Vanilla-JS SPA. Markup here, styling entirely in style.css.

// ---------- theme (dark default / light) ----------
// Applied before first paint to avoid a flash. Dark is the bare :root; light sets data-magi.
try { const th = localStorage.getItem('magi.theme'); if (th === 'light') document.documentElement.setAttribute('data-magi', 'light'); } catch { /* private mode */ }
function currentTheme() { return document.documentElement.getAttribute('data-magi') === 'light' ? 'light' : 'dark'; }
function toggleTheme() {
  const next = currentTheme() === 'light' ? 'dark' : 'light';
  if (next === 'light') document.documentElement.setAttribute('data-magi', 'light');
  else document.documentElement.removeAttribute('data-magi');
  try { localStorage.setItem('magi.theme', next); } catch { /* ignore */ }
  if (typeof renderAccount === 'function' && document.querySelector('#account')) renderAccount();
}

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

// The one credential: a JWT kept in localStorage and sent as `Authorization: Bearer` on every
// call (no cookies). Cleared on logout or a genuine 401.
const AUTH_KEY = 'magi.jwt';
function authToken() { try { return localStorage.getItem(AUTH_KEY) || ''; } catch { return ''; } }
function setAuthToken(t) { try { if (t) localStorage.setItem(AUTH_KEY, t); } catch { /* private mode */ } }
function clearAuthToken() { try { localStorage.removeItem(AUTH_KEY); } catch { /* ignore */ } }
function authHeaders(extra) { const t = authToken(); return { ...(t ? { authorization: 'Bearer ' + t } : {}), ...(extra || {}) }; }

// Attachments are auth-gated, but an <img src> can't carry the Bearer header — so fetch the bytes
// with auth and show them via an object URL. Cached by id (attachment bytes are immutable per id)
// so the live-refresh re-render reuses the same URL instead of leaking a new one each cycle.
const IMG_CACHE = new Map(); // attachment id -> object URL
function attachmentSrc(id) {
  if (IMG_CACHE.has(id)) return Promise.resolve(IMG_CACHE.get(id));
  return fetch('/api/attachments/' + id, { headers: authHeaders() })
    .then(r => r.ok ? r.blob() : Promise.reject(new Error(r.statusText)))
    .then(b => { const u = URL.createObjectURL(b); IMG_CACHE.set(id, u); return u; });
}
function attachmentImg(id, attrs = {}) {
  const img = el('img', attrs);
  attachmentSrc(id).then(u => { img.src = u; }).catch(() => { /* leave broken-image; a reload retries */ });
  return img;
}
function openLightbox(im) {
  attachmentSrc(im.id).then(src => lightbox(src, im.filename, () => downloadAttachment(im))).catch(() => toast('Could not load the image'));
}

async function api(path, opts) {
  // opts.timeout (ms) fails fast instead of hanging when a linked server is unreachable — the
  // request is proxied to the remote, which can otherwise stall for a long TCP timeout.
  const signal = opts?.timeout ? AbortSignal.timeout(opts.timeout) : opts?.signal;
  const token = authToken();
  let r;
  try {
    r = await fetch('/api' + path, {
      ...opts,
      headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}), ...(opts?.headers || {}) },
      body: opts?.body ? JSON.stringify(opts.body) : undefined, signal,
    });
  } catch (e) {
    if (e?.name === 'TimeoutError' || e?.name === 'AbortError') throw new Error('the server did not respond');
    throw e;
  }
  // A 401 from a /link/* call is the remote SERVER rejecting our device token (e.g. it was
  // revoked) — NOT our local session expiring. Only a genuine local 401 sends us to login,
  // otherwise a revoked device would trap the app in a login loop.
  if (r.status === 401 && path !== '/me' && path !== '/auth/login' && !path.startsWith('/link')) { clearAuthToken(); showLogin(); throw new Error('Session expired'); }
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
  { key: 'retest', label: 'Retest' },
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
let HOME_TAB = 'active';      // engagements home: 'active' | 'finished' tab
let EVID = { kind: 'all', q: '', sort: 'new' }; // evidence-log filter/sort (kind, search, order)
let DOCK_W = Math.max(240, Math.min(900, +localStorage.getItem('magi.dockW') || 322)); // evidence-log width (draggable)
// A draggable divider between the checklist and the evidence log — widen/narrow it, remembered.
function dockResizer(dock) {
  const handle = el('div', { className: 'dock-resizer', title: 'Drag to resize the evidence log' });
  handle.onmousedown = (e) => {
    e.preventDefault();
    const startX = e.clientX, startW = dock.getBoundingClientRect().width;
    const move = (ev) => { DOCK_W = Math.max(240, Math.min(900, startW + (startX - ev.clientX))); dock.style.flex = `0 0 ${DOCK_W}px`; dock.style.width = DOCK_W + 'px'; };
    const up = () => { document.removeEventListener('mousemove', move); document.removeEventListener('mouseup', up); document.body.style.cursor = ''; try { localStorage.setItem('magi.dockW', DOCK_W); } catch {} };
    document.addEventListener('mousemove', move); document.addEventListener('mouseup', up); document.body.style.cursor = 'col-resize';
  };
  return handle;
}
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
function filterSortFindings(findings) {
  let out = EVID.kind === 'all' ? findings.slice() : findings.filter(f => f.kind === EVID.kind);
  const q = EVID.q.trim().toLowerCase();
  if (q) out = out.filter(f => `${f.title || ''} ${f.body || ''}`.toLowerCase().includes(q));
  if (EVID.sort === 'sev') out.sort((a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9));
  else if (EVID.sort === 'title') out.sort((a, b) => (a.title || '').localeCompare(b.title || ''));
  return out; // 'new' keeps the server's created_at-DESC order
}

// Where the admin API lives for the signed-in identity, or null if not an admin:
//  - on the server's own web UI: /api/admin directly (session admin)
//  - on a client linked as an admin device: proxied through /api/link/admin
function adminCtx() {
  if (LINK?.linked && LINK.link?.role === 'admin') return { base: '/link/admin' };
  if (LINK?.unavailable && ME?.role === 'admin') return { base: '/admin' };
  return null;
}
// Is the signed-in identity an admin? On a team the linked device's role decides; standalone
// or on the server's own web UI it's the account role (the local owner is an admin).
function isAdmin() { return (LINK?.linked ? LINK.link?.role : ME?.role) === 'admin'; }
// Editors (and admins) may create/edit/delete engagements, targets and checklist structure.
// Admin-only actions (templates, the Admin panel, encryption) stay on isAdmin().
function isEditor() { const r = LINK?.linked ? LINK.link?.role : ME?.role; return r === 'admin' || r === 'editor'; }

// ---------- modal ----------
// kicker + title + optional note, fields, optional danger box, gold/red CTA
function modal(opts) {
  const { kicker = 'Form', title, note, build, onSubmit, cta = 'Save', danger = false, wide = false } = opts;
  const root = $('#modalRoot');
  const form = el('form', { className: 'modal' + (danger ? ' danger' : '') + (wide ? ' wide' : '') });
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
  // Date/time fields: pop the native calendar when the field is clicked or focused, so you never
  // have to type a date by hand (the tiny icon alone is an easy target to miss).
  if (['date', 'time', 'month', 'week', 'datetime-local'].includes(type)) {
    const pop = () => { try { input.showPicker?.(); } catch {} };
    input.addEventListener('click', pop);
    input.addEventListener('focus', pop);
  }
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
    : (LINK?.linked && LINK.link?.needs_reauth)
      ? el('button', { className: 'linkbadge reauth', title: 'Session expired — sync is paused. Click to sign in and resume.', onclick: () => linkSignIn({ reauth: true }) },
          el('span', { className: 'dot' }), lbl('sign in'))
    : LINK?.linked
      ? el('button', { className: 'linkbadge on', title: `Linked to ${LINK.link?.server_url} — open settings`, onclick: () => location.hash = '/settings' },
          el('span', { className: 'dot' }), lbl(LINK.link?.display_name || 'linked'))
      : LINK?.unavailable
        ? el('button', { className: 'linkbadge on', title: 'Team server — open settings', onclick: () => location.hash = '/settings' },
            el('span', { className: 'dot' }), lbl('server'))
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
    // Self-service rename is a self-hosted (standalone) thing. When connected to a team server the
    // server owns identities (like AD), so the client doesn't offer it.
    (LINK?.linked || LINK?.pending) ? null
      : el('button', { className: 'iconbtn', title: 'Change username', onclick: changeUsername }, icon('edit')),
    el('button', { className: 'iconbtn theme', title: `Theme — ${currentTheme()} (click to switch)`, onclick: toggleTheme },
      el('span', { className: 'themedot' })),
    el('button', { className: 'iconbtn danger', title: 'Sign out', onclick: logout }, icon('exit'))));
  const tb = $('#tplBtn'); if (tb) tb.hidden = !isAdmin(); // editing templates is admin-only
}
// When the background poll first notices the token has lapsed (server 401 → sync paused),
// open the sign-in dialog once, so the user is actually asked for a fresh token instead of
// working on against a mirror that has silently stopped syncing. We ask only once per lapse
// (the pulsing topbar badge stays as the standing cue) and never stomp an open dialog or
// interrupt typing — the next poll retries when the user is free.
let REAUTH_PROMPTED = false;
function maybePromptReauth() {
  const need = !!(LINK?.linked && LINK.link?.needs_reauth);
  if (!need) { REAUTH_PROMPTED = false; return; }
  if (REAUTH_PROMPTED || !CURRENT_USER) return;
  if ($('#modalRoot')?.hasChildNodes()) return;
  const ae = document.activeElement;
  if (ae && /^(INPUT|TEXTAREA|SELECT)$/.test(ae.tagName)) return;
  REAUTH_PROMPTED = true;
  linkSignIn({ reauth: true });
}
async function refreshLink() {
  try { LINK = await api('/link'); } catch { LINK = { linked: false, unavailable: true }; }
  maybePromptReauth();
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
    // Settings holds the account (username / passphrase) in every mode, plus linking on clients.
    if (h === '/settings') return renderSettings();
    if (h === '/admin') return renderAdmin();
    // Template editing is admin-only; workers are bounced back to their engagements.
    if (h === '/editor' || h.startsWith('/editor/') || h.startsWith('/group/')) {
      if (!isAdmin()) { location.hash = ''; return; }
    }
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
    isEditor() ? el('div', { style: 'display:flex;gap:7px' },
      el('button', { className: 'btn', onclick: importProjectFile, title: 'Import an engagement from a file' }, icon('up', 12), 'Import'),
      el('button', { className: 'btn gold', onclick: newProject }, icon('plus', 12), 'New engagement')) : null);

  if (!projects.length) {
    return view.replaceChildren(el('div', { className: 'page' }, head,
      el('div', { className: 'empty', style: 'margin-top:26px' },
        el('div', {}, isEditor() ? 'No engagements yet. Every target, checklist and finding lives inside one.' : 'No engagements yet. An admin sets these up.'),
        isEditor() ? el('button', { className: 'btn gold', onclick: newProject }, icon('plus', 12), 'Create the first') : null)));
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

  const lists = { active: projects.filter(p => p.status !== 'finished'), finished: projects.filter(p => p.status === 'finished') };

  // Active / Finished tabs (Sysreptor-style), with a search that filters the open tab.
  const tabs = el('div', { className: 'filters' });
  const btns = {};
  for (const d of [{ k: 'active', l: 'Active' }, { k: 'finished', l: 'Finished' }]) {
    btns[d.k] = el('button', { className: 'filt', onclick: () => { HOME_TAB = d.k; paint(); } }, d.l, el('span', {}, String(lists[d.k].length)));
    tabs.append(btns[d.k]);
  }
  const search = el('input', { className: 'searchbox', type: 'search' });
  const listWrap = el('div');

  function paint() {
    for (const k in btns) btns[k].classList.toggle('on', k === HOME_TAB);
    const src = lists[HOME_TAB];
    search.placeholder = `Search ${src.length} ${HOME_TAB} engagement${src.length === 1 ? '' : 's'}…`;
    const t = search.value.trim().toLowerCase();
    const hits = t ? src.filter(p => `${p.name} ${p.client || ''}`.toLowerCase().includes(t)) : src;
    const table = el('div', { className: 'ptable' },
      el('div', { className: 'ptable-head kicker' },
        el('span', {}, 'Engagement'), el('span', { className: 'hide-sm' }, 'Client'),
        el('span', { className: 'hide-sm' }, 'Coverage'), el('span', { className: 'hide-sm' }, 'Dates'), el('span', {})));
    if (!hits.length) table.append(el('div', { className: 'empty', style: 'border:0' },
      t ? 'No engagements match your search.' : HOME_TAB === 'finished' ? 'No finished engagements yet.' : 'No active engagements yet.'));
    else hits.forEach(p => table.append(projectRow(p)));
    table.append(el('div', { className: 'end' }));
    listWrap.replaceChildren(table);
  }
  search.oninput = paint;
  view.replaceChildren(el('div', { className: 'page' }, head, tabs, search, listWrap));
  paint();
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
// Short mono code badge per target type (WEB / API / NET / AD / POC …).
const TYPE_CODE = { web: 'WEB', api: 'API', ip: 'NET', exthost: 'NET', ad: 'AD', mobile: 'MOB', wireless: 'WIFI', iot: 'IOT', ot: 'OT', container: 'CTR', poc: 'POC', retest: 'RTS' };
const typeCode = (t) => TYPE_CODE[t] || String(t || '?').replace(/[^a-z0-9]/gi, '').slice(0, 3).toUpperCase() || '?';
const codeBadge = (type, on) => el('span', { className: 'tcode' + (on ? ' on' : '') }, typeCode(type));
function groupLabel(key) { return (GROUP_ORDER.find(g => g.key === key) || {}).label || key; }
// engagement groups that actually have a selectable (non-soon) target type
function selectableGroups() { return new Set(TYPES.filter(t => !t.soon).map(t => t.grp || 'additional')); }

function railForFolder(folder, activeTargetId) {
  const targets = folder.targets || [];
  const total = targets.reduce((a, x) => a + x.total, 0);
  const handled = targets.reduce((a, x) => a + x.handled, 0);
  const head = el('div', { className: 'rail-head' },
    el('div', { className: 'kicker' }, 'Asset · ' + groupLabel(folder.grp)),
    el('div', { className: 'rail-title' }, `${folder.label}`),
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
        codeBadge(a.type, String(a.id) === String(activeTargetId)),
        el('span', { className: 'rt-pct' }, p + '%')),
      el('span', { className: 'rt-name' }, a.label),
      el('span', { className: 'bar thin' + (p > 70 ? ' good' : !p ? ' idle' : '') }, el('span', { style: `width:${p}%` }))));
  }
  if (!targets.length) list.append(el('div', { className: 'pmeta', style: 'padding:10px' }, 'No targets yet'));
  return [head,
    el('button', { className: 'railback', onclick: () => location.hash = `/project/${folder.project_id}` }, '‹ Back to engagement'),
    el('div', { className: 'rail-label kicker' }, 'Targets'), list,
    isEditor() ? el('div', { className: 'rail-foot' },
      el('button', { className: 'dashbtn', onclick: () => addTarget(folder) }, icon('plus', 12), 'Add target')) : null];
}
// Rail listing every target in the engagement, grouped by kind (the flat engagement→target model).
function railForProject(project, activeTargetId) {
  const groups = (project.assets || []).filter(f => (f.items || []).length);
  const targets = groups.flatMap(f => f.items || []);
  const total = targets.reduce((a, x) => a + x.total, 0);
  const handled = targets.reduce((a, x) => a + x.handled, 0);
  const head = el('div', { className: 'rail-head' },
    el('div', { className: 'kicker' }, 'Engagement'),
    el('div', { className: 'rail-title' }, project.name),
    el('div', { className: 'rail-status' }, el('span', { className: 'pulse' }),
      `${pct(handled, total)}% · ${targets.length} TARGET${targets.length === 1 ? '' : 'S'}`));
  const list = el('div', { className: 'rail-list' });
  for (const f of groups) {
    list.append(el('div', { className: 'rail-label kicker', style: 'margin-top:10px' }, `${groupLabel(f.grp)}`));
    for (const a of f.items) {
      const p = pct(a.handled, a.total);
      list.append(el('button', {
        className: 'railtarget' + (String(a.id) === String(activeTargetId) ? ' on' : ''),
        onclick: () => location.hash = `/target/${a.id}`,
      },
        el('span', { className: 'rt-top' }, codeBadge(a.type, String(a.id) === String(activeTargetId)), el('span', { className: 'rt-pct' }, p + '%')),
        el('span', { className: 'rt-name' }, a.label),
        el('span', { className: 'bar thin' + (p > 70 ? ' good' : !p ? ' idle' : '') }, el('span', { style: `width:${p}%` }))));
    }
  }
  if (!targets.length) list.append(el('div', { className: 'pmeta', style: 'padding:10px' }, 'No targets yet'));
  return [head,
    el('button', { className: 'railback', onclick: () => location.hash = `/project/${project.id}` }, '‹ Back to engagement'),
    list,
    isEditor() ? el('div', { className: 'rail-foot' },
      el('button', { className: 'dashbtn', onclick: () => addTargetToProject(project.id) }, icon('plus', 12), 'Add target')) : null];
}

// ---------- engagement (project) — lists Asset folders ----------
async function renderProject(id) {
  const p = await api('/projects/' + id);
  setRail(null);
  setCrumbs([{ label: 'engagements', go: () => location.hash = '' }, { label: p.name }]);
  const finished = p.status === 'finished';
  // Every target across the engagement (the folders are just kind-groups under the hood now).
  const allTargets = p.assets.flatMap(f => (f.items || []).map(t => ({ ...t, grp: f.grp })));
  topActions(
    el('button', { className: 'btn', onclick: () => exportProjectMenu(id, p.name) }, icon('down', 12), 'Export'),
    isEditor() ? el('button', { className: 'btn', onclick: () => editProject(p, () => renderProject(id)) }, icon('edit', 12), 'Edit') : null,
    isEditor()
      ? (finished
        ? el('button', { className: 'btn', onclick: () => setProjectStatus(p, 'active', () => renderProject(id)) }, 'Reopen')
        : el('button', { className: 'btn', onclick: () => setProjectStatus(p, 'finished', () => renderProject(id)) }, icon('check', 12), 'Finish'))
      : null,
    isEditor() ? el('button', { className: 'btn danger', onclick: () => delProject(p, allTargets.length, () => location.hash = '') }, 'Delete') : null);

  const total = allTargets.reduce((a, x) => a + x.total, 0);
  const handled = allTargets.reduce((a, x) => a + x.handled, 0);
  const findings = allTargets.reduce((a, x) => a + (x.findings || 0), 0);
  const flags = allTargets.reduce((a, x) => a + x.flags, 0);

  const stat = (label, value, cls) => el('div', { className: 'stat' },
    el('div', { className: 'kicker' }, label), el('div', { className: 'stat-value ' + (cls || '') }, value));

  const targetRow = (a) => {
    const t = TYPES.find(x => x.type === a.type) || {};
    const cov = pct(a.handled, a.total);
    const del = isEditor() ? el('button', { className: 'ibtn del', title: 'Delete target' }, icon('trash')) : null;
    if (del) del.onclick = (e) => { e.stopPropagation(); delTarget(a, () => renderProject(id)); };
    return el('button', { className: 'trow', onclick: () => location.hash = `/target/${a.id}` },
      codeBadge(a.type),
      el('span', { className: 'tgrow' },
        el('span', { className: 'tname' }, a.label),
        el('span', { className: 'tmeta' }, `${(t.label || a.type).toUpperCase()} · ${a.handled}/${a.total} handled${a.findings ? ' · ' + a.findings + ' finding' + (a.findings === 1 ? '' : 's') : ''}`)),
      el('span', { className: 'tprog' },
        el('span', { className: 'bar' + (cov > 70 ? ' good' : !cov ? ' idle' : '') }, el('span', { style: `width:${cov}%` })),
        el('span', { className: 'pct' + (cov > 70 ? ' good' : cov ? ' some' : '') }, cov + '%')),
      el('span', { className: 'tflag' + (a.flags ? ' on' : '') }, a.flags ? '⚑ ' + a.flags : '—'),
      del);
  };

  const body = el('div', {});
  const groups = p.assets.filter(f => (f.items || []).length); // only kind-groups that hold targets
  if (!groups.length) {
    body.append(el('div', { className: 'empty', style: 'border:0;margin-top:20px' },
      el('div', {}, isEditor() ? 'No targets yet. Add a web app, host, API, AD domain… to start testing.' : 'No targets yet. An admin adds these.'),
      isEditor() ? el('button', { className: 'btn gold', onclick: () => addTargetToProject(id) }, icon('plus', 12), 'Add target') : null));
  } else {
    for (const f of groups) {
      body.append(el('div', { className: 'srule', style: 'margin-top:22px' },
        el('span', { className: 'kicker' }, `${groupLabel(f.grp)}`), el('span', { className: 'rule' }),
        el('span', { className: 'muted small' }, `${f.items.length} target${f.items.length === 1 ? '' : 's'}`)));
      const list = el('div', { className: 'tlist' });
      for (const a of f.items) list.append(targetRow(a));
      body.append(list);
    }
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
      stat('Targets', String(allTargets.length))),
    el('div', { className: 'srule' },
      el('span', { className: 'kicker' }, 'Targets'), el('span', { className: 'rule' }),
      isEditor() ? el('button', { className: 'btn line sm', onclick: () => addTargetToProject(id) }, '+ Add target') : null),
    body));
}

// The asset-folder layer is now implicit — any /asset link jumps straight to its engagement.
async function renderAssetFolder(id) {
  try { const f = await api('/assets/' + id); location.hash = `/project/${f.project_id}`; }
  catch { location.hash = ''; }
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
          el('span', { className: 'lbl' }, `${g.label}`),
          el('span', { className: 'hint' }, soon ? 'coming soon' : (g.key === 'internal' ? 'host, subnet, AD'
            : g.key === 'external' ? 'web, api, domain' : g.key === 'otiot' ? 'IoT, OT/ICS'
            : g.key === 'additional' ? 'container, PoC' : g.key === 'retest' ? 'remediation check'
              : g.label.toLowerCase())));
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
          el('span', { className: 'lbl' }, `${t.label}`),
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

// Add a target straight to an engagement — pick any target type; its kind-group is auto-managed.
function addTargetToProject(projectId) {
  const types = TYPES.filter(t => !t.soon);
  if (!types.length) return;
  const byGrp = {};
  for (const t of types) (byGrp[t.grp || 'additional'] ||= []).push(t);
  modal({
    kicker: 'Target', title: 'Add a target', cta: 'Add target', wide: true,
    build: (b) => {
      const hidden = el('input', { type: 'hidden', name: 'type', value: types[0].type });
      const label = el('input', { name: 'label', placeholder: types[0].hint || 'value' });
      const btns = [];
      const wrap = el('div', {});
      for (const g of GROUP_ORDER) {
        const gts = byGrp[g.key];
        if (!gts || !gts.length) continue;
        wrap.append(el('div', { className: 'kicker', style: 'margin:12px 0 6px' }, `${g.label}`));
        const grid = el('div', { className: 'typegrid' });
        for (const t of gts) {
          const btn = el('button', { type: 'button', className: 'type' + (t.type === hidden.value ? ' sel' : '') },
            el('span', { className: 'lbl' }, `${t.label}`),
            el('span', { className: 'hint' }, t.hint || t.type));
          btn.onclick = () => { hidden.value = t.type; label.placeholder = t.hint || 'value'; for (const x of btns) x.classList.remove('sel'); btn.classList.add('sel'); label.focus(); };
          btns.push(btn); grid.append(btn);
        }
        wrap.append(grid);
      }
      b.append(el('label', {}, 'Target type'), wrap, hidden, el('label', { style: 'margin-top:8px' }, 'Identifier'), label);
    },
    onSubmit: async (fd) => {
      const body = { type: fd.get('type'), label: fd.get('label') };
      if (!body.label) throw new Error('Enter an identifier');
      const a = await api(`/projects/${projectId}/targets`, { method: 'POST', body });
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
      if (after) after(); else location.hash = a.project?.id || a.folder?.project_id ? `/project/${a.project?.id || a.folder?.project_id}` : '';
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

  const pid = a.project?.id ?? a.folder?.project_id;
  const project = pid ? await api('/projects/' + pid) : null;   // engagement → all targets for the rail
  setRail(project ? railForProject(project, id) : null);
  setCrumbs([
    { label: 'engagements', go: () => location.hash = '' },
    { label: a.project?.name || 'engagement', go: () => location.hash = `/project/${pid}` },
    { label: a.label }]);
  // Retest targets carry no checklist — just remediation items (a finding per re-checked issue).
  if (a.type === 'retest') {
    topActions(
      el('button', { className: 'btn gold', onclick: () => addFinding(id, true) }, icon('plus', 12), 'Add retest item'),
      isEditor() ? el('button', { className: 'btn danger', onclick: () => delTarget(a) }, 'Delete target') : null);
    const list = el('div', { className: 'tlist' });
    if (!a.findings.length) list.append(el('div', { className: 'empty', style: 'border:0' },
      el('div', {}, 'No retest items yet. Add one for each finding from the previous engagement you re-checked.'),
      el('button', { className: 'btn gold', onclick: () => addFinding(id, true) }, icon('plus', 12), 'Add the first')));
    for (const f of a.findings) list.append(findingCard(f, id));
    const counts = { fixed: 0, half_fixed: 0, not_fixed: 0 };
    for (const f of a.findings) if (f.fix_status) counts[f.fix_status]++;
    return $('#view').replaceChildren(el('div', { className: 'page narrow' },
      el('div', { className: 'kicker' }, 'Retest'),
      el('h1', {}, a.label),
      el('div', { className: 'lede' }, `${a.findings.length} item${a.findings.length === 1 ? '' : 's'} · ${counts.fixed} fixed · ${counts.half_fixed} partial · ${counts.not_fixed} not fixed`),
      el('div', { className: 'srule' }, el('span', { className: 'kicker' }, 'Remediation items'), el('span', { className: 'rule' }),
        el('button', { className: 'btn line sm', onclick: () => addFinding(id, true) }, '+ Add')),
      list));
  }

  // PoC targets carry no checklist — just findings: somewhere to document an exploit / demo with
  // notes, requests, credentials and screenshots. (Same "no checklist" shape as Retest, but the
  // normal finding kinds rather than the remediation fix-status flow.)
  if (a.type === 'poc') {
    topActions(
      el('button', { className: 'btn gold', onclick: () => addFinding(id, false) }, icon('plus', 12), 'Add finding'),
      isEditor() ? el('button', { className: 'btn danger', onclick: () => delTarget(a) }, 'Delete target') : null);
    const list = el('div', { className: 'tlist' });
    if (!a.findings.length) list.append(el('div', { className: 'empty', style: 'border:0' },
      el('div', {}, 'No findings yet. Record the exploit — notes, requests, credentials and screenshots — as your proof of concept.'),
      el('button', { className: 'btn gold', onclick: () => addFinding(id, false) }, icon('plus', 12), 'Add the first')));
    for (const f of a.findings) list.append(findingCard(f, id));
    return $('#view').replaceChildren(el('div', { className: 'page narrow' },
      el('div', { className: 'kicker' }, 'Proof of concept'),
      el('h1', {}, a.label),
      el('div', { className: 'lede' }, `${a.findings.length} finding${a.findings.length === 1 ? '' : 's'}`),
      el('div', { className: 'srule' }, el('span', { className: 'kicker' }, 'Findings'), el('span', { className: 'rule' }),
        el('button', { className: 'btn line sm', onclick: () => addFinding(id, false) }, '+ Add')),
      list));
  }

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
        el('div', { style: 'display:flex;align-items:center;gap:9px' },
          codeBadge(a.type), el('span', { className: 'kicker' }, t.label || a.type)),
        el('h1', {}, a.label)),
      el('div', { className: 'target-actions' },
        el('button', { className: 'btn', onclick: () => { groups.forEach(g => openGroups.add(g.key)); renderTarget(id); } }, 'Expand all'),
        el('button', { className: 'btn', onclick: () => { openGroups.clear(); renderTarget(id); } }, 'Collapse'),
        isEditor() ? el('button', { className: 'btn line', onclick: () => itemModal(id) }, '+ Item') : null)),
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
  if (!a.findings.length) {
    dbody.append(el('div', { className: 'pmeta', style: 'padding:4px 2px;line-height:1.7' },
      'Nothing captured yet. Save raw requests, credentials and confirmed vulnerabilities here — the export is built from them.'));
  } else {
    // filter (by kind) + search (by name) + sort, repainting only the list so search keeps focus
    const findList = el('div', { className: 'find-list' });
    const tabs = el('div', { className: 'evtabs' });
    const search = el('input', { className: 'evsearch', type: 'search', placeholder: 'Search findings…', value: EVID.q });
    const sortSel = el('select', { className: 'evsort' },
      ...[['new', 'Newest'], ['sev', 'Severity'], ['title', 'Name']].map(([v, l]) => el('option', { value: v, selected: EVID.sort === v }, l)));
    const repaint = () => {
      [...tabs.children].forEach(b => b.classList.toggle('on', b.dataset.k === EVID.kind));
      const shown = filterSortFindings(a.findings);
      findList.replaceChildren();
      if (!shown.length) findList.append(el('div', { className: 'pmeta', style: 'padding:6px 2px' }, 'No findings match.'));
      else for (const f of shown) findList.append(findingCard(f, id));
    };
    for (const [k, l] of [['all', 'All'], ['note', 'Notes'], ['credential', 'Creds'], ['vuln', 'Vulns']]) {
      const b = el('button', { className: 'evtab', 'data-k': k, onclick: () => { EVID.kind = k; repaint(); } }, l);
      b.dataset.k = k; tabs.append(b);
    }
    search.oninput = () => { EVID.q = search.value; repaint(); };
    sortSel.onchange = () => { EVID.sort = sortSel.value; repaint(); };
    dbody.append(el('div', { className: 'evfilter' }, tabs, el('div', { className: 'evrow' }, search, sortSel)), findList);
    repaint();
  }
  dock.append(dbody);

  dock.style.flex = `0 0 ${DOCK_W}px`; dock.style.width = DOCK_W + 'px';
  const y = $('.target-col')?.scrollTop || 0;
  $('#view').replaceChildren(el('div', { className: 'target' },
    el('div', { className: 'target-col' }, head, list), dockResizer(dock), dock));
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
  // Editing the checklist itself (add sub-item / edit / delete) is admin-only; workers tick boxes.
  if (isEditor()) actions.append(el('div', { className: 'itools' },
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
const FIX_STATUS = [{ value: 'not_fixed', label: 'Not fixed' }, { value: 'half_fixed', label: 'Partially fixed' }, { value: 'fixed', label: 'Fixed' }];
const fixLabel = (v) => (FIX_STATUS.find(x => x.value === v)?.label || v);
// A vuln's location(s) are stored as a "Location: a, b, c" first line of the body.
const parseLocations = (body) => { const m = /^Location:\s*(.+)/.exec(body || ''); return m ? m[1].split(',').map(s => s.trim()).filter(Boolean) : []; };
const stripLocationPrefix = (body) => (body || '').replace(/^Location:.*\n\n?/, '');

// A tick that marks whether this finding has been written into the report, so it's obvious at a
// glance what's already covered and what's left. Toggles in place and refreshes the view.
function reportTick(f, afterToggle) {
  const b = el('button', { className: 'reptick', type: 'button' });
  const paint = () => {
    const on = !!f.in_report;
    b.className = 'reptick' + (on ? ' on' : '');
    b.title = on ? 'Written into the report — click to unmark' : 'Mark as added to the report';
    b.replaceChildren(icon('check', 11), el('span', {}, on ? 'In report' : 'Mark done'));
  };
  paint();
  b.onclick = async (e) => {
    e.stopPropagation();
    const next = f.in_report ? 0 : 1;
    try { await api('/findings/' + f.id, { method: 'PATCH', body: { in_report: next } }); f.in_report = next; paint(); afterToggle && afterToggle(); }
    catch (err) { alert('Could not update: ' + err.message); }
  };
  return b;
}

// One finding, as shown in the evidence log and the retest view (severity, kind or fix-status,
// screenshots, and any attack-chain links to other findings).
function findingCard(f, id) {
  const stop = (e) => e.stopPropagation(); // interactive bits shouldn't open the detail popup
  const tools = el('div', { className: 'f-tools', onclick: stop },
    el('button', { className: 'ibtn', title: 'Add image', onclick: () => uploadToFinding(f.id, id) }, icon('image', 11)),
    el('button', { className: 'ibtn', title: 'Edit', onclick: () => editFinding(f, id) }, icon('edit', 11)),
    el('button', { className: 'ibtn del', title: 'Delete', onclick: async () => { if (confirm('Delete this finding and its images?')) { await api('/findings/' + f.id, { method: 'DELETE' }); renderTarget(id); } } }, icon('x', 11)));
  const shots = el('div', { className: 'f-shots', onclick: stop });
  for (const im of (f.attachments || [])) {
    const thumb = attachmentImg(im.id, { title: im.filename, loading: 'lazy' });
    thumb.onclick = (e) => { e.stopPropagation(); openLightbox(im); };
    const dl = el('button', { className: 'shotdl', title: 'Download image', onclick: (e) => { e.stopPropagation(); downloadAttachment(im); } }, icon('down', 10));
    const x = el('button', { className: 'shotx', title: 'Remove image', onclick: async (e) => { e.stopPropagation(); await api('/attachments/' + im.id, { method: 'DELETE' }); renderTarget(id); } }, '✕');
    shots.append(el('span', { className: 'f-shot' }, thumb, dl, x));
  }
  const links = (f.links || []).length ? el('div', { className: 'f-links' }, el('span', { className: 'muted' }, 'chains → '),
    ...f.links.flatMap((l, i) => [i ? el('span', { className: 'muted' }, ', ') : null, el('span', { className: 'chainlink', title: l.target }, l.title)].filter(Boolean))) : null;
  const card = el('div', { className: 'finding sev-' + (f.severity || 'info') + (f.in_report ? ' in-report' : ''), title: 'Click to open' },
    el('div', { className: 'f-top' },
      f.severity ? el('span', { className: 'f-sev' }, f.severity) : null,
      f.fix_status ? el('span', { className: 'f-fix ' + f.fix_status }, fixLabel(f.fix_status)) : el('span', { className: 'f-kind' }, f.kind),
      reportTick(f, () => renderTarget(id)),
      tools),
    el('div', { className: 'f-title' }, f.title),
    f.body ? el('pre', {}, f.body) : null,
    links,
    (f.attachments || []).length ? shots : null);
  card.onclick = () => findingDetail(f, id);
  return card;
}
// Full, readable view of one finding (opened by clicking its card). Read-only, with an Edit CTA.
function findingDetail(f, id) {
  const locs = parseLocations(f.body);
  modal({
    kicker: f.fix_status ? 'Retest · ' + fixLabel(f.fix_status) : (f.kind === 'credential' ? 'Credential' : f.kind === 'note' ? 'Note' : 'Vulnerability'),
    title: f.title, cta: 'Edit', wide: true,
    build: (b) => {
      b.append(el('div', { className: 'fd-badges' },
        f.severity ? el('span', { className: 'fd-sev sev-' + f.severity }, f.severity.toUpperCase()) : null,
        reportTick(f, () => renderTarget(id))));
      if (locs.length) { b.append(el('label', {}, locs.length > 1 ? 'Locations' : 'Location')); b.append(el('div', { className: 'fd-locs' }, ...locs.map(l => el('code', {}, l)))); }
      const bodyText = f.kind === 'vuln' ? stripLocationPrefix(f.body) : f.body;
      if (bodyText) { b.append(el('label', {}, f.kind === 'credential' ? 'Credentials' : 'Details')); b.append(el('pre', { className: 'fd-body' }, bodyText)); }
      if ((f.links || []).length) { b.append(el('label', {}, 'Attack chain')); b.append(el('div', { className: 'fd-links' }, ...f.links.map((l, i) => el('span', { className: 'chainlink', title: l.target }, (i ? ', ' : '') + l.title)))); }
      if ((f.attachments || []).length) {
        b.append(el('label', {}, `Screenshots (${f.attachments.length})`));
        const g = el('div', { className: 'fd-shots' });
        for (const im of f.attachments) { const img = attachmentImg(im.id, { title: im.filename, loading: 'lazy' }); img.onclick = () => openLightbox(im); g.append(img); }
        b.append(g);
      }
    },
    onSubmit: async () => { editFinding(f, id); }, // "Edit" hands off to the editor
  });
}
async function saveFinding(editing, finding, assetId, payload, images) {
  if (editing) { await api('/findings/' + finding.id, { method: 'PATCH', body: payload }); return; }
  const f = await api(`/targets/${assetId}/findings`, { method: 'POST', body: payload });
  // Attach the screenshots. A rejected image must never vanish silently — collect the reasons
  // and surface them, so "it didn't save" is always explained (too large, wrong type, offline…).
  const failed = [];
  for (const file of images) {
    const name = file.name || 'image';
    if (!file.type || !file.type.startsWith('image/')) { failed.push(`${name} — not an image file`); continue; }
    try {
      const r = await fetch(`/api/findings/${f.id}/attachments`, { method: 'POST',
        headers: authHeaders({ 'content-type': file.type, 'x-filename': encodeURIComponent(name) }), body: await file.arrayBuffer() });
      if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.statusText);
    } catch (e) { failed.push(`${name} — ${e.message}`); }
  }
  if (failed.length) alert(`The finding was saved, but ${failed.length} image${failed.length > 1 ? 's' : ''} could not be attached:\n\n${failed.join('\n')}`);
}

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
async function findingModal(assetId, finding = null, isRetest = false) {
  const editing = !!finding;
  const startKind = finding?.kind === 'request' ? 'note' : (finding?.kind || 'note');
  const images = [];
  const selectedRefs = new Set(finding?.ref_uids || []);
  // Other findings across the engagement, to link as an attack chain (or a retest reference).
  let candidates = [];
  try { candidates = (await api(`/targets/${assetId}/finding-candidates`)).filter(c => c.uid && c.uid !== finding?.uid); } catch { }

  // Linking is optional: a collapsed toggle that opens the picker. The list shows ~3 rows and
  // scrolls if there are more.
  const chainSection = (parent) => {
    if (!candidates.length) return;
    const box = el('div', { className: 'chainpick' });
    const caption = el('span', {});
    const label = () => (isRetest ? 'Link the original finding' : 'Link related findings (attack chain)') + (selectedRefs.size ? ` · ${selectedRefs.size} selected` : '');
    caption.textContent = label();
    for (const c of candidates) {
      const cb = el('input', { type: 'checkbox', checked: selectedRefs.has(c.uid) });
      cb.onchange = () => { cb.checked ? selectedRefs.add(c.uid) : selectedRefs.delete(c.uid); caption.textContent = label(); };
      box.append(el('label', { className: 'chainrow' }, cb,
        el('span', { className: 'chaint' }, c.severity ? el('span', { className: 'f-sev' }, c.severity) : null,
          c.title, el('span', { className: 'muted small' }, ' · ' + c.target))));
    }
    const open0 = selectedRefs.size > 0; // start open when editing something already linked
    box.hidden = !open0;
    const toggle = el('button', { type: 'button', className: 'chaintoggle' + (open0 ? ' open' : '') },
      el('span', { className: 'chev' }, '▸'), caption);
    toggle.onclick = () => { box.hidden = !box.hidden; toggle.classList.toggle('open', !box.hidden); };
    parent.append(el('div', { className: 'chainsec' }, toggle, box));
  };

  if (isRetest) {
    modal({
      kicker: 'Retest', title: editing ? 'Edit retest item' : 'Add retest item', cta: 'Save',
      note: 'Re-checking a finding from the previous engagement — record its ID, current severity, whether it was fixed, and evidence.',
      build: (b) => {
        field(b, 'Original finding ID', 'title', { value: finding?.title || '', ph: 'e.g. ACME-2024-014 — SQLi in /search' });
        const c1 = el('div'), c2 = el('div');
        field(c1, 'Severity', 'severity', { value: finding?.severity || 'medium', options: SEVERITIES.filter(s => s.value) });
        field(c2, 'Fix status', 'fix_status', { value: finding?.fix_status || 'not_fixed', options: FIX_STATUS });
        b.append(el('div', { className: 'field-row' }, c1, c2));
        field(b, 'Explanation', 'body', { value: finding?.body || '', textarea: true, ph: 'what you re-tested and the result' });
        chainSection(b);
        if (!editing) fileField(b, 'Images (screenshots)', images);
      },
      onSubmit: async (fd) => {
        const raw = Object.fromEntries(fd);
        await saveFinding(editing, finding, assetId, {
          title: raw.title || 'Retest item', kind: 'vuln', severity: raw.severity || null,
          body: raw.body || '', fix_status: raw.fix_status || 'not_fixed', refs: [...selectedRefs],
        }, images);
        renderTarget(assetId);
      },
    });
    return;
  }

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
          // one or more affected locations (URLs / domains)
          fields.append(el('label', {}, 'Location(s) — URL / domain'));
          const locList = el('div', { className: 'loclist' });
          const addLoc = (val = '') => {
            const inp = el('input', { className: 'locinput', value: val, placeholder: 'https://app/search?q=' });
            const rmv = el('button', { type: 'button', className: 'ibtn del', title: 'Remove', onclick: () => { row.remove(); if (!locList.children.length) addLoc(); } }, icon('x', 11));
            const row = el('div', { className: 'locrow' }, inp, rmv);
            locList.append(row); return inp;
          };
          const existing = editing ? parseLocations(finding.body) : [];
          (existing.length ? existing : ['']).forEach(v => addLoc(v));
          fields.append(locList,
            el('button', { type: 'button', className: 'btn line sm', style: 'margin:2px 0 6px', onclick: () => addLoc().focus() }, icon('plus', 12), 'Add location'));
          field(fields, 'Explanation', 'body', { value: editing ? stripLocationPrefix(finding.body) : '', textarea: true, ph: 'how it was found / impact' });
          if (!editing) fileField(fields, 'Images (screenshots)', images);
        }
        chainSection(fields);
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
        const locs = [...document.querySelectorAll('.modal .locinput')].map(i => i.value.trim()).filter(Boolean);
        body = (locs.length ? `Location: ${locs.join(', ')}\n\n` : '') + (raw.body || '');
      }
      const title = raw.title || (kind === 'credential' ? 'Credentials' : kind === 'vuln' ? 'Vulnerability' : 'Note');
      await saveFinding(editing, finding, assetId, { title, kind, severity, body, refs: [...selectedRefs] }, images);
      renderTarget(assetId);
    },
  });
}
const addFinding = (assetId, isRetest = false) => findingModal(assetId, null, isRetest);
const editFinding = (finding, assetId) => findingModal(assetId, finding, finding?.fix_status != null || finding?.kind === 'retest');

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
          headers: authHeaders({ 'content-type': f.type || 'application/octet-stream', 'x-filename': encodeURIComponent(f.name) }),
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

// Save a finding's screenshot to the local machine. Fetches the bytes and triggers a normal
// browser/Electron download, forcing a save even though the server serves it inline.
async function downloadAttachment(im) {
  try {
    const r = await fetch('/api/attachments/' + im.id, { headers: authHeaders() });
    if (!r.ok) throw new Error(r.statusText);
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = el('a', { href: url, download: im.filename || `screenshot-${im.id}.png` });
    document.body.append(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  } catch (e) { alert('Could not download the image: ' + e.message); }
}

// Full-size image overlay, with a Download button so a screenshot can be saved locally.
function lightbox(src, caption, onDownload) {
  const root = $('#modalRoot');
  const close = () => root.replaceChildren();
  const bar = el('div', { className: 'lb-bar', onclick: (e) => e.stopPropagation() },
    onDownload ? el('button', { className: 'btn sm', onclick: onDownload }, icon('down', 12), 'Download') : null,
    el('button', { className: 'btn sm', onclick: close }, 'Close'));
  root.replaceChildren(el('div', { className: 'lightbox', onclick: close },
    bar,
    el('img', { src, onclick: (e) => e.stopPropagation() }),
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
  }, codeBadge(t.type, t.type === active), el('span', { className: 'tt-label' }, t.label),
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
      codeBadge(t.type),
      el('h2', {}, t.label),
      el('span', { className: 'meta' }, `${t.items.length} items · ${sections.length} sections · ${t.catalogs.length} catalogs`),
      el('div', { style: 'display:flex;gap:6px;margin-left:auto' },
        el('button', { className: 'btn sm', onclick: () => editType(t) }, 'Edit'),
        el('button', { className: 'btn sm', onclick: () => tplItemModal(t.type) }, '+ Item'),
        el('button', { className: 'btn sm', onclick: () => exportTemplates(t.type), title: 'Export this asset type to a file' }, 'Export'),
        el('button', { className: 'btn sm', onclick: () => resetTypeDefaults(t) }, 'Defaults'),
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
            el('span', { className: 'tcode' }, typeCode(t.type)),
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
    el('div', {}, el('div', { className: 'kicker' }, 'Settings'), el('h1', {}, 'Workspace'))));

  // Account — shown in every mode; this is where changing your passphrase lives now.
  const canRename = !(LINK?.linked || LINK?.pending);
  page.append(el('div', { className: 'setcard' },
    el('div', { className: 'setcard-hd', style: 'display:flex;align-items:center;gap:10px' },
      el('span', { className: 'kicker' }, 'Operator account'),
      el('span', { style: 'flex:1' }),
      el('div', { className: 'avatar sm' }, (CURRENT_USER || '?')[0].toUpperCase()),
      el('span', { className: 'who' }, CURRENT_USER || '')),
    el('div', { className: 'setcard-actions' },
      canRename ? el('button', { className: 'btn', onclick: changeUsername }, icon('edit'), 'Change username') : null,
      el('button', { className: 'btn gold', onclick: changePassword }, icon('key'), 'Change passphrase'))));

  if (LINK.unavailable) {
    page.append(el('div', { className: 'setcard' },
      el('div', { className: 'setcard-hd' }, el('span', { className: 'kicker' }, 'Team server'), el('span', { className: 'rule' })),
      el('p', { className: 'muted' }, 'This instance is running as a server. Manage users, devices and backups from the Admin panel; linking is for client installs.')));
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
  } else if (LINK.needs_login) {
    const L = LINK.link || {};
    page.append(el('div', { className: 'setcard' },
      el('div', { className: 'setcard-hd' }, el('span', { className: 'linkbadge on' }, el('span', { className: 'dot' }), 'Approved')),
      el('p', { className: 'muted' }, `Your request to join ${L.server_url || 'the server'} was approved. Sign in with your password to finish linking.`),
      el('div', { className: 'setcard-actions' },
        el('button', { className: 'btn gold', onclick: () => linkSignIn() }, icon('server'), 'Sign in'),
        el('button', { className: 'btn danger', onclick: disconnectDialog }, icon('x'), 'Cancel'))));
  } else if (!LINK.linked) {
    page.append(el('div', { className: 'setcard' },
      el('div', { className: 'setcard-hd' }, el('span', { className: 'linkbadge' }, el('span', { className: 'dot' }), 'Working locally')),
      el('p', { className: 'muted' }, 'Everything you create stays in this install. Connect to a team server to share engagements — you will need the server address, a one-time code from an admin, a name and a password. The admin then approves your request.'),
      el('div', { className: 'setcard-actions' },
        el('button', { className: 'btn gold', onclick: connectDialog }, icon('server'), 'Connect to a server'))));
  } else {
    const L = LINK.link || {};
    const atRest = L.token_at_rest === 'encrypted' ? el('span', { className: 'pill ok' }, 'encrypted · workspace passphrase')
      : el('span', { className: 'pill warn' }, 'stored unencrypted — enable encryption');
    page.append(el('div', { className: 'setcard' },
      el('div', { className: 'setcard-hd' }, el('span', { className: 'linkbadge on' }, el('span', { className: 'dot' }), 'Linked')),
      L.needs_reauth ? el('div', { className: 'duebanner' },
        el('div', {}, el('strong', {}, 'Sign-in required'), el('div', { className: 'muted small' }, 'Your session expired or an admin reset your access — syncing is paused. Your local work is safe.')),
        el('button', { className: 'btn gold', onclick: () => linkSignIn({ reauth: true }) }, 'Sign in')) : null,
      kv('Server', L.server_url),
      kv('Signed as', `${L.display_name} · ${L.username} · ${L.role}`),
      kv('This device', L.device_id),
      kv('Fingerprint', el('code', { className: 'fp' }, L.fingerprint || '—')),
      el('div', { className: 'kv' }, el('span', { className: 'k' }, 'Token at rest'), el('span', { className: 'v' }, atRest)),
      L.token_at_rest !== 'encrypted' ? el('p', { className: 'muted small' },
        'Your access token is stored in this workspace’s database, which is not encrypted — anyone with the file can read it. Turn on encryption below to protect it with a passphrase.') : null,
      kv('Connected', L.connected_at ? new Date(L.connected_at).toLocaleString() : '—'),
      kv('Last sync', L.last_sync ? new Date(L.last_sync).toLocaleString() : 'not yet'),
      (() => { const s = el('span', {}, 'checking…'); api('/link/ping').then(hb => { s.textContent = hb?.who?.version ? 'v' + hb.who.version : (hb?.online ? 'unknown' : 'offline'); }).catch(() => { s.textContent = 'offline'; }); return kv('Server version', s); })(),
      el('p', { className: 'muted' }, 'Your work saves locally and syncs in the background. Offline changes are kept and sent when the server is reachable again.'),
      el('div', { className: 'setcard-actions' },
        el('button', { className: 'btn gold', onclick: syncNowUI }, icon('down'), 'Sync now'),
        el('button', { className: 'btn', onclick: pingLink }, 'Check connection'),
        // Force a fresh token on demand (asks for the password, and a 2FA code if the server
        // requires it) — for when you'd rather re-authenticate now than wait for the session to lapse.
        el('button', { className: 'btn', onclick: () => linkSignIn({ reauth: true }) }, icon('server'), 'Sign in again'),
        el('button', { className: 'btn danger', onclick: disconnectDialog }, icon('exit'), 'Disconnect'))));
  }

  // Local at-rest encryption is a property of THIS machine's own database file — the cached link
  // token, the passphrase verifier and every synced finding live in it — so every operator manages
  // it regardless of their team role. Offered on any non-server install (the team server keys its
  // own DB by a secret file, so its web UI never lands here anyway; sec.manageable enforces that).
  if (!ME?.server) {
    try { const sec = await api('/security'); if (sec.manageable) page.append(securityCard(sec)); }
    catch { /* an older server without the endpoint — just omit the card */ }
  }
  // This install's version — on the server's own web UI this IS the server version, so it's the
  // quickest way to confirm an update took.
  page.append(el('p', { className: 'muted small', style: 'margin-top:24px;text-align:center' }, 'Magi v' + (ME?.version || '?')));
  view.replaceChildren(page);
}
function securityCard(sec) {
  const c = el('div', { className: 'setcard' });
  c.append(el('div', { className: 'setcard-hd' }, el('h3', {}, 'Encryption at rest')));
  if (sec.encrypted) {
    c.append(
      el('p', { className: 'muted' }, el('span', { className: 'pill ok' }, 'encrypted'),
        ' This workspace’s database is encrypted on disk — a copied file or a stolen disk is useless without the passphrase.'),
      el('div', { className: 'setcard-actions' },
        el('button', { className: 'btn', onclick: () => rekeyDialog(true) }, 'Change passphrase…')));
  } else {
    c.append(
      el('p', { className: 'muted' }, 'The database is stored unencrypted. Set a passphrase to encrypt it with SQLCipher; you then enter it each time Magi starts.'),
      el('div', { className: 'setcard-actions' },
        el('button', { className: 'btn gold', onclick: () => rekeyDialog(false) }, 'Encrypt this workspace…')));
  }
  return c;
}
function rekeyDialog(isChange) {
  modal({
    kicker: 'Security',
    title: isChange ? 'Change passphrase' : 'Encrypt this workspace',
    cta: isChange ? 'Change' : 'Encrypt',
    danger: !isChange,
    note: isChange
      ? 'Enter your current passphrase, then a new one. It is never stored — you type it at each launch.'
      : 'Choose a passphrase (at least 8 characters). It is NEVER stored, so if you lose it the data cannot be recovered. You will enter it every time Magi starts — back up first if you can.',
    build: (b) => {
      if (isChange) field(b, 'Current passphrase', 'current', { type: 'password' });
      field(b, isChange ? 'New passphrase' : 'Passphrase', 'next', { type: 'password' });
      field(b, 'Confirm passphrase', 'confirm', { type: 'password' });
    },
    onSubmit: async (fd) => {
      const o = Object.fromEntries(fd);
      if ((o.next || '').length < 8) throw new Error('passphrase must be at least 8 characters');
      if (o.next !== o.confirm) throw new Error('the two passphrases do not match');
      await api('/security/rekey', { method: 'POST', body: { current: o.current, next: o.next } });
      toast(isChange ? 'Passphrase changed' : 'Workspace encrypted — you’ll enter this passphrase next launch');
      renderSettings();
    },
  });
}
function connectDialog() {
  modal({
    kicker: 'Team server', title: 'Request to join a server', cta: 'Send request',
    note: 'Get the address and a one-time code from an admin, and pick a password — they approve your request and give you a role. Your local engagements are set aside on approval and restored if you disconnect.',
    build: (b) => {
      field(b, 'Server address', 'server_url', { ph: 'https://magi.corp.local:8443' });
      field(b, 'One-time code', 'code', { ph: 'from your admin' });
      field(b, 'Username', 'username', { ph: 'a new login name' });
      field(b, 'Your display name', 'display_name', { ph: 'shown on your changes, e.g. Ana R.' });
      field(b, 'Password', 'password', { type: 'password', ph: 'at least 8 characters' });
      field(b, 'Confirm password', 'confirm', { type: 'password' });
    },
    onSubmit: async (fd) => {
      const o = Object.fromEntries(fd);
      if ((o.password || '').length < 8) throw new Error('password must be at least 8 characters');
      if (o.password !== o.confirm) throw new Error('the two passwords do not match');
      delete o.confirm;
      const link = await api('/link/connect', { method: 'POST', body: o });
      LINK = { linked: false, pending: true, link };
      toast('Request sent — waiting for an admin to approve');
      renderSettings();
    },
  });
}
// Password (+ OTP when the server asks) to finish a just-approved link, or to re-authenticate
// after the token expired / an admin reset access. A small state machine: password → maybe MFA
// setup (show the key/QR) or a required code → done.
function linkSignIn({ reauth } = {}) {
  const root = $('#modalRoot');
  const close = () => root.replaceChildren();
  let phase = 'password', setup = null, savedPw = '';
  function render() {
    const body = el('div', { className: 'modal-body' },
      el('h3', {}, reauth ? 'Sign in to resume sync' : 'Sign in to finish connecting'),
      el('p', { className: 'modal-note' }, reauth
        ? 'Your session expired or an admin reset your access. Enter your password to keep syncing — your local work is safe.'
        : 'Your request was approved. Enter your password to finish linking.'));
    let pw, otp;
    if (phase === 'password') { pw = el('input', { type: 'password', value: savedPw }); body.append(el('label', {}, 'Password'), pw); }
    if (phase === 'setup') {
      body.append(el('p', { className: 'muted small' }, 'This server requires two-factor. Scan or add the key, then enter the code:'));
      const qr = typeof qrMatrix === 'function' ? qrEl(setup.otpauth_uri) : null;
      if (qr) body.append(qr);
      body.append(el('label', {}, 'Setup key'), el('code', { className: 'codebox' }, setup.secret),
        el('label', { style: 'margin-top:8px' }, 'Code from the app'), (otp = el('input', { inputMode: 'numeric', placeholder: '000000' })));
    }
    if (phase === 'code') { otp = el('input', { inputMode: 'numeric', placeholder: '000000' }); body.append(el('label', {}, 'Two-factor code'), otp); }
    const err = el('div', { className: 'modal-err' }); body.append(err);
    const submit = el('button', { className: 'btn gold', type: 'submit' }, phase === 'password' ? 'Continue' : 'Sign in');
    const form = el('form', { className: 'modal' },
      el('div', { className: 'modal-head' }, el('span', { className: 'modal-kicker' }, 'Team server'), el('button', { type: 'button', className: 'modal-x', onclick: close }, icon('x'))),
      body, el('div', { className: 'actions' }, el('button', { type: 'button', className: 'btn', onclick: close }, 'Cancel'), submit));
    form.onsubmit = async (e) => {
      e.preventDefault(); err.textContent = ''; submit.disabled = true;
      try {
        if (pw) savedPw = pw.value;
        const r = await api('/link/login', { method: 'POST', body: { password: savedPw, otp: otp?.value || undefined } });
        if (r.ok) { close(); if (r.recovery_codes) showRecoveryCodes(r.recovery_codes); toast('Signed in — syncing resumed'); REAUTH_PROMPTED = false; try { LINK = await api('/link'); } catch {} renderAccount(); route(); return; }
        if (r.mfa === 'setup') { setup = { secret: r.secret, otpauth_uri: r.otpauth_uri }; phase = 'setup'; render(); return; }
        if (r.mfa === 'required') { phase = 'code'; render(); return; }
        err.textContent = 'Sign-in failed — try again';
      } catch (ex) { err.textContent = ex.message; } finally { submit.disabled = false; }
    };
    root.replaceChildren(el('div', { className: 'overlay', onclick: (e) => { if (e.target.classList.contains('overlay')) close(); } }, form));
    (otp || pw)?.focus();
  }
  render();
}
function showRecoveryCodes(codes) {
  modal({
    kicker: 'Two-factor', title: 'Save your recovery codes', cta: 'I saved them',
    note: 'Each works once if you lose your phone. They are shown only now.',
    build: (b) => {
      b.append(el('div', { className: 'recovery-grid' }, ...codes.map(c => el('code', {}, c))));
      b.append(el('div', { className: 'setcard-actions', style: 'margin-top:10px' },
        el('button', { type: 'button', className: 'btn', onclick: () => { navigator.clipboard?.writeText(codes.join('\n')); toast('Copied'); } }, 'Copy all'),
        el('button', { type: 'button', className: 'btn', onclick: () => downloadText('magi-recovery-codes.txt', codes.join('\n')) }, 'Download')));
    },
    onSubmit: async () => {},
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
    // A 401 means the token lapsed (expiry or an admin reset access) — offer to sign in rather
    // than a dead-end message. A genuinely revoked device just fails the re-auth, which the dialog shows.
    if (r.revoked) { toast('Session expired — sign in to resume sync'); linkSignIn({ reauth: true }); return; }
    toast(r.online ? 'Server reachable' : ('Server not reachable' + (r.error ? ` — ${r.error}` : '')));
    renderSettings();
  } catch (e) { toast('Ping failed: ' + e.message); }
}
async function syncNowUI() {
  try {
    const r = await api('/link/sync', { method: 'POST' });
    if (r.needs_reauth) { toast('Session expired — sign in to resume sync'); linkSignIn({ reauth: true }); return; }
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
  const savedY = view.scrollTop;                          // preserve scroll across the 5s live-refresh
  const isRefresh = !!view.querySelector('.setcard');     // already showing the admin panel
  const page = el('div', { className: 'page' });
  page.append(el('div', { className: 'page-head' }, el('div', {}, el('div', { className: 'kicker' }, 'Team server'), el('h1', {}, 'Admin'))));
  // On the FIRST paint, show a shell immediately so the body matches the header even if the server
  // hangs. On a background refresh, don't swap in a loading state (that flashed the page to the top
  // every few seconds) — build the new page off-screen and swap it in at the end instead.
  const loading = el('div', { className: 'empty' }, 'Loading team data…');
  if (!isRefresh) { page.append(loading); view.replaceChildren(page); }
  const A = (p, o) => api(ctx.base + p, { ...o, timeout: 8000 });

  let requests = [], devices = [], codes = [], audit = [], users = [];
  try { [requests, devices, codes, audit, users] = await Promise.all([A('/requests'), A('/devices'), A('/enroll-codes'), A('/audit?limit=10'), A('/users')]); }
  catch (e) {
    if (isRefresh) return;                                // a refresh failed — keep what's shown, retry next tick
    loading.textContent = 'Could not load team data: ' + e.message + '. Check the connection, then press Refresh.';
    return;
  }
  loading.remove();
  ADMIN_PENDING = requests.length; renderAccount();

  const card = (title) => el('div', { className: 'setcard' }, el('div', { className: 'setcard-hd' }, el('h3', {}, title)));
  const row = (info, ...actions) => el('div', { className: 'reqrow' }, el('div', { className: 'reqinfo' }, ...info), el('div', { className: 'reqactions' }, ...actions.filter(Boolean)));

  // Join requests
  const reqCard = card(`Join requests (${requests.length})`);
  if (!requests.length) reqCard.append(el('p', { className: 'muted' }, 'No pending requests.'));
  for (const r of requests) reqCard.append(row(
    [el('strong', {}, r.display_name), el('span', { className: 'muted' }, ' wants to join as '), el('span', { className: 'pill' }, r.role),
      el('div', { className: 'muted small' }, `username ${r.username} · device ${String(r.device_id).slice(0, 8)}… · ${new Date(r.created_at).toLocaleString()}`)],
    el('button', { className: 'btn gold', onclick: () => approveDialog(ctx, r.id, r.display_name) }, icon('check', 12), 'Approve'),
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

  // Members — accounts, roles, and MFA status (with lost-phone reset)
  const memCard = card(`Members (${users.length})`);
  for (const m of users) memCard.append(row(
    [el('strong', {}, m.username), el('span', { className: 'muted' }, ' · '), el('span', { className: 'pill' }, m.role),
      el('div', { className: 'muted small' }, m.mfa_enabled ? '🔒 two-factor on' : 'two-factor not set up yet')],
    el('button', { className: 'btn', onclick: () => manageUserDialog(ctx, m) }, icon('edit', 12), 'Manage')));
  page.append(memCard);

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
      el('div', {}, el('div', { className: 'muted small' }, 'New enrollment code — copy it now, it is not shown again'), el('code', { className: 'codebox' }, LAST_CODE.code)),
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

  // Recent activity (last 10; full history is kept in the database)
  const auditCard = card('Recent activity');
  if (!audit.length) auditCard.append(el('p', { className: 'muted' }, 'Nothing yet.'));
  for (const a of audit.slice(0, 10)) auditCard.append(el('div', { className: 'auditrow' },
    el('span', { className: 'muted small' }, new Date(a.at).toLocaleTimeString()),
    el('span', { className: 'aud-who' }, ` ${a.display_name || a.username || '—'} `),
    el('span', { className: 'muted' }, a.action || `${a.method} ${a.path}`)));
  if (audit.length) auditCard.append(el('p', { className: 'muted small', style: 'margin-top:8px' }, 'Showing the last 10 — the full audit trail is kept in the database.'));
  page.append(auditCard);

  view.replaceChildren(page);
  view.scrollTop = savedY;   // stay where the user was reading, don't jump to the top on refresh
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
    note: 'A single-use join ticket. Share it with the person joining; you pick their role when you approve their request.',
    build: (b) => { field(b, 'Note (optional)', 'note', { ph: 'e.g. Ana laptop' }); },
    onSubmit: async (fd) => {
      const r = await api(`${ctx.base}/enroll-codes`, { method: 'POST', body: Object.fromEntries(fd) });
      LAST_CODE = { id: r.id, code: r.code };
      renderAdmin();
    },
  });
}
// Approve a join request, choosing the new member's role.
function approveDialog(ctx, id, name) {
  modal({
    kicker: 'Admin', title: `Approve ${name}`, cta: 'Approve',
    note: 'Choose their role — you can change it later from Members.',
    build: (b) => field(b, 'Role', 'role', { value: 'worker', options: [
      { value: 'worker', label: 'Worker — use checklists, record findings' },
      { value: 'editor', label: 'Editor — also add/edit/delete engagements & targets' },
      { value: 'admin', label: 'Admin — full server management' },
    ] }),
    onSubmit: async (fd) => { await api(`${ctx.base}/requests/${id}/approve`, { method: 'POST', body: { role: Object.fromEntries(fd).role } }); toast(`Approved ${name}`); renderAdmin(); },
  });
}
// Manage a member: change role, reset password / two-factor, or remove them.
function manageUserDialog(ctx, m) {
  modal({
    kicker: 'Admin', title: `Manage ${m.username}`, cta: 'Save role',
    note: 'Changing the role or resetting the password signs this member out of every device (they sign in again).',
    build: (b) => {
      field(b, 'Role', 'role', { value: m.role, options: [
        { value: 'worker', label: 'Worker' }, { value: 'editor', label: 'Editor' }, { value: 'admin', label: 'Admin' },
      ] });
      b.append(el('div', { className: 'setcard-actions', style: 'margin-top:12px' },
        el('button', { type: 'button', className: 'btn', onclick: () => resetUserPasswordDialog(ctx, m) }, 'Reset password…'),
        m.mfa_enabled ? el('button', { type: 'button', className: 'btn', onclick: () => resetMfaDialog(ctx, m) }, 'Reset two-factor') : null,
        el('button', { type: 'button', className: 'btn danger', onclick: () => removeUserDialog(ctx, m) }, 'Remove member')));
    },
    onSubmit: async (fd) => { await api(`${ctx.base}/users/${m.id}/role`, { method: 'POST', body: { role: Object.fromEntries(fd).role } }); toast('Role updated'); renderAdmin(); },
  });
}
function resetUserPasswordDialog(ctx, m) {
  modal({
    kicker: 'Admin', title: `Reset ${m.username}'s password`, cta: 'Reset', danger: true,
    note: 'Sets a new password and signs them out everywhere — they sign in again with it. Share it over a trusted channel.',
    build: (b) => { field(b, 'New password', 'password', { type: 'password', ph: 'at least 8 characters' }); field(b, 'Confirm', 'confirm', { type: 'password' }); },
    onSubmit: async (fd) => { const o = Object.fromEntries(fd); if ((o.password || '').length < 8) throw new Error('password must be at least 8 characters'); if (o.password !== o.confirm) throw new Error('the two passwords do not match'); await api(`${ctx.base}/users/${m.id}/reset-password`, { method: 'POST', body: { password: o.password } }); toast('Password reset'); renderAdmin(); },
  });
}
function removeUserDialog(ctx, m) {
  modal({
    kicker: 'Admin', title: `Remove ${m.username}?`, cta: 'Remove', danger: true,
    note: 'Deletes this account and all its devices from the server. Their synced engagements stay on the server. This cannot be undone.',
    onSubmit: async () => { await api(`${ctx.base}/users/${m.id}`, { method: 'DELETE' }); toast('Member removed'); renderAdmin(); },
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
function resetMfaDialog(ctx, m) {
  modal({
    kicker: 'Admin', title: `Reset two-factor for ${m.username}?`, cta: 'Reset', danger: true,
    note: 'Clears their authenticator and recovery codes so they enrol fresh at next sign-in, and signs them out everywhere. Use this for a lost or wiped phone.',
    onSubmit: async () => { await api(`${ctx.base}/users/${m.id}/reset-mfa`, { method: 'POST' }); toast('Two-factor reset'); renderAdmin(); },
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
  loginPasswordStep();
}
// One card, wrapped in the MAGI mark. Each login step swaps the card in this same shell.
function loginShell(card) {
  const box = el('form', { className: 'login-box' },
    el('div', { className: 'login-mark' }, magiMark(72),
      el('div', {}, el('div', { className: 'login-name' }, 'MAGI'),
        el('div', { className: 'login-tag' }, "The pentester's familiar"))),
    card);
  $('#view').replaceChildren(el('div', { className: 'login-wrap' }, box));
  return box;
}
const showLoginErr = (node, msg) => { node.textContent = String(msg).toUpperCase().startsWith('TOO MANY') ? String(msg).toUpperCase() : msg; };
async function afterAuth() { onAuthed(await api('/me')); } // fetch the full profile (role, server, …)
// Login is the one endpoint whose non-2xx body is meaningful: a 401 can be a real error (bad
// password / wrong code) OR an MFA challenge ({mfa:'required'|'setup'}). api() throws on any 401
// before exposing the body, so login talks to the endpoint directly and returns the parsed body.
async function postLogin(body) {
  const r = await fetch('/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  let json = {}; try { json = await r.json(); } catch { /* empty */ }
  return { status: r.status, json };
}
function copyField(display, value, mono) {
  return el('div', { className: 'mfa-copy' },
    el('input', { readOnly: true, value: display, className: 'mfa-field' + (mono ? ' mono' : '') }),
    el('button', { type: 'button', className: 'btn sm', onclick: () => { navigator.clipboard?.writeText(value); toast('Copied'); } }, 'Copy'));
}
function downloadText(name, text) {
  const a = el('a', { href: URL.createObjectURL(new Blob([text], { type: 'text/plain' })), download: name });
  document.body.append(a); a.click(); a.remove(); URL.revokeObjectURL(a.href);
}

function loginPasswordStep() {
  const u = el('input', { name: 'username', placeholder: 'admin', autocomplete: 'username' });
  const p = el('input', { name: 'password', type: 'password', autocomplete: 'current-password' });
  const err = el('div', { className: 'loginerr' });
  const hint = el('div', { className: 'login-hint' });
  // On a linked device you sign in with your SERVER account, not a local one — lock the username to
  // it and say so. (A local account can no longer open a device that's connected to a server.)
  fetch('/api/me').then(r => r.json()).then(d => {
    if (d?.link?.username) { u.value = d.link.username; u.readOnly = true; hint.textContent = 'sign in with your team-server account'; }
    else if (d?.hint) { hint.textContent = `default login — ${d.hint}`; }
  }).catch(() => {});
  const box = loginShell(el('div', { className: 'login-card' },
    el('label', {}, 'Operator'), u,
    el('label', {}, 'Passphrase'), p,
    err, el('button', { className: 'btn gold', type: 'submit' }, 'Authenticate'), hint));
  box.onsubmit = async (e) => {
    e.preventDefault(); err.textContent = ''; p.style.borderColor = '';
    try {
      const { json: r } = await postLogin({ username: u.value, password: p.value });
      if (r.token) { setAuthToken(r.token); return afterAuth(); }
      if (r.mfa === 'setup') return loginSetupStep(u.value, p.value, r);
      if (r.mfa === 'required') return loginCodeStep(u.value, p.value);
      throw new Error(r.error || 'authentication failed');
    } catch (ex) { showLoginErr(err, ex.message.toUpperCase().startsWith('TOO MANY') ? ex.message : `AUTH REJECTED — ${ex.message}.`); p.style.borderColor = 'var(--red)'; }
  };
  u.focus();
}

// Enrolled account: enter the rolling code (or a one-time recovery code). The password from the
// first step is carried in memory so we can complete the login in one call.
function loginCodeStep(username, password) {
  let recovery = false;
  const label = el('label', {}, 'Authenticator code');
  const code = el('input', { inputMode: 'numeric', autocomplete: 'one-time-code', placeholder: '000000', maxLength: 6, className: 'mfa-code' });
  const err = el('div', { className: 'loginerr' });
  const toggle = el('button', { type: 'button', className: 'linklike' }, 'Use a recovery code');
  toggle.onclick = () => {
    recovery = !recovery;
    label.textContent = recovery ? 'Recovery code' : 'Authenticator code';
    code.placeholder = recovery ? 'xxxx-xxxx' : '000000';
    code.maxLength = recovery ? 9 : 6; code.className = recovery ? '' : 'mfa-code';
    toggle.textContent = recovery ? 'Use an authenticator code' : 'Use a recovery code';
    code.value = ''; code.focus();
  };
  const box = loginShell(el('div', { className: 'login-card' },
    el('div', { className: 'login-hd' }, 'Two-factor'),
    el('p', { className: 'login-note' }, 'Enter the 6-digit code from your authenticator app.'),
    label, code, err,
    el('button', { className: 'btn gold', type: 'submit' }, 'Verify'),
    el('div', { className: 'login-row' }, toggle, el('button', { type: 'button', className: 'linklike', onclick: showLogin }, 'Back'))));
  box.onsubmit = async (e) => {
    e.preventDefault(); err.textContent = '';
    try {
      const { json: r } = await postLogin({ username, password, otp: code.value });
      if (!r.token) throw new Error(r.error || 'that code did not work — try again');
      setAuthToken(r.token); await afterAuth();
    } catch (ex) { showLoginErr(err, ex.message); code.select(); }
  };
  code.focus();
}

// First-time enrolment: scan/enter the key, confirm a code, then save recovery codes.
// Render a QR matrix of `text` as a crisp SVG (white quiet zone + black modules). null if the
// QR generator failed to load — the setup screen still works via the manual key.
function qrEl(text) {
  let m; try { m = qrMatrix(text); } catch { return null; }
  const q = 4, dim = m.size + q * 2;
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', `0 0 ${dim} ${dim}`);
  svg.setAttribute('class', 'qrcode'); svg.setAttribute('shape-rendering', 'crispEdges');
  const bg = document.createElementNS(NS, 'rect');
  bg.setAttribute('width', dim); bg.setAttribute('height', dim); bg.setAttribute('fill', '#fff');
  svg.append(bg);
  let d = '';
  for (let y = 0; y < m.size; y++) for (let x = 0; x < m.size; x++)
    if (m.modules[y][x]) d += `M${x + q} ${y + q}h1v1h-1z`;
  const path = document.createElementNS(NS, 'path');
  path.setAttribute('d', d); path.setAttribute('fill', '#000');
  svg.append(path);
  return svg;
}
function loginSetupStep(username, password, r) {
  const grouped = r.secret.replace(/(.{4})/g, '$1 ').trim();
  const code = el('input', { inputMode: 'numeric', autocomplete: 'one-time-code', placeholder: '000000', maxLength: 6, className: 'mfa-code' });
  const err = el('div', { className: 'loginerr' });
  const qr = typeof qrMatrix === 'function' ? qrEl(r.otpauth_uri) : null;
  const box = loginShell(el('div', { className: 'login-card' },
    el('div', { className: 'login-hd' }, 'Set up two-factor'),
    el('p', { className: 'login-note' }, 'Your team requires an authenticator app (Google Authenticator, Authy, 1Password…). Scan the QR — or add an account with the setup key — then enter the code it shows.'),
    qr, qr ? el('div', { className: 'qr-hint' }, 'Scan with your authenticator app') : null,
    el('label', {}, 'Setup key'), copyField(grouped, r.secret),
    el('label', {}, 'Or paste this link into the app'), copyField(r.otpauth_uri, r.otpauth_uri, true),
    el('label', { style: 'margin-top:8px' }, 'Code from the app'), code, err,
    el('button', { className: 'btn gold', type: 'submit' }, 'Confirm & continue'),
    el('div', { className: 'login-row' }, el('button', { type: 'button', className: 'linklike', onclick: showLogin }, 'Back'))));
  box.onsubmit = async (e) => {
    e.preventDefault(); err.textContent = '';
    try {
      const { json: res } = await postLogin({ username, password, otp: code.value });
      if (!res.token) throw new Error(res.error || 'that code did not match');
      setAuthToken(res.token);
      loginRecoveryStep(res.recovery_codes);
    } catch (ex) { showLoginErr(err, ex.message); code.select(); }
  };
  code.focus();
}

function loginRecoveryStep(codes) {
  const box = loginShell(el('div', { className: 'login-card' },
    el('div', { className: 'login-hd' }, 'Save your recovery codes'),
    el('p', { className: 'login-note' }, 'Each works once if you lose your phone. Store them somewhere safe — they are shown only now.'),
    el('div', { className: 'recovery-grid' }, ...codes.map(c => el('code', {}, c))),
    el('div', { className: 'login-row', style: 'margin:12px 0' },
      el('button', { type: 'button', className: 'btn', onclick: () => { navigator.clipboard?.writeText(codes.join('\n')); toast('Copied'); } }, icon('down', 12), 'Copy all'),
      el('button', { type: 'button', className: 'btn', onclick: () => downloadText('magi-recovery-codes.txt', codes.join('\n')) }, 'Download')),
    el('button', { className: 'btn gold', type: 'submit' }, 'I saved them — continue')));
  box.onsubmit = async (e) => { e.preventDefault(); try { await afterAuth(); } catch { showLogin(); } };
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
    // Preserve scroll across the redraw. The engagement/home views scroll in #view; the target
    // checklist scrolls in .target-col — restore whichever applies so a refresh never jumps to top.
    const viewY = $('#view')?.scrollTop || 0;
    const colY = $('.target-col')?.scrollTop || 0;
    await route();
    if ($('#view')) $('#view').scrollTop = viewY;
    if ($('.target-col')) $('.target-col').scrollTop = colY;
  }
  LAST_REV = rev;
}
function onAuthed(me) {
  CURRENT_USER = me.username;
  ME = me;
  $('#topbar').hidden = false;
  renderAccount();
  // Replace the login screen IMMEDIATELY — never let a slow or hanging server call leave the
  // two-factor screen sitting under the (now visible) top bar. The type list and team link only
  // enrich the view (icons, admin controls), so load them in the background and re-render once
  // they land. A hung request now just delays the enrichment, not the whole app.
  route();
  (async () => {
    let enriched = false;
    try { TYPES = await api('/asset-types'); enriched = true; } catch { /* offline / hiccup — keep the view */ }
    try { await refreshLink(); enriched = true; } catch { /* keep going */ }
    if (enriched && CURRENT_USER) route();
  })();
  // Keep the link/admin state (pending badge, incoming requests) reasonably fresh…
  clearInterval(LINK_POLL);
  LINK_POLL = setInterval(() => { if (CURRENT_USER) refreshLink(); }, 12000);
  // …and live-refresh the engagement view as changes sync in.
  clearInterval(DATA_POLL);
  DATA_POLL = setInterval(() => { pollData().catch(() => {}); }, 10000);
}
async function logout() { try { await api('/auth/logout', { method: 'POST' }); } catch { /* best effort */ } clearAuthToken(); showLogin(); }
function changePassword() {
  modal({
    kicker: 'Account', title: 'Change passphrase', cta: 'Change',
    note: 'Signs out every other session. Minimum 10 characters.',
    build: (b) => {
      field(b, 'Current passphrase', 'current', { type: 'password' });
      field(b, 'New passphrase', 'next', { type: 'password' });
    },
    onSubmit: async (fd) => {
      const r = await api('/change-password', { method: 'POST', body: Object.fromEntries(fd) });
      if (r?.token) setAuthToken(r.token); // keep THIS session alive; the epoch bump killed the rest
      toast('Passphrase changed — other sessions signed out');
    },
  });
}
function changeUsername() {
  modal({
    kicker: 'Account', title: 'Change username', cta: 'Change',
    note: 'Your sign-in name. Confirm with your current password.',
    build: (b) => {
      field(b, 'New username', 'username', { value: CURRENT_USER || '', ph: 'e.g. memo' });
      field(b, 'Current password', 'password', { type: 'password' });
    },
    onSubmit: async (fd) => {
      const r = await api('/change-username', { method: 'POST', body: Object.fromEntries(fd) });
      CURRENT_USER = r.username; if (ME) ME.username = r.username;
      renderAccount();
      toast('Username changed to ' + r.username);
    },
  });
}

// The templates button lives in the header, next to the account block. Editing templates is
// admin-only, so its visibility is toggled by renderAccount() as the link/role settles.
$('#topbar').insertBefore(
  el('button', { id: 'tplBtn', className: 'btn', onclick: () => location.hash = '/editor', title: 'Checklist templates' },
    icon('lines'), el('span', { className: 'lbl' }, 'Templates')),
  $('#account'));

// ---------- boot ----------
(async () => {
  try { onAuthed(await api('/me')); }
  catch { showLogin(); }
})();
