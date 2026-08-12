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
  key: ['M10.5 2.5a3.5 3.5 0 100 7 3.5 3.5 0 000-7zM8 8l-5.5 5.5V15h2l4-4', 1.3],
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
  if (r.status === 401 && path !== '/me' && path !== '/auth/login') { showLogin(); throw new Error('Session expired'); }
  if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.error || r.statusText); }
  return r.headers.get('content-type')?.includes('json') ? r.json() : r.text();
}
function toast(msg) {
  $('.toast')?.remove();
  const t = el('div', { className: 'toast', textContent: msg });
  document.body.append(t); setTimeout(() => t.remove(), 1800);
}
const pct = (a, b) => (b ? Math.round((a / b) * 100) : 0);
const pad = (n) => String(n).padStart(2, '0');
const HANDLED = ['done', 'na', 'yes', 'no'];
const ACTIONABLE = (i) => !['select', 'group'].includes(i.kind);
const KIND_OPTS = [
  { value: 'check', label: 'Check' }, { value: 'question', label: 'Question / input' },
  { value: 'input', label: 'Input value' }, { value: 'trigger', label: 'Trigger (yes/no + follow-up)' },
  { value: 'select', label: 'Select (option chips)' }];
const daysSince = (iso) => Math.max(1, Math.round((Date.now() - new Date(iso.replace(' ', 'T') + 'Z')) / 864e5));

let TYPES = [];
let CURRENT_USER = null;

// ---------- modal ----------
// kicker + title + optional note, fields, optional danger box, gold/red CTA
function modal(opts) {
  const { kicker = 'Form', title, note, build, onSubmit, cta = 'Save', danger = false } = opts;
  const root = $('#modalRoot');
  const form = el('form', { className: 'modal' + (danger ? ' danger' : '') });
  const body = el('div', { className: 'modal-body' }, el('h3', {}, title), note ? el('p', { className: 'modal-note' }, note) : null);
  if (build) build(body);
  const close = () => root.replaceChildren();
  const x = el('button', { type: 'button', className: 'modal-x', title: 'Close', onclick: close }, icon('x'));
  form.append(
    el('div', { className: 'modal-head' }, el('span', { className: 'modal-kicker' }, kicker), x),
    body,
    el('div', { className: 'actions' },
      el('button', { type: 'button', className: 'btn', onclick: close }, 'Cancel'),
      el('button', { type: 'submit', className: 'btn ' + (danger ? 'dangerfill' : 'gold') }, cta)));
  form.onsubmit = async (e) => {
    e.preventDefault();
    try { await onSubmit(new FormData(form)); close(); }
    catch (err) { alert(err.message); }
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
  $('#account').replaceChildren(el('div', { className: 'acct' },
    el('div', { className: 'avatar' }, (CURRENT_USER || '?')[0].toUpperCase()),
    el('span', { className: 'who' }, CURRENT_USER || ''),
    el('button', { className: 'iconbtn', title: 'Change password', onclick: changePassword }, icon('key')),
    el('button', { className: 'iconbtn danger', title: 'Sign out', onclick: logout }, icon('exit'))));
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
  if (!CURRENT_USER) return;
  try {
    if (h === '/editor') return renderEditor();
    const gm = h.match(/^\/group\/(\d+)/); if (gm) return renderGroup(gm[1]);
    const em = h.match(/^\/editor\/([a-z0-9_]+)/); if (em) return renderEditor(em[1]);
    const [, kind, id] = h.match(/^\/(project|asset)\/(\d+)/) || [];
    if (kind === 'project') return renderProject(id);
    if (kind === 'asset') return renderAsset(id);
    return renderHome();
  } catch (e) {
    setRail(null);
    $('#view').replaceChildren(el('div', { className: 'page' }, el('div', { className: 'empty' }, 'Error: ' + e.message)));
  }
}
window.addEventListener('hashchange', route);
$('#homeBtn').onclick = () => location.hash = '';

// ---------- engagements (home) ----------
async function renderHome() {
  const projects = await api('/projects');
  setRail(null);
  setCrumbs([{ label: 'engagements' }]);
  const view = $('#view');
  const head = el('div', { className: 'page-head' },
    el('div', {}, el('div', { className: 'kicker' }, 'Workspace'), el('h1', {}, 'Engagements')),
    el('button', { className: 'btn gold', onclick: newProject }, icon('plus', 12), 'New engagement'));

  if (!projects.length) {
    return view.replaceChildren(el('div', { className: 'page' }, head,
      el('div', { className: 'empty', style: 'margin-top:26px' },
        el('div', {}, 'No engagements yet. Every target, checklist and finding lives inside one.'),
        el('button', { className: 'btn gold', onclick: newProject }, icon('plus', 12), 'Create the first'))));
  }

  const table = el('div', { className: 'ptable' },
    el('div', { className: 'ptable-head kicker' },
      el('span', {}, 'Engagement'), el('span', { className: 'hide-sm' }, 'Client'),
      el('span', { className: 'hide-sm' }, 'Coverage'), el('span', { className: 'hide-sm' }, 'Opened'), el('span', {})));

  for (const p of projects) {
    const cov = pct(p.handled, p.total);
    const del = el('button', { className: 'ibtn del', title: 'Delete engagement' }, icon('trash'));
    del.onclick = (e) => { e.stopPropagation(); delProject(p, p.asset_count, renderHome); };
    const dot = el('span', { className: 'pdot' + (!p.total ? ' idle' : cov > 70 ? '' : ' part') });
    table.append(el('button', { className: 'prow', onclick: () => location.hash = `/project/${p.id}` },
      el('span', { style: 'display:flex;align-items:center;gap:12px;min-width:0' }, dot,
        el('span', { style: 'display:flex;flex-direction:column;gap:3px;min-width:0' },
          el('span', { className: 'pname' }, p.name),
          el('span', { className: 'pmeta' }, `${p.asset_count} targets · ${p.finding_count} findings`))),
      el('span', { className: 'pcell hide-sm' }, p.client || '—'),
      el('span', { className: 'hide-sm', style: 'display:flex;align-items:center;gap:10px' },
        el('span', { className: 'bar' + (cov > 70 ? ' good' : !cov ? ' idle' : '') }, el('span', { style: `width:${cov}%` })),
        el('span', { className: 'pct' + (cov > 70 ? ' good' : cov ? ' some' : '') }, cov + '%')),
      el('span', { className: 'pcell hide-sm' }, new Date(p.created_at).toLocaleDateString(undefined, { day: '2-digit', month: 'short' })),
      del));
  }
  table.append(el('div', { className: 'end' }));
  view.replaceChildren(el('div', { className: 'page' }, head, table));
}

function newProject() {
  modal({
    kicker: 'Create', title: 'New engagement', cta: 'Create',
    build: (b) => {
      field(b, 'Engagement name', 'name', { ph: 'Acme Corp — Q4 External' });
      field(b, 'Client', 'client', { ph: 'Acme Corp' });
      field(b, 'Scope', 'scope', { ph: '*.acme.com, 10.0.0.0/16' });
      field(b, 'Notes', 'notes', { textarea: true });
    },
    onSubmit: async (fd) => {
      const p = await api('/projects', { method: 'POST', body: Object.fromEntries(fd) });
      location.hash = `/project/${p.id}`;
    },
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

// ---------- rail (targets of the current engagement) ----------
function railFor(project, activeAssetId) {
  const total = project.assets.reduce((a, x) => a + x.total, 0);
  const handled = project.assets.reduce((a, x) => a + x.handled, 0);
  const head = el('div', { className: 'rail-head' },
    el('div', { className: 'kicker' }, 'Engagement'),
    el('div', { className: 'rail-title' }, project.name),
    el('div', { className: 'rail-status' }, el('span', { className: 'pulse' }),
      `${pct(handled, total)}% · ${project.assets.length} TARGET${project.assets.length === 1 ? '' : 'S'}`));
  const list = el('div', { className: 'rail-list' });
  for (const a of project.assets) {
    const p = pct(a.handled, a.total);
    list.append(el('button', {
      className: 'railtarget' + (String(a.id) === String(activeAssetId) ? ' on' : ''),
      onclick: () => location.hash = `/asset/${a.id}`,
    },
      el('span', { className: 'rt-top' },
        el('span', { className: 'rt-kind' }, a.type.toUpperCase()),
        el('span', { className: 'rt-pct' }, p + '%')),
      el('span', { className: 'rt-name' }, a.label),
      el('span', { className: 'bar thin' + (p > 70 ? ' good' : !p ? ' idle' : '') }, el('span', { style: `width:${p}%` }))));
  }
  if (!project.assets.length) list.append(el('div', { className: 'pmeta', style: 'padding:10px' }, 'No targets yet'));
  return [head, el('div', { className: 'rail-label kicker' }, 'Targets'), list,
    el('div', { className: 'rail-foot' },
      el('button', { className: 'dashbtn', onclick: () => addAsset(project.id) }, icon('plus', 12), 'Add target'))];
}

// ---------- engagement detail ----------
async function renderProject(id) {
  const p = await api('/projects/' + id);
  setRail(railFor(p, null));
  setCrumbs([{ label: 'engagements', go: () => location.hash = '' }, { label: p.name }]);
  topActions(
    el('button', { className: 'btn', onclick: () => exportProject(id) }, icon('down', 12), 'Export'),
    el('button', { className: 'btn danger', onclick: () => delProject(p, p.assets.length, () => location.hash = '') }, 'Delete'));

  const total = p.assets.reduce((a, x) => a + x.total, 0);
  const handled = p.assets.reduce((a, x) => a + x.handled, 0);
  const findings = p.assets.reduce((a, x) => a + (x.findings || 0), 0);
  const flags = p.assets.reduce((a, x) => a + x.flags, 0);

  const stat = (label, value, cls) => el('div', { className: 'stat' },
    el('div', { className: 'kicker' }, label), el('div', { className: 'stat-value ' + (cls || '') }, value));

  const list = el('div', { className: 'tlist' });
  if (!p.assets.length) {
    list.append(el('div', { className: 'empty', style: 'border:0' },
      el('div', {}, 'No targets in scope yet. Add a URL, host, subnet, domain, API or app.'),
      el('button', { className: 'btn gold', onclick: () => addAsset(id) }, icon('plus', 12), 'Add target')));
  }
  for (const a of p.assets) {
    const t = TYPES.find(x => x.type === a.type) || {};
    const cov = pct(a.handled, a.total);
    const del = el('button', { className: 'ibtn del', title: 'Delete target' }, icon('trash'));
    del.onclick = (e) => { e.stopPropagation(); delAsset(a, () => renderProject(id)); };
    list.append(el('button', { className: 'trow', onclick: () => location.hash = `/asset/${a.id}` },
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
    el('div', { className: 'kicker' }, 'Engagement'),
    el('h1', {}, p.name),
    p.client || p.scope ? el('div', { className: 'lede' }, [p.client, p.scope].filter(Boolean).join(' · ')) : null,
    el('div', { className: 'stats' },
      stat('Coverage', pct(handled, total) + '%', 'gold'),
      stat('Findings', String(findings + flags), 'red'),
      stat('Targets', String(p.assets.length)),
      stat('Days open', String(daysSince(p.created_at)))),
    el('div', { className: 'srule' },
      el('span', { className: 'kicker' }, 'Targets'), el('span', { className: 'rule' }),
      el('button', { className: 'btn line sm', onclick: () => addAsset(id) }, '+ Add target')),
    list));
}

function addAsset(projectId) {
  modal({
    kicker: 'Scope', title: 'Add a target', cta: 'Add target',
    build: (b) => {
      const hidden = el('input', { type: 'hidden', name: 'type', value: TYPES[0]?.type || 'web' });
      const grid = el('div', { className: 'typegrid' });
      const label = el('input', { name: 'label', placeholder: TYPES[0]?.hint || 'value' });
      for (const t of TYPES) {
        const btn = el('button', { type: 'button', className: 'type' + (t.type === hidden.value ? ' sel' : '') },
          el('span', { className: 'lbl' }, `${t.icon || ''} ${t.label}`),
          el('span', { className: 'hint' }, t.hint || t.type));
        btn.onclick = () => {
          hidden.value = t.type; label.placeholder = t.hint || 'value';
          for (const x of grid.children) x.classList.remove('sel');
          btn.classList.add('sel'); label.focus();
        };
        grid.append(btn);
      }
      b.append(el('label', {}, 'Asset type'), grid, hidden, el('label', {}, 'Identifier'), label);
    },
    onSubmit: async (fd) => {
      const body = { type: fd.get('type'), label: fd.get('label') };
      if (!body.label) throw new Error('Enter an identifier');
      const a = await api(`/projects/${projectId}/assets`, { method: 'POST', body });
      location.hash = `/asset/${a.id}`;
    },
  });
}

function delAsset(a, after) {
  const items = a.total ?? a.items?.length ?? 0;
  const findings = a.findings?.length ?? a.findings ?? 0;
  const done = a.handled ?? a.items?.filter(i => HANDLED.includes(i.status)).length ?? 0;
  modal({
    kicker: 'Destructive', title: `Delete target “${a.label}”?`, danger: true, cta: 'Delete forever',
    note: 'The engagement is kept. Everything recorded against this target is not.',
    build: (b) => b.append(el('div', { className: 'dangerbox' },
      el('div', { className: 'kicker' }, 'Irreversible'),
      el('ul', { className: 'dellist' },
        el('li', {}, `${items} checklist item${items === 1 ? '' : 's'}${done ? ` (${done} already handled)` : ''}`),
        el('li', {}, findings ? `${findings} finding${findings === 1 ? '' : 's'} and captured evidence` : 'Any findings and evidence recorded against it'),
        el('li', {}, 'All answers and progress')))),
    onSubmit: async () => {
      await api('/assets/' + a.id, { method: 'DELETE' });
      curAssetId = null; toast('Target deleted');
      if (after) after(); else location.hash = `/project/${a.project_id}`;
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

async function renderAsset(id) {
  id = String(id);
  const a = await api('/assets/' + id);
  const t = TYPES.find(x => x.type === a.type) || {};
  if (curAssetId !== id) { curAssetId = id; openGroups.clear(); openPayloads.clear(); FILTER = 'all'; }

  const project = await api('/projects/' + a.project_id);
  setRail(railFor(project, id));
  setCrumbs([
    { label: 'engagements', go: () => location.hash = '' },
    { label: project.name, go: () => location.hash = `/project/${a.project_id}` },
    { label: a.label }]);
  topActions(
    el('button', { className: 'btn', onclick: () => delAsset(a) }, 'Delete target'));

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
        renderAsset(id);
      },
    }, f.l, el('span', {}, String(f.n))));
  }

  const head = el('div', { className: 'target-head' },
    el('div', { style: 'display:flex;align-items:flex-start;gap:16px' },
      el('div', { style: 'min-width:0;flex:1' },
        el('div', { className: 'kicker' }, t.label || a.type),
        el('h1', {}, a.label)),
      el('div', { className: 'target-actions' },
        el('button', { className: 'btn', onclick: () => { groups.forEach(g => openGroups.add(g.key)); renderAsset(id); } }, 'Expand all'),
        el('button', { className: 'btn', onclick: () => { openGroups.clear(); renderAsset(id); } }, 'Collapse'),
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
    hdr.onclick = () => { open ? openGroups.delete(g.key) : openGroups.add(g.key); renderAsset(id); };
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
    const del = el('button', { className: 'ibtn del', title: 'Delete', onclick: async () => { await api('/findings/' + f.id, { method: 'DELETE' }); renderAsset(id); } }, icon('x', 11));
    dbody.append(el('div', { className: 'finding sev-' + (f.severity || 'info') },
      el('div', { className: 'f-top' },
        el('span', { className: 'f-sev' }, f.severity || 'note'),
        el('span', { className: 'f-kind' }, f.kind)),
      el('div', { className: 'f-title' }, f.title),
      f.body ? el('pre', {}, f.body) : null, del));
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
    onclick: () => { pOpen ? openPayloads.delete(it.id) : openPayloads.add(it.id); renderAsset(assetId); },
  }, `${pOpen ? '▾' : '▸'} ${pcount} payload${pcount > 1 ? 's' : ''}`));
  body.append(row);
  if (it.detail) body.append(el('p', { className: 'detail' }, it.detail));

  if (isSelect) {
    const chosen = new Set(kids.map(k => k.opt_key));
    const chips = el('div', { className: 'chips' });
    for (const o of (it.options || [])) {
      const on = chosen.has(o.key);
      chips.append(el('button', {
        className: 'chip' + (on ? ' on' : ''),
        onclick: async () => { await api('/items/' + it.id + '/select', { method: 'POST', body: { key: o.key } }); renderAsset(assetId); },
      }, (on ? '✓ ' : '') + o.label));
    }
    body.append(chips);
  }

  if (pcount && pOpen) {
    const box = el('div', { className: 'payloads' });
    for (const p of it.payloads) {
      const c = el('code', { title: 'click to copy' }, p);
      c.onclick = () => { navigator.clipboard?.writeText(p); toast('Copied'); };
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
        renderAsset(assetId);
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
      onclick: async () => { if (confirm(kids.length ? 'Delete this item and everything under it?' : 'Delete this item?')) { await api('/items/' + it.id, { method: 'DELETE' }); renderAsset(assetId); } },
    }, icon('x', 12))));

  node.append(el('span', { className: 'inum' }, pad(num)), body, actions);
  return node;
}

async function doSpawn(it, assetId) {
  const r = await api('/items/' + it.id + '/spawn', { method: 'POST' });
  toast(r.instance > 1 ? `Added follow-up #${r.instance}` : `Added ${r.added} items`);
  renderAsset(assetId);
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
      renderAsset(assetId);
    },
  });
}

function addFinding(assetId) {
  modal({
    kicker: 'Evidence', title: 'Capture evidence', cta: 'Save',
    note: 'Raw requests, credentials and confirmed issues. These become the findings section of the export.',
    build: (b) => {
      field(b, 'Title', 'title', { ph: 'Login endpoint captured' });
      field(b, 'Type', 'kind', {
        options: [{ value: 'note', label: 'Note' }, { value: 'request', label: 'HTTP request' },
        { value: 'credential', label: 'Credential' }, { value: 'vuln', label: 'Vulnerability' }]
      });
      field(b, 'Severity', 'severity', {
        options: [{ value: '', label: '—' }, { value: 'info', label: 'Info' }, { value: 'low', label: 'Low' },
        { value: 'medium', label: 'Medium' }, { value: 'high', label: 'High' }, { value: 'critical', label: 'Critical' }]
      });
      field(b, 'Body', 'body', { textarea: true, ph: 'POST /login HTTP/1.1\nHost: ...' });
    },
    onSubmit: async (fd) => {
      await api(`/assets/${assetId}/findings`, { method: 'POST', body: Object.fromEntries(fd) });
      renderAsset(assetId);
    },
  });
}

async function exportProject(id) {
  const md = await api(`/projects/${id}/export`);
  const blob = new Blob([md], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const link = el('a', { href: url, download: `magi-engagement-${id}.md` });
  document.body.append(link); link.click(); link.remove(); URL.revokeObjectURL(url);
  toast('Markdown exported');
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
  for (const t of types) {
    side.append(el('button', {
      className: 'tpl-type' + (t.type === active ? ' on' : ''),
      onclick: () => location.hash = `/editor/${t.type}`,
    }, el('span', { className: 'tt-label' }, `${t.icon || ''} ${t.label}`),
      el('span', { className: 'tt-count' }, String(t.item_count))));
  }
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
function onAuthed(me) {
  CURRENT_USER = me.username;
  $('#topbar').hidden = false;
  renderAccount();
  (async () => { TYPES = await api('/asset-types'); route(); })();
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
    icon('lines'), 'Templates'),
  $('#account'));

// ---------- boot ----------
(async () => {
  try { onAuthed(await api('/me')); }
  catch { showLogin(); }
})();
