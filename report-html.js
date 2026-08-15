// Self-contained HTML findings report. Images are embedded as data: URIs so the file
// is a single portable document — hand it to a client and it opens anywhere with no
// server, no external assets, no missing screenshots.
import { db } from './db.js';

const esc = (s) => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4, '': 5, null: 5 };
const SEV_COLOR = { critical: '#7c1d1d', high: '#E2453C', medium: '#E8B65A', low: '#3D6FF0', info: '#6A7288' };

export function projectReportHTML(projectId) {
  const p = db.prepare(`SELECT * FROM projects WHERE id=?`).get(projectId);
  if (!p) return null;
  const assets = db.prepare(`SELECT * FROM assets WHERE project_id=? ORDER BY created_at, id`).all(p.id);

  // gather findings with their images, across the whole engagement
  const blocks = [];
  let total = 0, withImages = 0;
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, none: 0 };
  for (const a of assets) {
    const findings = db.prepare(`SELECT * FROM findings WHERE asset_id=? ORDER BY id`).all(a.id)
      .map(f => ({
        ...f,
        images: db.prepare(`SELECT id, filename, mime, data FROM attachments WHERE finding_id=? ORDER BY id`).all(f.id),
      }));
    if (!findings.length) continue;
    findings.sort((x, y) => (SEV_ORDER[x.severity] ?? 5) - (SEV_ORDER[y.severity] ?? 5));
    for (const f of findings) {
      total++;
      counts[f.severity && counts[f.severity] !== undefined ? f.severity : 'none']++;
      if (f.images.length) withImages++;
    }
    blocks.push({ asset: a, findings });
  }

  const now = new Date();
  const findingCard = (f) => {
    const sev = f.severity || '';
    const imgs = f.images.map(im => {
      const b64 = Buffer.from(im.data).toString('base64');
      return `<figure class="shot">
        <img src="data:${esc(im.mime)};base64,${b64}" alt="${esc(im.filename)}">
        <figcaption>${esc(im.filename)}</figcaption>
      </figure>`;
    }).join('');
    return `<article class="finding sev-${esc(sev || 'none')}">
      <div class="fhead">
        <span class="chip sev">${esc(sev || 'no severity')}</span>
        <span class="chip kind">${esc(f.kind || 'note')}</span>
        <h3>${esc(f.title)}</h3>
      </div>
      ${f.body ? `<pre>${esc(f.body)}</pre>` : ''}
      ${imgs ? `<div class="shots">${imgs}</div>` : ''}
    </article>`;
  };

  const sevTiles = ['critical', 'high', 'medium', 'low', 'info']
    .map(s => `<div class="tile"><div class="n" style="color:${SEV_COLOR[s]}">${counts[s]}</div><div class="k">${s}</div></div>`).join('');

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(p.name)} — findings</title>
<style>
  :root{--bg:#0b0d13;--panel:#0e111a;--line:#1e2230;--fg:#eef1f8;--muted:#98a1b6;--gold:#e8b65a;--mono:ui-monospace,"JetBrains Mono",Menlo,monospace}
  *{box-sizing:border-box}
  html,body{margin:0;background:var(--bg);color:var(--fg);font-family:system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.55}
  .wrap{max-width:900px;margin:0 auto;padding:40px 24px 80px}
  header{border-bottom:1px solid var(--line);padding-bottom:20px;margin-bottom:8px}
  .kick{font-family:var(--mono);font-size:11px;letter-spacing:.22em;text-transform:uppercase;color:var(--muted)}
  h1{font-size:28px;margin:8px 0 4px}
  .meta{color:var(--muted);font-size:14px}
  .tiles{display:flex;gap:1px;background:var(--line);border:1px solid var(--line);margin:22px 0}
  .tile{flex:1;background:var(--panel);padding:12px 14px;text-align:center}
  .tile .n{font-size:24px;font-weight:700;font-family:var(--mono)}
  .tile .k{font-family:var(--mono);font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:var(--muted);margin-top:3px}
  h2.asset{font-family:var(--mono);font-size:13px;letter-spacing:.06em;color:var(--gold);margin:36px 0 4px;padding-top:14px;border-top:1px solid var(--line)}
  .finding{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--muted);border-radius:4px;padding:16px 18px;margin:14px 0}
  .finding.sev-critical{border-left-color:${SEV_COLOR.critical}}
  .finding.sev-high{border-left-color:${SEV_COLOR.high}}
  .finding.sev-medium{border-left-color:${SEV_COLOR.medium}}
  .finding.sev-low{border-left-color:${SEV_COLOR.low}}
  .finding.sev-info,.finding.sev-none{border-left-color:${SEV_COLOR.info}}
  .fhead{display:flex;align-items:baseline;gap:8px;flex-wrap:wrap}
  .fhead h3{margin:0;font-size:17px;flex-basis:100%;order:3}
  .chip{font-family:var(--mono);font-size:10px;letter-spacing:.12em;text-transform:uppercase;padding:2px 8px;border-radius:3px;border:1px solid var(--line);color:var(--muted)}
  .chip.sev{color:#fff}
  .sev-critical .chip.sev{background:${SEV_COLOR.critical}}
  .sev-high .chip.sev{background:${SEV_COLOR.high};color:#1a1408}
  .sev-medium .chip.sev{background:${SEV_COLOR.medium};color:#1a1408}
  .sev-low .chip.sev{background:${SEV_COLOR.low}}
  .sev-info .chip.sev,.sev-none .chip.sev{background:${SEV_COLOR.info}}
  pre{background:#06070b;border:1px solid var(--line);border-radius:3px;padding:12px;overflow:auto;font-family:var(--mono);font-size:12.5px;line-height:1.6;color:#a8c8ff;white-space:pre-wrap;word-break:break-word;margin:12px 0 0}
  .shots{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px;margin-top:14px}
  figure.shot{margin:0;border:1px solid var(--line);border-radius:4px;overflow:hidden;background:#06070b}
  figure.shot img{display:block;width:100%;height:auto;cursor:zoom-in}
  figure.shot figcaption{font-family:var(--mono);font-size:10.5px;color:var(--muted);padding:6px 8px;border-top:1px solid var(--line);word-break:break-all}
  .empty{color:var(--muted);padding:40px 0}
  footer{margin-top:50px;color:var(--muted);font-family:var(--mono);font-size:11px;border-top:1px solid var(--line);padding-top:16px}
  @media print{body{background:#fff;color:#111}.finding,.tile,figure.shot{break-inside:avoid}}
</style></head>
<body><div class="wrap">
  <header>
    <div class="kick">Findings report</div>
    <h1>${esc(p.name)}</h1>
    <div class="meta">${[p.client && 'Client: ' + esc(p.client), p.scope && 'Scope: ' + esc(p.scope)].filter(Boolean).join(' &nbsp;·&nbsp; ') || '&nbsp;'}</div>
  </header>
  <div class="tiles"><div class="tile"><div class="n">${total}</div><div class="k">findings</div></div>${sevTiles}<div class="tile"><div class="n">${withImages}</div><div class="k">with images</div></div></div>
  ${blocks.length ? blocks.map(bl => `
    <h2 class="asset">${esc(bl.asset.type.toUpperCase())} — ${esc(bl.asset.label)}</h2>
    ${bl.findings.map(findingCard).join('')}
  `).join('') : `<p class="empty">No findings recorded yet.</p>`}
  <footer>Generated by Magi · ${now.toISOString().replace('T', ' ').slice(0, 16)} UTC · for authorized security testing only</footer>
</div>
<script>
  // click a screenshot to open it full-size in a new tab
  document.querySelectorAll('figure.shot img').forEach(function(img){
    img.addEventListener('click', function(){ var w=window.open(); if(w) w.document.write('<img src="'+img.src+'" style="max-width:100%">'); });
  });
</script>
</body></html>`;
}
