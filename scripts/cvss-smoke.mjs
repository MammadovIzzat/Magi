// Validate the shared CVSS v3.1 calculator (public/cvss.js) against reference vectors — base,
// temporal and environmental — plus the vector round-trip and severity banding.
//
//   node scripts/cvss-smoke.mjs
import { readFileSync } from 'node:fs';

// public/cvss.js is a classic script that assigns globalThis.MagiCVSS — eval it here.
(0, eval)(readFileSync(new URL('../public/cvss.js', import.meta.url), 'utf8'));
const C = globalThis.MagiCVSS;

const checks = [];
const approx = (a, b) => a != null && Math.abs(a - b) < 0.001;
const check = (name, ok) => { checks.push([name, !!ok]); if (!ok) console.error('   ^ FAILED: ' + name); return !!ok; };

// Reference base scores (FIRST.org calculator).
const base = [
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8, 'critical'],
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0, 'critical'],
  ['CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N', 3.1, 'low'],
  ['CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 6.2, 'medium'],
  ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 8.8, 'high'],
  ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0.0, 'info'],
];
for (const [v, s, sev] of base) {
  const d = C.scoreDetail(v);
  check(`base ${s} — ${v.slice(9)}`, approx(d.base, s) && approx(d.overall, s) && d.severity === sev);
}

// Temporal: overall follows the temporal score once a temporal metric is set.
const t = C.scoreDetail('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C');
check('temporal reduces 9.8 -> 8.8 (E:P/RL:O/RC:C)', approx(t.base, 9.8) && approx(t.temporal, 8.8) && approx(t.overall, 8.8) && t.severity === 'high');

// Environmental: lower requirements drop the score; env becomes the overall.
const e = C.scoreDetail('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:L/IR:L/AR:L');
check('environmental (low reqs) lowers the overall score', e.environmental < e.base && approx(e.overall, e.environmental));
check('undefined temporal/env leaves overall == base', approx(C.scoreDetail(base[0][0]).overall, 9.8));

// Vector round-trip: base always present, X metrics omitted.
const m = C.parse('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
m.E = 'F'; m.RL = 'X';
const vec = C.buildVector(m);
check('buildVector keeps base + set temporal, drops X', vec.includes('/E:F') && !vec.includes('RL:X') && vec.startsWith('CVSS:3.1/AV:N'));
check('isValidVector needs all base metrics', C.isValidVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H') && !C.isValidVector('CVSS:3.1/AV:N/AC:L'));

let bad = 0;
for (const [name, ok] of checks) { console.log(`  ${ok ? 'ok  ' : 'FAIL'}  ${name}`); if (!ok) bad++; }
if (bad) { console.error(`\n  CVSS SMOKE FAILED — ${bad} check(s)\n`); process.exit(1); }
console.log('\n  cvss smoke ok\n');
