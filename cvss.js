// CVSS v3.1 BASE score — dependency-free, per the FIRST.org specification. We only compute the
// base metric group (the exploitability + impact of the vulnerability itself), which is what a
// pentest finding is graded on. Vector looks like:
//   CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
// score() returns a number 0.0–10.0 (or null if the vector is incomplete/invalid); severityOf()
// maps a score to Magi's severity bands (None→'info', matching how the app labels a 0.0).
const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  C: { H: 0.56, L: 0.22, N: 0 }, I: { H: 0.56, L: 0.22, N: 0 }, A: { H: 0.56, L: 0.22, N: 0 },
  // Privileges Required is scored differently when the Scope changes.
  PR: { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.5 } },
};
export const CVSS_METRICS = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];

export function parseVector(v) {
  if (typeof v !== 'string') return null;
  const out = {};
  for (const part of v.trim().split('/')) {
    const i = part.indexOf(':'); if (i < 1) continue;
    out[part.slice(0, i)] = part.slice(i + 1);
  }
  return out;
}

const roundup = (x) => Math.ceil(x * 10) / 10;

/** Base score for a vector string, or null if any base metric is missing/invalid. */
export function score(vector) {
  const m = parseVector(vector); if (!m) return null;
  const S = m.S; if (S !== 'U' && S !== 'C') return null;
  const av = W.AV[m.AV], ac = W.AC[m.AC], ui = W.UI[m.UI], pr = W.PR[S]?.[m.PR];
  const c = W.C[m.C], i = W.I[m.I], a = W.A[m.A];
  if ([av, ac, ui, pr, c, i, a].some((x) => x === undefined)) return null;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = S === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  if (impact <= 0) return 0;
  const expl = 8.22 * av * ac * pr * ui;
  const base = S === 'U' ? Math.min(impact + expl, 10) : Math.min(1.08 * (impact + expl), 10);
  return roundup(base);
}

/** Map a base score to a severity band. 'None' folds into 'info' (Magi's lowest band). */
export function severityOf(s) {
  if (s == null || Number.isNaN(s)) return null;
  if (s <= 0) return 'info';
  if (s < 4) return 'low';
  if (s < 7) return 'medium';
  if (s < 9) return 'high';
  return 'critical';
}

/** A complete, valid base vector? (All eight metrics present and recognised.) */
export function isValidVector(v) { return score(v) != null && CVSS_METRICS.every((k) => parseVector(v)?.[k] != null); }
