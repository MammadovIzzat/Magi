// CVSS v3.1 calculator — Base, Temporal and Environmental groups, per the FIRST.org specification.
// A single classic script (no import/export) that assigns globalThis.MagiCVSS, so the SAME file is
// used by the browser (a <script> tag) and by the Node server (a side-effect `import`), keeping the
// scoring identical on both sides. The server re-derives + is authoritative on save.
//
// Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H[/E:F/RL:O/RC:C/CR:H/…/MAV:N/…]. Temporal and
// Environmental metrics left "Not Defined" (X) are omitted from the string. `score()` returns the
// applicable overall score (Environmental if any env metric is set, else Temporal if any temporal
// metric is set, else Base) and `severityOf()` maps it to Magi's bands (None → 'info').
(function () {
  const AVW = { N: .85, A: .62, L: .55, P: .2 }, ACW = { L: .77, H: .44 }, UIW = { N: .85, R: .62 };
  const CIAW = { N: 0, L: .22, H: .56 };
  const PRW = { U: { N: .85, L: .62, H: .27 }, C: { N: .85, L: .68, H: .5 } };
  const EW = { X: 1, H: 1, F: .97, P: .94, U: .91 };
  const RLW = { X: 1, U: 1, W: .97, T: .96, O: .95 };
  const RCW = { X: 1, C: 1, R: .96, U: .92 };
  const REQW = { X: 1, H: 1.5, M: 1, L: .5 };

  // Metric groups. `col` places each metric in the editor's left/right column so the layout matches
  // the CVSS spec's grouping (Base: AV/AC/PR/UI left, Scope/C/I/A right). Vector-string order is
  // ORDER below, independent of this presentation.
  const GROUPS = [
    { title: 'Base Score', metrics: [
      { k: 'AV', col: 'l', label: 'Attack Vector', opts: [['N', 'Network'], ['A', 'Adjacent'], ['L', 'Local'], ['P', 'Physical']] },
      { k: 'AC', col: 'l', label: 'Attack Complexity', opts: [['L', 'Low'], ['H', 'High']] },
      { k: 'PR', col: 'l', label: 'Privileges Required', opts: [['N', 'None'], ['L', 'Low'], ['H', 'High']] },
      { k: 'UI', col: 'l', label: 'User Interaction', opts: [['N', 'None'], ['R', 'Required']] },
      { k: 'S', col: 'r', label: 'Scope', opts: [['U', 'Unchanged'], ['C', 'Changed']] },
      { k: 'C', col: 'r', label: 'Confidentiality', opts: [['N', 'None'], ['L', 'Low'], ['H', 'High']] },
      { k: 'I', col: 'r', label: 'Integrity', opts: [['N', 'None'], ['L', 'Low'], ['H', 'High']] },
      { k: 'A', col: 'r', label: 'Availability', opts: [['N', 'None'], ['L', 'Low'], ['H', 'High']] },
    ] },
    { title: 'Temporal Score', metrics: [
      { k: 'E', col: 'l', label: 'Exploit Code Maturity', opts: [['X', 'Not Defined'], ['U', 'Unproven'], ['P', 'Proof-of-Concept'], ['F', 'Functional'], ['H', 'High']] },
      { k: 'RL', col: 'l', label: 'Remediation Level', opts: [['X', 'Not Defined'], ['O', 'Official Fix'], ['T', 'Temporary Fix'], ['W', 'Workaround'], ['U', 'Unavailable']] },
      { k: 'RC', col: 'l', label: 'Report Confidence', opts: [['X', 'Not Defined'], ['U', 'Unknown'], ['R', 'Reasonable'], ['C', 'Confirmed']] },
    ] },
    { title: 'Environmental Score', metrics: [
      { k: 'CR', col: 'l', label: 'Confidentiality Requirement', opts: [['X', 'Not Defined'], ['L', 'Low'], ['M', 'Medium'], ['H', 'High']] },
      { k: 'IR', col: 'l', label: 'Integrity Requirement', opts: [['X', 'Not Defined'], ['L', 'Low'], ['M', 'Medium'], ['H', 'High']] },
      { k: 'AR', col: 'l', label: 'Availability Requirement', opts: [['X', 'Not Defined'], ['L', 'Low'], ['M', 'Medium'], ['H', 'High']] },
      { k: 'MAV', col: 'r', label: 'Modified Attack Vector', opts: [['X', 'Not Defined'], ['N', 'Network'], ['A', 'Adjacent Network'], ['L', 'Local'], ['P', 'Physical']] },
      { k: 'MAC', col: 'r', label: 'Modified Attack Complexity', opts: [['X', 'Not Defined'], ['L', 'Low'], ['H', 'High']] },
      { k: 'MPR', col: 'r', label: 'Modified Privileges Required', opts: [['X', 'Not Defined'], ['N', 'None'], ['L', 'Low'], ['H', 'High']] },
      { k: 'MUI', col: 'r', label: 'Modified User Interaction', opts: [['X', 'Not Defined'], ['N', 'None'], ['R', 'Required']] },
      { k: 'MS', col: 'r', label: 'Modified Scope', opts: [['X', 'Not Defined'], ['U', 'Unchanged'], ['C', 'Changed']] },
      { k: 'MC', col: 'r', label: 'Modified Confidentiality', opts: [['X', 'Not Defined'], ['N', 'None'], ['L', 'Low'], ['H', 'High']] },
      { k: 'MI', col: 'r', label: 'Modified Integrity', opts: [['X', 'Not Defined'], ['N', 'None'], ['L', 'Low'], ['H', 'High']] },
      { k: 'MA', col: 'r', label: 'Modified Availability', opts: [['X', 'Not Defined'], ['N', 'None'], ['L', 'Low'], ['H', 'High']] },
    ] },
  ];
  const BASE_KEYS = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
  const TEMP_KEYS = ['E', 'RL', 'RC'];
  const ENV_KEYS = ['CR', 'IR', 'AR', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA'];
  const ORDER = [...BASE_KEYS, ...TEMP_KEYS, ...ENV_KEYS];

  const parse = (v) => { const o = {}; if (typeof v === 'string') for (const p of v.split('/')) { const i = p.indexOf(':'); if (i > 0) o[p.slice(0, i)] = p.slice(i + 1); } return o; };
  // Build the canonical string: base metrics always, temporal/env only when set (≠ X).
  const buildVector = (m) => 'CVSS:3.1/' + ORDER.filter(k => (BASE_KEYS.includes(k) ? m[k] : (m[k] && m[k] !== 'X'))).map(k => k + ':' + m[k]).join('/');
  // CVSS 3.1 Roundup — smallest 1-dp number ≥ input, float-safe.
  const roundup = (x) => { const i = Math.round(x * 100000); return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10; };
  const eff = (mod, base) => (mod && mod !== 'X' ? mod : base);
  const severityOf = (s) => (s == null || Number.isNaN(s) ? null : s <= 0 ? 'info' : s < 4 ? 'low' : s < 7 ? 'medium' : s < 9 ? 'high' : 'critical');

  function scoreDetail(vector) {
    const m = parse(vector);
    const AV = AVW[m.AV], AC = ACW[m.AC], UI = UIW[m.UI], PR = PRW[m.S]?.[m.PR], C = CIAW[m.C], I = CIAW[m.I], A = CIAW[m.A];
    if ((m.S !== 'U' && m.S !== 'C') || [AV, AC, UI, PR, C, I, A].some(x => x === undefined))
      return { base: null, temporal: null, environmental: null, overall: null, severity: null };
    const iss = 1 - (1 - C) * (1 - I) * (1 - A);
    const impact = m.S === 'U' ? 6.42 * iss : 7.52 * (iss - .029) - 3.25 * Math.pow(iss - .02, 15);
    const expl = 8.22 * AV * AC * PR * UI;
    const base = impact <= 0 ? 0 : roundup(Math.min((m.S === 'C' ? 1.08 : 1) * (impact + expl), 10));

    const E = EW[m.E || 'X'], RL = RLW[m.RL || 'X'], RC = RCW[m.RC || 'X'];
    const temporal = roundup(base * E * RL * RC);

    const eScope = eff(m.MS, m.S);
    const mav = AVW[eff(m.MAV, m.AV)], mac = ACW[eff(m.MAC, m.AC)], mui = UIW[eff(m.MUI, m.UI)], mpr = PRW[eScope]?.[eff(m.MPR, m.PR)];
    const CR = REQW[m.CR || 'X'], IR = REQW[m.IR || 'X'], AR = REQW[m.AR || 'X'];
    const mc = CIAW[eff(m.MC, m.C)], mi = CIAW[eff(m.MI, m.I)], ma = CIAW[eff(m.MA, m.A)];
    const miss = Math.min(1 - (1 - CR * mc) * (1 - IR * mi) * (1 - AR * ma), 0.915);
    const mimpact = eScope === 'U' ? 6.42 * miss : 7.52 * (miss - .029) - 3.25 * Math.pow(miss * 0.9731 - .02, 13);
    const mexpl = 8.22 * mav * mac * mpr * mui;
    const environmental = mimpact <= 0 ? 0 : roundup(roundup(Math.min((eScope === 'C' ? 1.08 : 1) * (mimpact + mexpl), 10)) * E * RL * RC);

    const hasEnv = ENV_KEYS.some(k => m[k] && m[k] !== 'X');
    const hasTemp = TEMP_KEYS.some(k => m[k] && m[k] !== 'X');
    const overall = hasEnv ? environmental : hasTemp ? temporal : base;
    return { base, temporal, environmental, overall, severity: severityOf(overall) };
  }
  const score = (v) => scoreDetail(v).overall;
  const isValidVector = (v) => { const m = parse(v); return BASE_KEYS.every(k => m[k] != null) && score(v) != null; };

  globalThis.MagiCVSS = { GROUPS, BASE_KEYS, ORDER, parse, buildVector, score, scoreDetail, severityOf, isValidVector };
})();
