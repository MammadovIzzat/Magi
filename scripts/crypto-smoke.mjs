// At-rest encryption smoke: a configured key encrypts the database file on disk, data
// round-trips, the wrong key is refused, and an existing plaintext DB migrates in place.
//
//   node scripts/crypto-smoke.mjs
import { execFileSync } from 'node:child_process';
import { readFileSync, rmSync, mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
let failures = 0;
const check = (name, cond) => { console.log(`  ${cond ? 'ok  ' : 'FAIL'}  ${name}`); if (!cond) failures++; };

// Run a snippet that imports the real db.js with the given env; returns {status, out, err}.
function withDb(env, code) {
  try {
    const out = execFileSync(process.execPath, ['--input-type=module', '-e',
      `import('${join(ROOT, 'db.js').replace(/\\/g, '/')}').then(m => { ${code} }).catch(e => { console.error('ERR:' + e.message); process.exit(3); })`],
      { env: { ...process.env, ...env }, cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    return { status: 0, out: String(out) };
  } catch (e) {
    return { status: e.status ?? 1, out: String(e.stdout || ''), err: String(e.stderr || '') };
  }
}
const MARKER = 'ENC_MARKER_SECRET_9f3a';
const dataDir = mkdtempSync(join(tmpdir(), 'magi-crypto-'));
const dbFile = join(dataDir, 'magi.db');
const fileHas = (s) => existsSync(dbFile) && readFileSync(dbFile).includes(Buffer.from(s));
const isPlain = () => existsSync(dbFile) && readFileSync(dbFile).subarray(0, 16).toString('latin1').startsWith('SQLite format 3');

try {
  // ── encrypted create + on-disk ciphertext ─────────────────────────────────
  const KEY = "pentest-secret'quote";
  const w = withDb({ MAGI_DATA_DIR: dataDir, MAGI_DB_KEY: KEY, MAGI_MFA: 'off' },
    `m.db.prepare("INSERT INTO projects (name) VALUES ('${MARKER}')").run(); console.log('W_OK');`);
  check('a keyed database accepts writes', w.status === 0 && w.out.includes('W_OK'));
  check('the database file is NOT a plaintext SQLite file', !isPlain());
  check('the marker does not appear in the file as plaintext', !fileHas(MARKER));

  // ── round-trip with the right key ─────────────────────────────────────────
  const r = withDb({ MAGI_DATA_DIR: dataDir, MAGI_DB_KEY: KEY, MAGI_MFA: 'off' },
    `const row = m.db.prepare("SELECT name FROM projects WHERE name='${MARKER}'").get(); console.log(row ? 'FOUND' : 'MISSING');`);
  check('the right key reads the data back', r.status === 0 && r.out.includes('FOUND'));

  // ── wrong key is refused ──────────────────────────────────────────────────
  const bad = withDb({ MAGI_DATA_DIR: dataDir, MAGI_DB_KEY: 'the-wrong-key', MAGI_MFA: 'off' },
    `console.log('SHOULD_NOT_REACH');`);
  check('a wrong key is refused (no data leaks)', bad.status !== 0 && !bad.out.includes('SHOULD_NOT_REACH'));

  // ── plaintext → encrypted migration in place ──────────────────────────────
  rmSync(dataDir, { recursive: true, force: true });
  const MIG = 'MIG_MARKER_PLAINTEXT_7b2c';
  const p = withDb({ MAGI_DATA_DIR: dataDir, MAGI_MFA: 'off' }, // no key => plaintext
    `m.db.prepare("INSERT INTO projects (name) VALUES ('${MIG}')").run(); console.log('P_OK');`);
  check('an unkeyed database is created plaintext', p.status === 0 && isPlain() && fileHas(MIG));

  const mig = withDb({ MAGI_DATA_DIR: dataDir, MAGI_DB_KEY: KEY, MAGI_MFA: 'off' },
    `const row = m.db.prepare("SELECT name FROM projects WHERE name='${MIG}'").get(); console.log(row ? 'KEPT' : 'LOST');`);
  check('opening a plaintext DB with a key migrates it and keeps the data', mig.status === 0 && mig.out.includes('KEPT'));
  check('after migration the file is encrypted (no SQLite header)', !isPlain());
  check('after migration the old plaintext marker is gone from the file', !fileHas(MIG));
} finally {
  rmSync(dataDir, { recursive: true, force: true });
}

if (failures) { console.error(`crypto-smoke: ${failures} check(s) failed`); process.exit(1); }
console.log('crypto-smoke: all checks passed');
