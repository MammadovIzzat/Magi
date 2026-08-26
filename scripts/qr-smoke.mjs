// QR generator test. Two layers:
//   1) a golden-hash regression guard (portable, always runs), and
//   2) a real round trip through an actual scanner (zbarimg) when the host has the tools —
//      the strongest proof the codes are genuinely scannable, not just self-consistent.
//
//   node scripts/qr-smoke.mjs
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// public/qr.js is a classic script that assigns globalThis.qrMatrix — eval it here.
(0, eval)(readFileSync(new URL('../public/qr.js', import.meta.url), 'utf8'));
const qrMatrix = globalThis.qrMatrix;

const checks = [];
const check = (n, ok) => { checks.push([n, !!ok]); if (!ok) console.error('   ^ FAILED: ' + n); };

// 1) Golden hash: the matrix for a fixed otpauth URI must not drift (a real scanner verified
//    this exact output once; the hash guards against a regression in the encoder).
const TEST = 'otpauth://totp/Magi:operator?secret=EWBSUTRZ3CCDRDLSCRWRB6STIJZMNSJV&issuer=Magi&algorithm=SHA1&digits=6&period=30';
const GOLDEN = '3861614de7b0546a749bd31691eaec7c3cc3362788366c3af3892db374540862';
const m = qrMatrix(TEST);
const ser = m.size + ':' + m.modules.map(r => r.map(b => b ? 1 : 0).join('')).join('');
check('QR output matches the golden hash', createHash('sha256').update(ser).digest('hex') === GOLDEN);

// structural sanity: three finder patterns present
const finder = (cx, cy) => m.modules[cy][cx] && m.modules[cy][cx + 6] && m.modules[cy + 6][cx] && !m.modules[cy + 1][cx + 1];
check('finder patterns are in three corners', finder(0, 0) && finder(m.size - 7, 0) && finder(0, m.size - 7));

// data-too-long is rejected, not silently truncated
let rejected = false; try { qrMatrix('x'.repeat(5000)); } catch { rejected = true; }
check('over-capacity input is rejected', rejected);

// 2) Real scanner round trip (best-effort — skipped cleanly if the tools are absent)
function have(cmd) { try { execFileSync('sh', ['-c', `command -v ${cmd}`], { stdio: 'ignore' }); return true; } catch { return false; } }
const toPng = have('magick') ? (i, o) => execFileSync('magick', [i, o]) : have('convert') ? (i, o) => execFileSync('convert', [i, o]) : null;
if (have('zbarimg') && toPng) {
  const dir = mkdtempSync(join(tmpdir(), 'magi-qr-'));
  try {
    for (const [i, text] of [TEST, 'HELLO 42', 'otpauth://totp/Magi:x@corp.example?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Magi&period=30'].entries()) {
      const qr = qrMatrix(text), scale = 8, quiet = 4, dim = (qr.size + quiet * 2) * scale;
      let pbm = `P1\n${dim} ${dim}\n`;
      for (let y = 0; y < dim; y++) {
        let row = '';
        for (let x = 0; x < dim; x++) {
          const mx = Math.floor(x / scale) - quiet, my = Math.floor(y / scale) - quiet;
          row += (mx >= 0 && mx < qr.size && my >= 0 && my < qr.size && qr.modules[my][mx]) ? '1 ' : '0 ';
        }
        pbm += row + '\n';
      }
      writeFileSync(join(dir, 'q.pbm'), pbm);
      toPng(join(dir, 'q.pbm'), join(dir, 'q.png'));
      const out = execFileSync('zbarimg', ['--quiet', '--raw', join(dir, 'q.png')], { encoding: 'utf8' }).replace(/\n$/, '');
      check(`a real scanner reads QR #${i} back exactly`, out === text);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
} else {
  console.log('  (zbarimg / imagemagick not installed — skipping the live scanner round trip)');
}

const failed = checks.filter(([, ok]) => !ok);
console.log(`\nqr-smoke: ${checks.length - failed.length}/${checks.length} checks passed`);
if (failed.length) { console.error('FAILED:', failed.map(([n]) => n).join(', ')); process.exit(1); }
console.log('  ✓ QR codes are stable and scannable');
