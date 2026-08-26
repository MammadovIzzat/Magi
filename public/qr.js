// Minimal QR Code generator — a compact port of Nayuki's public-domain QR-code-generator
// (https://www.nayuki.io/page/qr-code-generator-library). Byte mode, all four ECC levels,
// versions 1–40, automatic version + mask selection. Returns a square boolean matrix
// (true = dark module). Used to render the two-factor otpauth:// setup code so an operator can
// scan it into their authenticator instead of typing the key.
//
// Verified by an encode→decode round trip in scripts/qr-smoke.mjs.

const ECC_CODEWORDS_PER_BLOCK = [
  [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30], // L
  [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28], // M
  [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30], // Q
  [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30], // H
];
const NUM_ERROR_CORRECTION_BLOCKS = [
  [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25], // L
  [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49], // M
  [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68], // Q
  [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81], // H
];

const getBit = (x, i) => ((x >>> i) & 1) !== 0;

// --- Galois field GF(2^8) arithmetic for Reed-Solomon ---
function reedSolomonMultiply(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11D);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xFF;
}
function reedSolomonComputeDivisor(degree) {
  const result = new Uint8Array(degree);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < result.length; j++) {
      result[j] = reedSolomonMultiply(result[j], root);
      if (j + 1 < result.length) result[j] ^= result[j + 1];
    }
    root = reedSolomonMultiply(root, 0x02);
  }
  return result;
}
function reedSolomonComputeRemainder(data, divisor) {
  const result = new Uint8Array(divisor.length);
  for (const b of data) {
    const factor = b ^ result[0];
    result.copyWithin(0, 1);
    result[result.length - 1] = 0;
    for (let i = 0; i < result.length; i++) result[i] ^= reedSolomonMultiply(divisor[i], factor);
  }
  return result;
}

function numRawDataModules(ver) {
  let result = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const numAlign = Math.floor(ver / 7) + 2;
    result -= (25 * numAlign - 10) * numAlign - 55;
    if (ver >= 7) result -= 36;
  }
  return result;
}
function numDataCodewords(ver, ecl) {
  return Math.floor(numRawDataModules(ver) / 8)
    - ECC_CODEWORDS_PER_BLOCK[ecl][ver] * NUM_ERROR_CORRECTION_BLOCKS[ecl][ver];
}

// Encode a byte array as one QR code. eclLevel: 0=L 1=M 2=Q 3=H. Returns { size, modules }.
function qrEncodeBytes(bytes, eclLevel = 1) {
  let ecl = eclLevel;
  // Byte-mode segment bit length: 4 (mode) + charCountBits + 8*len
  const dataLen = bytes.length;
  let version = 0, dataCapacityBits = 0;
  for (let v = 1; v <= 40; v++) {
    const ccbits = v < 10 ? 8 : 16; // byte mode char-count bits
    const usableBits = numDataCodewords(v, ecl) * 8;
    const need = 4 + ccbits + 8 * dataLen;
    if (need <= usableBits) { version = v; dataCapacityBits = usableBits; break; }
  }
  if (version === 0) throw new Error('data too long for a QR code');

  // Build the bit stream
  const bits = [];
  const appendBits = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
  appendBits(0x4, 4);                                   // byte mode
  appendBits(dataLen, version < 10 ? 8 : 16);           // char count
  for (const b of bytes) appendBits(b, 8);
  appendBits(0, Math.min(4, dataCapacityBits - bits.length)); // terminator
  while (bits.length % 8 !== 0) bits.push(0);           // byte-align
  for (let pad = 0xEC; bits.length < dataCapacityBits; pad ^= 0xEC ^ 0x11) appendBits(pad, 8);

  // Pack into data codewords
  const dataCodewords = new Uint8Array(bits.length / 8);
  bits.forEach((bit, i) => { if (bit) dataCodewords[i >>> 3] |= 0x80 >>> (i & 7); });

  return drawQr(version, ecl, dataCodewords);
}

function addEccAndInterleave(version, ecl, data) {
  const numBlocks = NUM_ERROR_CORRECTION_BLOCKS[ecl][version];
  const blockEccLen = ECC_CODEWORDS_PER_BLOCK[ecl][version];
  const rawCodewords = Math.floor(numRawDataModules(version) / 8);
  const numShortBlocks = numBlocks - rawCodewords % numBlocks;
  const shortBlockLen = Math.floor(rawCodewords / numBlocks);

  const blocks = [];
  const rsDiv = reedSolomonComputeDivisor(blockEccLen);
  let k = 0;
  for (let i = 0; i < numBlocks; i++) {
    const datLen = shortBlockLen - blockEccLen + (i < numShortBlocks ? 0 : 1);
    const dat = Array.from(data.slice(k, k + datLen));
    k += datLen;
    const ecc = reedSolomonComputeRemainder(dat, rsDiv);
    if (i < numShortBlocks) dat.push(0);
    blocks.push(dat.concat(Array.from(ecc)));
  }
  // Interleave
  const result = new Uint8Array(rawCodewords);
  let idx = 0;
  for (let i = 0; i < blocks[0].length; i++) {
    for (let j = 0; j < blocks.length; j++) {
      if (i !== shortBlockLen - blockEccLen || j >= numShortBlocks) result[idx++] = blocks[j][i];
    }
  }
  return result;
}

function drawQr(version, ecl, dataCodewords) {
  const size = version * 4 + 17;
  const modules = Array.from({ length: size }, () => new Array(size).fill(false));
  const isFunction = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (x, y, dark) => { modules[y][x] = dark; isFunction[y][x] = true; };

  // Timing patterns
  for (let i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
  // Finder patterns (3 corners)
  const finder = (cx, cy) => {
    for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
      const dist = Math.max(Math.abs(dx), Math.abs(dy));
      const x = cx + dx, y = cy + dy;
      if (x >= 0 && x < size && y >= 0 && y < size) set(x, y, dist !== 2 && dist !== 4);
    }
  };
  finder(3, 3); finder(size - 4, 3); finder(3, size - 4);
  // Alignment patterns
  const alignPos = alignmentPatternPositions(version);
  const n = alignPos.length;
  for (let i = 0; i < n; i++) for (let j = 0; j < n; j++) {
    if ((i === 0 && j === 0) || (i === 0 && j === n - 1) || (i === n - 1 && j === 0)) continue;
    const cx = alignPos[i], cy = alignPos[j];
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++)
      set(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }
  // Reserve format (and version) areas as function modules so data skips them
  drawFormatBits(modules, isFunction, ecl, 0, size, true);
  if (version >= 7) drawVersion(modules, isFunction, version, size);

  // Place data+ecc codewords in the zigzag pattern
  const allCodewords = addEccAndInterleave(version, ecl, dataCodewords);
  let i = 0; // bit index
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let k = 0; k < 2; k++) {
        const x = right - k;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - vert : vert;
        if (!isFunction[y][x] && i < allCodewords.length * 8) {
          modules[y][x] = getBit(allCodewords[i >>> 3], 7 - (i & 7));
          i++;
        }
      }
    }
  }

  // Try all 8 masks, keep the lowest-penalty one
  let bestMask = 0, minPenalty = Infinity, best = null;
  for (let mask = 0; mask < 8; mask++) {
    const m = modules.map(r => r.slice());
    applyMask(m, isFunction, mask);
    drawFormatBits(m, isFunction, ecl, mask, size, false);
    const p = penalty(m, size);
    if (p < minPenalty) { minPenalty = p; bestMask = mask; best = m; }
  }
  return { size, modules: best };
}

function alignmentPatternPositions(ver) {
  if (ver === 1) return [];
  const numAlign = Math.floor(ver / 7) + 2;
  const step = Math.floor((ver * 4 + 17 - 13) / (numAlign * 2 - 2)) * 2;
  const result = [6];
  for (let pos = ver * 4 + 17 - 7; result.length < numAlign; pos -= step) result.splice(1, 0, pos);
  return result;
}

function drawFormatBits(modules, isFunction, ecl, mask, size, reserveOnly) {
  const eccFmt = [1, 0, 3, 2][ecl]; // L,M,Q,H -> 01,00,11,10
  const data = (eccFmt << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const bits = ((data << 10) | rem) ^ 0x5412;
  const place = (x, y, dark) => { modules[y][x] = dark; if (isFunction) isFunction[y][x] = true; };
  const val = (i) => reserveOnly ? false : getBit(bits, i);
  // first copy
  for (let i = 0; i <= 5; i++) place(8, i, val(i));
  place(8, 7, val(6)); place(8, 8, val(7)); place(7, 8, val(8));
  for (let i = 9; i < 15; i++) place(14 - i, 8, val(i));
  // second copy
  for (let i = 0; i < 8; i++) place(size - 1 - i, 8, val(i));
  for (let i = 8; i < 15; i++) place(8, size - 15 + i, val(i));
  place(8, size - 8, true); // always-dark module
  if (isFunction) isFunction[size - 8][8] = true;
}

function drawVersion(modules, isFunction, version, size) {
  let rem = version;
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1F25);
  const bits = (version << 12) | rem;
  for (let i = 0; i < 18; i++) {
    const dark = getBit(bits, i);
    const a = size - 11 + (i % 3), b = Math.floor(i / 3);
    modules[b][a] = dark; isFunction[b][a] = true;
    modules[a][b] = dark; isFunction[a][b] = true;
  }
}

function applyMask(modules, isFunction, mask) {
  const size = modules.length;
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
    if (isFunction[y][x]) continue;
    let invert;
    switch (mask) {
      case 0: invert = (x + y) % 2 === 0; break;
      case 1: invert = y % 2 === 0; break;
      case 2: invert = x % 3 === 0; break;
      case 3: invert = (x + y) % 3 === 0; break;
      case 4: invert = (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0; break;
      case 5: invert = (x * y) % 2 + (x * y) % 3 === 0; break;
      case 6: invert = ((x * y) % 2 + (x * y) % 3) % 2 === 0; break;
      case 7: invert = ((x + y) % 2 + (x * y) % 3) % 2 === 0; break;
    }
    if (invert) modules[y][x] = !modules[y][x];
  }
}

// Penalty score (spec section 8.3) — used only to pick the least-ugly mask.
function penalty(m, size) {
  let p = 0;
  const dark = m;
  // Rules 1 & 3 along rows and columns
  for (let y = 0; y < size; y++) {
    let run = 0, color = false;
    for (let x = 0; x < size; x++) {
      if (dark[y][x] === color) { run++; if (run === 5) p += 3; else if (run > 5) p++; }
      else { color = dark[y][x]; run = 1; }
    }
  }
  for (let x = 0; x < size; x++) {
    let run = 0, color = false;
    for (let y = 0; y < size; y++) {
      if (dark[y][x] === color) { run++; if (run === 5) p += 3; else if (run > 5) p++; }
      else { color = dark[y][x]; run = 1; }
    }
  }
  // Rule 2: 2x2 blocks
  for (let y = 0; y < size - 1; y++) for (let x = 0; x < size - 1; x++)
    if (dark[y][x] === dark[y][x + 1] && dark[y][x] === dark[y + 1][x] && dark[y][x] === dark[y + 1][x + 1]) p += 3;
  // Rule 4: proportion of dark modules
  let count = 0;
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (dark[y][x]) count++;
  const k = Math.floor((Math.abs(count * 20 - size * size * 10) + size * size - 1) / (size * size));
  p += k * 10;
  return p;
}

/** Convenience: encode a UTF-8 string to a QR matrix. */
function qrMatrix(text, ecl = 1) {
  return qrEncodeBytes(new TextEncoder().encode(text), ecl);
}

// Classic script (browser + node-eval) — expose on the global. No ES import/export so the same
// file loads via <script src="/qr.js"> and evaluates in the qr-smoke test.
globalThis.qrMatrix = qrMatrix;
globalThis.qrEncodeBytes = qrEncodeBytes;
