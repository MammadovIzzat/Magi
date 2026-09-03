// JWT (HS256) unit smoke: round-trips, rejects tampering / wrong secret / expiry.
//   node scripts/jwt-smoke.mjs
import { randomBytes } from 'node:crypto';
import { sign, verify, decodeUnsafe } from '../jwt.js';

let failures = 0;
const check = (name, cond) => { console.log(`  ${cond ? 'ok  ' : 'FAIL'}  ${name}`); if (!cond) failures++; };

const secret = randomBytes(32).toString('hex');
const claims = { sub: 7, username: 'izzat', role: 'admin', device_id: 'dev-1', epoch: 3 };

const tok = sign(claims, secret, { ttlSeconds: 60 });
const v = verify(tok, secret);
check('a valid token round-trips its claims', v && v.sub === 7 && v.username === 'izzat' && v.role === 'admin' && v.epoch === 3);
check('the token carries iat/exp/jti', v && typeof v.iat === 'number' && typeof v.exp === 'number' && typeof v.jti === 'string');

check('a wrong secret is rejected', verify(tok, randomBytes(32).toString('hex')) === null);

// tamper: flip a byte in the payload segment
const parts = tok.split('.');
const tampered = parts[0] + '.' + parts[1].slice(0, -1) + (parts[1].slice(-1) === 'A' ? 'B' : 'A') + '.' + parts[2];
check('a tampered payload is rejected', verify(tampered, secret) === null);

// tamper: try to elevate role by re-encoding the payload but keeping the old signature
const forged = { ...claims, role: 'admin', epoch: 999 };
const forgedTok = parts[0] + '.' + Buffer.from(JSON.stringify(forged)).toString('base64url') + '.' + parts[2];
check('a re-encoded payload with the old signature is rejected', verify(forgedTok, secret) === null);

check('a malformed token is rejected', verify('not.a.jwt', secret) === null && verify('', secret) === null && verify('a.b', secret) === null);

const expired = sign(claims, secret, { ttlSeconds: -1 });
check('an expired token is rejected', verify(expired, secret) === null);

check('decodeUnsafe reads claims without verifying (display only)', decodeUnsafe(tok)?.username === 'izzat' && decodeUnsafe(forgedTok)?.epoch === 999);

if (failures) { console.error(`jwt-smoke: ${failures} check(s) failed`); process.exit(1); }
console.log('jwt-smoke: all checks passed');
