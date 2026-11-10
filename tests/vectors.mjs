// An independent sealing of aril's v1 frames with Node's crypto and zlib:
// nothing here is RustCrypto or flate2.
import crypto from 'node:crypto';
import zlib from 'node:zlib';
const hkdf = (ikm, info, n = 32) => Buffer.from(crypto.hkdfSync('sha256', ikm, Buffer.alloc(0), info, n));
const padme = (len) => {
  if (len < 2) return len;
  const e = Math.floor(Math.log2(len));
  const s = Math.floor(Math.log2(e)) + 1;
  const mask = (1 << (e - s)) - 1;
  return (len + mask) & ~mask;
};
const root = Buffer.alloc(32, 2);
const dek = hkdf(root, 'diaryx-ep-v1/dek');
const blind = hkdf(root, 'diaryx-ep-v1/blind');
const name = crypto.createHmac('sha256', blind).update('b4rk9d').digest().subarray(0, 16).toString('hex');
const plaintext = Buffer.from('sealed by node, opened by aril\n'.repeat(12));
const gz = zlib.gzipSync(plaintext);
const unpadded = 4 + gz.length;
const body = Buffer.alloc(padme(unpadded));
body.writeUInt32LE(gz.length, 0);
gz.copy(body, 4);
const nonce = Buffer.alloc(12, 7);
const c = crypto.createCipheriv('aes-256-gcm', dek, nonce);
c.setAAD(Buffer.concat([Buffer.from('diaryx-ep-v1/obj'), Buffer.from(name)]));
const frame = Buffer.concat([Buffer.from('DEP1'), nonce, c.update(body), c.final(), c.getAuthTag()]);
console.log('name', name);
console.log('frame', frame.toString('hex'));
// A wrap: the DEK under a link gate's KEK, bound to "family".
const kek = hkdf(Buffer.alloc(32, 1), 'diaryx-ep-v1/gate-kek');
const wn = Buffer.alloc(12, 9);
const w = crypto.createCipheriv('aes-256-gcm', kek, wn);
w.setAAD(Buffer.from('diaryx-ep-v1/wrapfamily'));
const wrap = Buffer.concat([wn, w.update(dek), w.final(), w.getAuthTag()]);
console.log('wrap', wrap.toString('hex'));
console.log('dekfp', crypto.createHash('sha256').update(Buffer.concat([Buffer.from('diaryx-ep-v1/dek-id'), Buffer.from([0]), dek])).digest().subarray(0,16).toString('hex'));
