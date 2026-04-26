/**
 * ML-KEM-768 (formerly Kyber-768) — NIST FIPS 203
 *
 * Post-quantum Key Encapsulation Mechanism.
 * Security level: ~equivalent to AES-192.
 *
 * Parameters (k=3, ML-KEM-768):
 *   k    = 3    (module rank)
 *   eta1 = 2    (noise parameter for key gen)
 *   eta2 = 2    (noise parameter for encapsulation)
 *   du   = 10   (ciphertext compression bits for u)
 *   dv   = 4    (ciphertext compression bits for v)
 *
 * Zero external dependencies — uses only node:crypto.
 */
import nodeCrypto from 'node:crypto';
import { polyNew, polyAdd, polySub, polyNtt, polyInvNtt, polyBaseMul, polyCompress, polyDecompress, polyToBytes, polyFromBytes, polyCBD2, polyUniform, } from './poly.js';
import { N } from './ntt.js';
// ── Parameters ────────────────────────────────────────────────────────────────
const K = 3;
const ETA1 = 2;
const ETA2 = 2;
const DU = 10;
const DV = 4;
export const EK_SIZE = K * 384 + 32;
export const DK_SIZE = K * 384 + EK_SIZE + 64;
export const CT_SIZE = K * Math.ceil(N * DU / 8) + Math.ceil(N * DV / 8);
export const SS_SIZE = 32;
// ── Hash helpers ──────────────────────────────────────────────────────────────
function sha3_256(data) {
    return new Uint8Array(nodeCrypto.createHash('sha3-256').update(data).digest());
}
function sha3_512(data) {
    return new Uint8Array(nodeCrypto.createHash('sha3-512').update(data).digest());
}
// XOF using SHA3-256 in counter mode
function xof(data, outLen) {
    const out = new Uint8Array(outLen);
    let pos = 0;
    let counter = 0;
    while (pos < outLen) {
        const block = new Uint8Array(nodeCrypto.createHash('sha3-256')
            .update(Buffer.from([counter & 0xff, (counter >> 8) & 0xff]))
            .update(data)
            .digest());
        const take = Math.min(32, outLen - pos);
        out.set(block.subarray(0, take), pos);
        pos += take;
        counter++;
    }
    return out;
}
function prf(seed, nonce, outLen) {
    const input = new Uint8Array(seed.length + 1);
    input.set(seed);
    input[seed.length] = nonce;
    return xof(input, outLen);
}
// ── PolyVec helpers ───────────────────────────────────────────────────────────
function pvecNew() {
    return Array.from({ length: K }, () => polyNew());
}
function pvecNtt(v) {
    for (const p of v)
        polyNtt(p);
}
function pvecAdd(r, a, b) {
    for (let i = 0; i < K; i++)
        polyAdd(r[i], a[i], b[i]);
}
function pvecDot(a, b) {
    const r = polyNew();
    const tmp = polyNew();
    for (let i = 0; i < K; i++) {
        polyBaseMul(tmp, a[i], b[i]);
        polyAdd(r, r, tmp);
    }
    polyInvNtt(r);
    return r;
}
// ── Serialization ─────────────────────────────────────────────────────────────
function pvecToBytes(v) {
    const r = new Uint8Array(K * 384);
    for (let i = 0; i < K; i++)
        r.set(polyToBytes(v[i]), i * 384);
    return r;
}
function pvecFromBytes(b) {
    const v = pvecNew();
    for (let i = 0; i < K; i++)
        v[i] = polyFromBytes(b.subarray(i * 384, (i + 1) * 384));
    return v;
}
function pvecCompress(v, d) {
    const chunkSize = Math.ceil(N * d / 8);
    const r = new Uint8Array(K * chunkSize);
    for (let i = 0; i < K; i++)
        r.set(polyCompress(v[i], d), i * chunkSize);
    return r;
}
function pvecDecompress(b, d) {
    const chunkSize = Math.ceil(N * d / 8);
    const v = pvecNew();
    for (let i = 0; i < K; i++) {
        v[i] = polyDecompress(b.subarray(i * chunkSize, (i + 1) * chunkSize), d);
    }
    return v;
}
// ── Matrix A ──────────────────────────────────────────────────────────────────
function generateA(rho, transpose = false) {
    const A = Array.from({ length: K }, () => pvecNew());
    for (let i = 0; i < K; i++) {
        for (let j = 0; j < K; j++) {
            A[i][j] = transpose
                ? polyUniform(rho, j, i)
                : polyUniform(rho, i, j);
        }
    }
    return A;
}
// ── Core encrypt (used by both encaps and decaps re-check) ────────────────────
function kyberEnc(ek, m, // 32-byte message/seed
r) {
    // t is stored in NTT domain in ek — read directly, no NTT needed
    const t = pvecFromBytes(ek.subarray(0, K * 384));
    const rho = ek.subarray(K * 384, K * 384 + 32);
    // Generate A^T
    const AT = generateA(rho, true);
    // Sample r_vec, e1, e2 from r seed
    let nonce = 0;
    const r_vec = pvecNew();
    for (let i = 0; i < K; i++) {
        r_vec[i] = polyCBD2(prf(r, nonce++, 64 * ETA1));
    }
    const e1 = pvecNew();
    for (let i = 0; i < K; i++) {
        e1[i] = polyCBD2(prf(r, nonce++, 64 * ETA2));
    }
    const e2 = polyCBD2(prf(r, nonce++, 64 * ETA2));
    // NTT(r_vec)
    pvecNtt(r_vec);
    // u = NTT^{-1}(A^T * r_vec) + e1
    const u = pvecNew();
    const tmp = polyNew();
    for (let i = 0; i < K; i++) {
        for (let j = 0; j < K; j++) {
            polyBaseMul(tmp, AT[i][j], r_vec[j]);
            polyAdd(u[i], u[i], tmp);
        }
        polyInvNtt(u[i]);
        polyAdd(u[i], u[i], e1[i]);
    }
    // v = NTT^{-1}(t^T * r_vec) + e2 + Decompress(m, 1)
    const v = pvecDot(t, r_vec);
    polyAdd(v, v, e2);
    const m_poly = polyDecompress(m, 1);
    polyAdd(v, v, m_poly);
    // Compress
    const uChunk = K * Math.ceil(N * DU / 8);
    const vChunk = Math.ceil(N * DV / 8);
    const ct = new Uint8Array(uChunk + vChunk);
    ct.set(pvecCompress(u, DU), 0);
    ct.set(polyCompress(v, DV), uChunk);
    return ct;
}
// ── ML-KEM Key Generation ─────────────────────────────────────────────────────
export function mlkemKeyGen() {
    const d = new Uint8Array(nodeCrypto.randomBytes(32));
    const z = new Uint8Array(nodeCrypto.randomBytes(32));
    const G = sha3_512(d);
    const rho = G.subarray(0, 32);
    const sigma = G.subarray(32, 64);
    const A = generateA(rho);
    let nonce = 0;
    const s = pvecNew();
    for (let i = 0; i < K; i++)
        s[i] = polyCBD2(prf(sigma, nonce++, 64 * ETA1));
    const e = pvecNew();
    for (let i = 0; i < K; i++)
        e[i] = polyCBD2(prf(sigma, nonce++, 64 * ETA1));
    // Save s in normal domain for dk BEFORE NTT
    const s_normal = pvecNew();
    for (let i = 0; i < K; i++)
        s_normal[i].set(s[i]);
    pvecNtt(s);
    pvecNtt(e);
    // t = A*s + e  (all NTT domain)
    const t = pvecNew();
    const tmp = polyNew();
    for (let i = 0; i < K; i++) {
        for (let j = 0; j < K; j++) {
            polyBaseMul(tmp, A[i][j], s[j]);
            polyAdd(t[i], t[i], tmp);
        }
        polyAdd(t[i], t[i], e[i]);
    }
    // ek = ByteEncode12(t) ‖ rho  (t is in NTT domain)
    const ek = new Uint8Array(EK_SIZE);
    ek.set(pvecToBytes(t), 0);
    ek.set(rho, K * 384);
    // dk = ByteEncode12(s_hat) ‖ ek ‖ H(ek) ‖ z
    // Store s in NTT domain (s_hat) so decaps can do dot product directly
    const dk = new Uint8Array(DK_SIZE);
    dk.set(pvecToBytes(s), 0); // s is already NTT domain here
    dk.set(ek, K * 384);
    dk.set(sha3_256(ek), K * 384 + EK_SIZE);
    dk.set(z, K * 384 + EK_SIZE + 32);
    return { ek, dk };
}
// ── ML-KEM Encapsulation ──────────────────────────────────────────────────────
export function mlkemEncaps(ek) {
    if (ek.length !== EK_SIZE)
        throw new Error(`Invalid ek size: ${ek.length}`);
    const m = new Uint8Array(nodeCrypto.randomBytes(32));
    // (K, r) = G(m ‖ H(ek))
    const hek = sha3_256(ek);
    const G_in = new Uint8Array(64);
    G_in.set(m, 0);
    G_in.set(hek, 32);
    const G_out = sha3_512(G_in);
    const ss = G_out.subarray(0, 32);
    const r = G_out.subarray(32, 64);
    const ct = kyberEnc(ek, m, r);
    return {
        ciphertext: ct,
        sharedSecret: new Uint8Array(ss),
    };
}
// ── ML-KEM Decapsulation ──────────────────────────────────────────────────────
export function mlkemDecaps(ct, dk) {
    if (ct.length !== CT_SIZE)
        throw new Error(`Invalid ct size: ${ct.length}, expected ${CT_SIZE}`);
    if (dk.length !== DK_SIZE)
        throw new Error(`Invalid dk size: ${dk.length}`);
    // Parse dk
    const s_enc = dk.subarray(0, K * 384);
    const ek = dk.subarray(K * 384, K * 384 + EK_SIZE);
    const h = dk.subarray(K * 384 + EK_SIZE, K * 384 + EK_SIZE + 32);
    const z = dk.subarray(K * 384 + EK_SIZE + 32, K * 384 + EK_SIZE + 64);
    // Decode s — already in NTT domain (stored that way in dk)
    const s = pvecFromBytes(s_enc);
    // s is already NTT domain — do NOT apply NTT again
    // Decode u, v from ciphertext
    const uChunk = K * Math.ceil(N * DU / 8);
    const u = pvecDecompress(ct.subarray(0, uChunk), DU);
    const v = polyDecompress(ct.subarray(uChunk), DV);
    // NTT(u) so we can do NTT-domain dot product with s
    pvecNtt(u);
    // m' = Compress(v - NTT^{-1}(s^T * u), 1)
    const su = pvecDot(s, u);
    const diff = polyNew();
    polySub(diff, v, su);
    const m_prime = polyCompress(diff, 1);
    // (K', r') = G(m' ‖ h)
    const G_in = new Uint8Array(64);
    G_in.set(m_prime, 0);
    G_in.set(h, 32);
    const G_out = sha3_512(G_in);
    const ss_prime = G_out.subarray(0, 32);
    const r_prime = G_out.subarray(32, 64);
    // Re-encrypt and compare
    const ct_prime = kyberEnc(ek, m_prime, r_prime);
    const valid = constantTimeEqual(ct, ct_prime);
    // Implicit rejection: if invalid, return PRF(z, ct)
    const ss_reject = sha3_256(Buffer.concat([z, ct]));
    const result = new Uint8Array(SS_SIZE);
    for (let i = 0; i < SS_SIZE; i++) {
        result[i] = valid ? ss_prime[i] : ss_reject[i];
    }
    return result;
}
function constantTimeEqual(a, b) {
    if (a.length !== b.length)
        return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++)
        diff |= a[i] ^ b[i];
    return diff === 0;
}
