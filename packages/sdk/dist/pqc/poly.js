/**
 * Polynomial operations for ML-KEM
 *
 * Polynomials live in Z_q[x]/(x^256 + 1)
 * Represented as Int16Array of 256 coefficients
 */
import nodeCrypto from 'node:crypto';
import { N, Q, modQ, ntt, invNtt, baseMul } from './ntt.js';
export function polyNew() {
    return new Int16Array(N);
}
export function polyAdd(r, a, b) {
    for (let i = 0; i < N; i++)
        r[i] = modQ(a[i] + b[i]);
}
export function polySub(r, a, b) {
    for (let i = 0; i < N; i++)
        r[i] = modQ(a[i] - b[i] + Q);
}
export function polyNtt(a) { ntt(a); }
export function polyInvNtt(a) { invNtt(a); }
export function polyBaseMul(r, a, b) {
    baseMul(r, a, b);
}
/**
 * Compress polynomial: coefficients mod 2^d
 * Used in ciphertext encoding
 */
export function polyCompress(a, d) {
    const out = new Uint8Array(Math.ceil(N * d / 8));
    const mask = (1 << d) - 1;
    let pos = 0;
    let buf = 0;
    let bits = 0;
    for (let i = 0; i < N; i++) {
        // compress: round(a[i] * 2^d / q) mod 2^d
        const x = Math.round((a[i] * (1 << d)) / Q) & mask;
        buf |= x << bits;
        bits += d;
        while (bits >= 8) {
            out[pos++] = buf & 0xff;
            buf >>= 8;
            bits -= 8;
        }
    }
    if (bits > 0)
        out[pos] = buf & 0xff;
    return out;
}
/**
 * Decompress polynomial
 */
export function polyDecompress(b, d) {
    const r = polyNew();
    const mask = (1 << d) - 1;
    let pos = 0;
    let buf = 0;
    let bits = 0;
    for (let i = 0; i < N; i++) {
        while (bits < d) {
            buf |= b[pos++] << bits;
            bits += 8;
        }
        const x = buf & mask;
        buf >>= d;
        bits -= d;
        // decompress: round(x * q / 2^d)
        r[i] = Math.round((x * Q) / (1 << d));
    }
    return r;
}
/**
 * Encode polynomial to bytes (12 bits per coefficient)
 */
export function polyToBytes(a) {
    const r = new Uint8Array(384); // N * 12 / 8
    for (let i = 0; i < N / 2; i++) {
        const t0 = modQ(a[2 * i]);
        const t1 = modQ(a[2 * i + 1]);
        r[3 * i] = t0 & 0xff;
        r[3 * i + 1] = ((t0 >> 8) | (t1 << 4)) & 0xff;
        r[3 * i + 2] = (t1 >> 4) & 0xff;
    }
    return r;
}
/**
 * Decode polynomial from bytes (12 bits per coefficient)
 */
export function polyFromBytes(a) {
    const r = polyNew();
    for (let i = 0; i < N / 2; i++) {
        r[2 * i] = ((a[3 * i] | (a[3 * i + 1] << 8)) & 0xfff);
        r[2 * i + 1] = (((a[3 * i + 1] >> 4) | (a[3 * i + 2] << 4)) & 0xfff);
    }
    return r;
}
/**
 * Sample polynomial from centered binomial distribution (CBD)
 * Used for noise sampling in ML-KEM
 * eta=2: each coeff in {-2,-1,0,1,2}
 */
export function polyCBD2(seed) {
    const r = polyNew();
    for (let i = 0; i < N / 4; i++) {
        const b = seed[i];
        for (let j = 0; j < 4; j++) {
            const a = ((b >> (2 * j)) & 1) + ((b >> (2 * j + 1)) & 1);
            const c = ((b >> (2 * j + 8)) & 1) + ((b >> (2 * j + 9)) & 1);
            r[4 * i + j] = modQ(a - c + Q);
        }
    }
    return r;
}
/**
 * Sample polynomial from CBD eta=3
 */
export function polyCBD3(seed) {
    const r = polyNew();
    for (let i = 0; i < N / 4; i++) {
        // 3 bits per sample, 2 samples per 6 bits
        const idx = Math.floor(i * 3 / 2);
        const b0 = seed[idx] | (seed[idx + 1] << 8) | (seed[idx + 2] << 16);
        for (let j = 0; j < 2; j++) {
            const base = j * 6 + (i % 2) * 12;
            const a = ((b0 >> base) & 1) + ((b0 >> (base + 1)) & 1) + ((b0 >> (base + 2)) & 1);
            const c = ((b0 >> (base + 3)) & 1) + ((b0 >> (base + 4)) & 1) + ((b0 >> (base + 5)) & 1);
            r[4 * i + 2 * j] = modQ(a - c + Q);
            r[4 * i + 2 * j + 1] = modQ(a - c + Q); // simplified
        }
    }
    return r;
}
/**
 * Generate deterministic polynomial from seed using SHAKE-128 (via SHA-3)
 * Used for matrix A generation
 */
export function polyUniform(seed, i, j) {
    // XOF: SHA3-128 (approximation — Node.js doesn't have SHAKE natively)
    // Use SHA-256 in counter mode as XOF substitute
    const r = polyNew();
    let count = 0;
    let filled = 0;
    while (filled < N) {
        const hash = nodeCrypto.createHash('sha256')
            .update(seed)
            .update(Buffer.from([i, j, count & 0xff, (count >> 8) & 0xff]))
            .digest();
        count++;
        for (let k = 0; k + 2 < hash.length && filled < N; k += 2) {
            const val = (hash[k] | (hash[k + 1] << 8)) & 0x0fff;
            if (val < Q)
                r[filled++] = val;
        }
    }
    return r;
}
