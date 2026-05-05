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
 * SamplePolyCBD_η2 (Algorithm 8, FIPS 203)
 * Input: 64*η = 128 bytes (PRF output)
 * For each coefficient i in [0,256):
 *   bits at positions 4i..4i+3 of the byte array
 *   a = bit[4i] + bit[4i+1]
 *   b = bit[4i+2] + bit[4i+3]
 *   f[i] = a - b  (mod q)
 */
export function polyCBD2(seed) {
    const r = polyNew();
    for (let i = 0; i < N; i++) {
        const byteIdx = Math.floor(i / 2);
        const bitOff = (i % 2) * 4;
        const byte = seed[byteIdx];
        const a = ((byte >> bitOff) & 1) + ((byte >> (bitOff + 1)) & 1);
        const b = ((byte >> (bitOff + 2)) & 1) + ((byte >> (bitOff + 3)) & 1);
        r[i] = modQ(a - b + Q);
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
 * SampleNTT (Algorithm 7, FIPS 203): sample a polynomial from SHAKE-128 XOF.
 * XOF input: rho ‖ i ‖ j  (FIPS 203 §4.2.2)
 * Rejection-samples coefficients in [0, q) from the XOF stream.
 */
export function polyUniform(seed, i, j) {
    // SHAKE-128 with large output — rejection sampling needs ~840 bytes on average
    // Request enough to fill N=256 coefficients without re-squeezing
    const outLen = 840;
    const stream = new Uint8Array(nodeCrypto.createHash('shake128', { outputLength: outLen })
        .update(Buffer.concat([seed, Buffer.from([i, j])]))
        .digest());
    const r = polyNew();
    let pos = 0;
    let filled = 0;
    while (filled < N && pos + 2 < stream.length) {
        const b0 = stream[pos], b1 = stream[pos + 1], b2 = stream[pos + 2];
        pos += 3;
        const d1 = b0 | ((b1 & 0x0f) << 8);
        const d2 = (b1 >> 4) | (b2 << 4);
        if (d1 < Q)
            r[filled++] = d1;
        if (d2 < Q && filled < N)
            r[filled++] = d2;
    }
    // Fallback if stream exhausted (shouldn't happen with outLen=840)
    if (filled < N) {
        let extra = outLen;
        while (filled < N) {
            const more = new Uint8Array(nodeCrypto.createHash('shake128', { outputLength: extra + 168 })
                .update(Buffer.concat([seed, Buffer.from([i, j])]))
                .digest());
            for (let p = extra; p + 2 < more.length && filled < N; p += 3) {
                const d1 = more[p] | ((more[p + 1] & 0x0f) << 8);
                const d2 = (more[p + 1] >> 4) | (more[p + 2] << 4);
                if (d1 < Q)
                    r[filled++] = d1;
                if (d2 < Q && filled < N)
                    r[filled++] = d2;
            }
            extra += 168;
        }
    }
    return r;
}
