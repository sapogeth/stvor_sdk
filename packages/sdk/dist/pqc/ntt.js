/**
 * Number Theoretic Transform for ML-KEM (Kyber)
 *
 * Ring: Z_q[x]/(x^256 + 1), q = 3329
 * Straightforward implementation following the ML-KEM spec exactly.
 */
export const N = 256;
export const Q = 3329;
// ── Zeta table ────────────────────────────────────────────────────────────────
// zetas[i] = 17^brv7(i) mod 3329
// The primitive 512th root of unity is ζ = 17
export const ZETAS = (() => {
    function brv7(x) {
        let r = 0;
        for (let i = 0; i < 7; i++) {
            r = (r << 1) | (x & 1);
            x >>= 1;
        }
        return r;
    }
    const powers = new Array(128);
    let p = 1;
    for (let i = 0; i < 128; i++) {
        powers[i] = p;
        p = (p * 17) % Q;
    }
    return Array.from({ length: 128 }, (_, i) => powers[brv7(i)]);
})();
// ── Modular arithmetic ────────────────────────────────────────────────────────
export function modQ(a) {
    a = a % Q;
    return a < 0 ? a + Q : a;
}
// Optimised reduce into [0, Q)
export function reduce(a) {
    return modQ(a);
}
// ── NTT ───────────────────────────────────────────────────────────────────────
// Algorithm 9 from FIPS 203.
// Input/output coefficients in Z_q (integers mod q).
export function ntt(f) {
    let k = 1;
    for (let len = 128; len >= 2; len >>= 1) {
        for (let start = 0; start < N; start += 2 * len) {
            const zeta = ZETAS[k++];
            for (let j = start; j < start + len; j++) {
                const t = (zeta * f[j + len]) % Q;
                f[j + len] = modQ(f[j] - t);
                f[j] = modQ(f[j] + t);
            }
        }
    }
}
// ── Inverse NTT ───────────────────────────────────────────────────────────────
// Algorithm 10 from FIPS 203.
export function invNtt(f) {
    let k = 127;
    for (let len = 2; len <= 128; len <<= 1) {
        for (let start = 0; start < N; start += 2 * len) {
            const zeta = ZETAS[k--];
            for (let j = start; j < start + len; j++) {
                const t = f[j];
                f[j] = modQ(t + f[j + len]);
                f[j + len] = modQ((zeta * modQ(f[j + len] - t)) % Q);
            }
        }
    }
    // Multiply by 128^{-1} mod 3329 = 3303
    const INV128 = 3303;
    for (let i = 0; i < N; i++) {
        f[i] = (f[i] * INV128) % Q;
    }
}
// ── Base multiplication ───────────────────────────────────────────────────────
// Pointwise multiplication of two NTT-domain polys using degree-2 factors.
export function baseMul(r, a, b) {
    for (let i = 0; i < 64; i++) {
        const zeta = ZETAS[64 + i];
        const i0 = 4 * i, i1 = 4 * i + 1, i2 = 4 * i + 2, i3 = 4 * i + 3;
        // (a0 + a1*X)(b0 + b1*X) mod (X^2 - zeta)
        r[i0] = modQ((a[i0] * b[i0] + a[i1] * b[i1] * zeta) % Q);
        r[i1] = modQ((a[i0] * b[i1] + a[i1] * b[i0]) % Q);
        // (a2 + a3*X)(b2 + b3*X) mod (X^2 + zeta) [negated zeta for odd pair]
        r[i2] = modQ((a[i2] * b[i2] - a[i3] * b[i3] * zeta % Q + Q) % Q);
        r[i3] = modQ((a[i2] * b[i3] + a[i3] * b[i2]) % Q);
    }
}
// Legacy aliases used by poly.ts
export function fqmul(a, b) {
    return (a * b) % Q;
}
export function montgomeryReduce(a) {
    return modQ(a);
}
export function barrettReduce(a) {
    return modQ(a);
}
