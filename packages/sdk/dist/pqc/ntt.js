/**
 * Number Theoretic Transform for ML-KEM (FIPS 203)
 *
 * Ring: Z_q[x]/(x^256 + 1), q = 3329, primitive root ζ = 17
 *
 * Zeta table: ZETAS[k] = 17^brv7(k) mod 3329, k = 0..255
 * NTT uses ZETAS[1..127], baseMul uses ZETAS[128..255].
 */
export const N = 256;
export const Q = 3329;
// 7-bit bit-reversal
function brv7(x) {
    let r = 0;
    for (let i = 0; i < 7; i++) {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    return r;
}
// ZETAS[k] = 17^brv7(k) mod 3329, k = 0..127
// Used by NTT (forward: k=1..127) and invNTT (reverse: k=127..1)
export const ZETAS = (() => {
    const powers = new Array(128);
    let p = 1n;
    for (let i = 0; i < 128; i++) {
        powers[i] = Number(p);
        p = p * 17n % 3329n;
    }
    return Array.from({ length: 128 }, (_, k) => powers[brv7(k)]);
})();
// GAMMAS[i] = ζ^(2·brv₇(i)+1) mod 3329, i = 0..127
// Used by baseMul: pair i of the NTT-domain product uses GAMMAS[i] as the root.
// FIPS 203 §4.3, Algorithm 11.
export const GAMMAS = (() => {
    const pow = (b, e, m) => {
        let r = 1n;
        b = b % m;
        while (e > 0n) {
            if (e & 1n)
                r = r * b % m;
            b = b * b % m;
            e >>= 1n;
        }
        return Number(r);
    };
    return Array.from({ length: 128 }, (_, i) => pow(17n, BigInt(2 * brv7(i) + 1), 3329n));
})();
// ── Modular arithmetic ────────────────────────────────────────────────────────
export function modQ(a) {
    a = a % Q;
    return a < 0 ? a + Q : a;
}
export function reduce(a) { return modQ(a); }
// ── NTT (Algorithm 9, FIPS 203) ───────────────────────────────────────────────
// In-place forward NTT. Coefficients remain in Z_q.
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
// ── Inverse NTT (Algorithm 10, FIPS 203) ─────────────────────────────────────
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
    for (let i = 0; i < N; i++)
        f[i] = (f[i] * 3303) % Q;
}
// ── Base multiplication (Algorithm 11/12, FIPS 203) ──────────────────────────
// Multiplies two NTT-domain polynomials.
// The 128 degree-2 factors use ZETAS[128..255]:
//   pair i (indices 4i, 4i+1, 4i+2, 4i+3) uses ZETAS[128+i] and -ZETAS[128+i]
// baseMul: multiply two NTT-domain polynomials.
// Follows the Kyber/ML-KEM reference implementation exactly:
//   For i = 0..63:
//     Pair at (4i, 4i+1): basemul with zeta =  ZETAS[64+i]
//     Pair at (4i+2, 4i+3): basemul with zeta = -ZETAS[64+i]
// (Kyber ref: poly_basemul_montgomery in poly.c)
export function baseMul(r, a, b) {
    for (let i = 0; i < 64; i++) {
        const zeta = ZETAS[64 + i];
        const i0 = 4 * i, i1 = 4 * i + 1, i2 = 4 * i + 2, i3 = 4 * i + 3;
        // Pair 0: mod (X² − zeta)
        r[i0] = modQ((a[i0] * b[i0] + (a[i1] * b[i1] % Q) * zeta) % Q);
        r[i1] = modQ((a[i0] * b[i1] + a[i1] * b[i0]) % Q);
        // Pair 1: mod (X² + zeta)  [note: -zeta ≡ Q-zeta]
        r[i2] = modQ((a[i2] * b[i2] - (a[i3] * b[i3] % Q) * zeta % Q + 2 * Q) % Q);
        r[i3] = modQ((a[i2] * b[i3] + a[i3] * b[i2]) % Q);
    }
}
// Legacy aliases
export function fqmul(a, b) { return (a * b) % Q; }
export function montgomeryReduce(a) { return modQ(a); }
export function barrettReduce(a) { return modQ(a); }
