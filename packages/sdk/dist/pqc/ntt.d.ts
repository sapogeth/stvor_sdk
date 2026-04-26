/**
 * Number Theoretic Transform for ML-KEM (Kyber)
 *
 * Ring: Z_q[x]/(x^256 + 1), q = 3329
 * Straightforward implementation following the ML-KEM spec exactly.
 */
export declare const N = 256;
export declare const Q = 3329;
export declare const ZETAS: number[];
export declare function modQ(a: number): number;
export declare function reduce(a: number): number;
export declare function ntt(f: Int16Array): void;
export declare function invNtt(f: Int16Array): void;
export declare function baseMul(r: Int16Array, a: Int16Array, b: Int16Array): void;
export declare function fqmul(a: number, b: number): number;
export declare function montgomeryReduce(a: number): number;
export declare function barrettReduce(a: number): number;
