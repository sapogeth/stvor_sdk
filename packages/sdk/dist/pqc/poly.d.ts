/**
 * Polynomial operations for ML-KEM
 *
 * Polynomials live in Z_q[x]/(x^256 + 1)
 * Represented as Int16Array of 256 coefficients
 */
export type Poly = Int16Array;
export declare function polyNew(): Poly;
export declare function polyAdd(r: Poly, a: Poly, b: Poly): void;
export declare function polySub(r: Poly, a: Poly, b: Poly): void;
export declare function polyNtt(a: Poly): void;
export declare function polyInvNtt(a: Poly): void;
export declare function polyBaseMul(r: Poly, a: Poly, b: Poly): void;
/**
 * Compress polynomial: coefficients mod 2^d
 * Used in ciphertext encoding
 */
export declare function polyCompress(a: Poly, d: number): Uint8Array;
/**
 * Decompress polynomial
 */
export declare function polyDecompress(b: Uint8Array, d: number): Poly;
/**
 * Encode polynomial to bytes (12 bits per coefficient)
 */
export declare function polyToBytes(a: Poly): Uint8Array;
/**
 * Decode polynomial from bytes (12 bits per coefficient)
 */
export declare function polyFromBytes(a: Uint8Array): Poly;
/**
 * Sample polynomial from centered binomial distribution (CBD)
 * Used for noise sampling in ML-KEM
 * eta=2: each coeff in {-2,-1,0,1,2}
 */
export declare function polyCBD2(seed: Uint8Array): Poly;
/**
 * Sample polynomial from CBD eta=3
 */
export declare function polyCBD3(seed: Uint8Array): Poly;
/**
 * Generate deterministic polynomial from seed using SHAKE-128 (via SHA-3)
 * Used for matrix A generation
 */
export declare function polyUniform(seed: Uint8Array, i: number, j: number): Poly;
