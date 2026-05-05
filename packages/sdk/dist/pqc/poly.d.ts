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
 * SamplePolyCBD_η2 (Algorithm 8, FIPS 203)
 * Input: 64*η = 128 bytes (PRF output)
 * For each coefficient i in [0,256):
 *   bits at positions 4i..4i+3 of the byte array
 *   a = bit[4i] + bit[4i+1]
 *   b = bit[4i+2] + bit[4i+3]
 *   f[i] = a - b  (mod q)
 */
export declare function polyCBD2(seed: Uint8Array): Poly;
/**
 * Sample polynomial from CBD eta=3
 */
export declare function polyCBD3(seed: Uint8Array): Poly;
/**
 * SampleNTT (Algorithm 7, FIPS 203): sample a polynomial from SHAKE-128 XOF.
 * XOF input: rho ‖ i ‖ j  (FIPS 203 §4.2.2)
 * Rejection-samples coefficients in [0, q) from the XOF stream.
 */
export declare function polyUniform(seed: Uint8Array, i: number, j: number): Poly;
