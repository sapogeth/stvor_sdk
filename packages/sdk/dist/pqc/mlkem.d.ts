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
export declare const EK_SIZE: number;
export declare const DK_SIZE: number;
export declare const CT_SIZE: number;
export declare const SS_SIZE = 32;
export interface MLKEMKeyPair {
    ek: Uint8Array;
    dk: Uint8Array;
}
export interface MLKEMEncapsResult {
    ciphertext: Uint8Array;
    sharedSecret: Uint8Array;
}
export declare function shake128xof(seed: Uint8Array, i: number, j: number, outLen: number): Uint8Array;
export declare function mlkemKeyGenFrom(d: Uint8Array, z: Uint8Array): MLKEMKeyPair;
export declare function mlkemKeyGen(): MLKEMKeyPair;
export declare function mlkemEncapsFrom(ek: Uint8Array, m: Uint8Array): MLKEMEncapsResult;
export declare function mlkemEncaps(ek: Uint8Array): MLKEMEncapsResult;
export declare function mlkemDecaps(ct: Uint8Array, dk: Uint8Array): Uint8Array;
