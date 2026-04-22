/**
 * X3DH + Double Ratchet Implementation
 * Uses ONLY Node.js built-in crypto module — zero external dependencies
 *
 * Implements the Signal Protocol Double Ratchet with deferred initialization:
 *   - First send  → "initiator" DH ratchet (DH with peer's SPK)
 *   - First receive → "responder" DH ratchet (use own SPK, then fresh key)
 * This allows either side to send first after symmetric X3DH key agreement.
 *
 * Provides:
 *   - X3DH key agreement (symmetric variant, both sides derive same SK)
 *   - Double Ratchet with DH ratchet + symmetric-key ratchet
 *   - AES-256-GCM AEAD encryption with header as AAD
 *   - ECDSA P-256 signing / verification
 *   - HKDF-SHA256 key derivation
 *   - HMAC-based chain-key ratchet (Signal-style)
 */
export interface KeyPair {
    publicKey: Buffer;
    privateKey: Buffer;
}
export interface SessionState {
    myIdentityPublicKey: Buffer;
    peerIdentityPublicKey: Buffer;
    rootKey: Buffer;
    sendingChainKey: Buffer;
    receivingChainKey: Buffer;
    myRatchetKeyPair: KeyPair;
    theirRatchetPublicKey: Buffer | null;
    sendCount: number;
    recvCount: number;
    prevSendCount: number;
    skippedKeys: Map<string, Buffer>;
    isPostCompromise: boolean;
    peerSPK: Buffer | null;
    mySPKPair: KeyPair | null;
    preInitRootKey: Buffer | null;
    sentBeforeRecv: boolean;
    peerSPKPublic: Buffer | null;
    identityKey: Uint8Array;
    signedPreKey: Uint8Array;
    oneTimePreKey: Uint8Array;
    sendingChainMessageNumber: number;
    receivingChainMessageNumber: number;
    previousSendingChainLength: number;
}
export declare function initializeCrypto(): Promise<void>;
export declare function generateKeyPair(): KeyPair;
/** ECDSA-P256-SHA256 sign */
export declare function ecSign(data: Buffer, kp: KeyPair): Buffer;
/** ECDSA-P256-SHA256 verify */
export declare function ecVerify(data: Buffer, sig: Buffer, pub: Buffer): boolean;
export declare function x3dhSymmetric(myIK: KeyPair, mySPK: KeyPair, peerIK: Buffer, peerSPK: Buffer, peerOPK?: Buffer): Buffer;
export declare function establishSession(myIK: KeyPair, mySPK: KeyPair, peerIK: Buffer, peerSPK: Buffer): SessionState;
export declare function encryptMessage(session: SessionState, plaintext: Buffer): {
    ciphertext: Buffer;
    header: Buffer;
};
export declare function decryptMessage(session: SessionState, ciphertext: Buffer, header: Buffer): Buffer;
export declare function forceRatchet(session: SessionState): void;
export declare function serializeSession(s: SessionState): Buffer;
export declare function deserializeSession(data: Buffer): SessionState;
