/**
 * Double Ratchet для браузера — Web Crypto API only.
 *
 * Алгоритмы:
 *   Key agreement : ECDH P-256
 *   Signing       : ECDSA P-256 SHA-256
 *   KDF           : HKDF-SHA-256
 *   AEAD          : AES-256-GCM
 *
 * Семантика совпадает с Node.js ядром (ratchet/index.ts):
 *   - X3DH symmetric variant — обе стороны дают одинаковый SK
 *   - Deferred DH ratchet    — первый send/receive инициирует ratchet-шаг
 *   - Skipped keys           — поддержка out-of-order сообщений
 */
export interface WebKeyPair {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
    publicRaw: ArrayBuffer;
}
export interface WebSessionState {
    myIdentityPublicRaw: ArrayBuffer;
    peerIdentityPublicRaw: ArrayBuffer;
    rootKey: ArrayBuffer;
    sendingChainKey: ArrayBuffer;
    receivingChainKey: ArrayBuffer;
    myRatchetPair: WebKeyPair;
    theirRatchetPublicRaw: ArrayBuffer | null;
    sendCount: number;
    recvCount: number;
    prevSendCount: number;
    skippedKeys: Map<string, ArrayBuffer>;
    peerSPKRaw: ArrayBuffer | null;
    mySPKPair: WebKeyPair | null;
}
export interface WebSerializedPublicKeys {
    identityKey: string;
    signedPreKey: string;
    signedPreKeySignature: string;
    oneTimePreKey: string;
}
export declare function webEstablishSession(myIK: WebKeyPair, mySPK: WebKeyPair, peerIKRaw: ArrayBuffer, peerSPKRaw: ArrayBuffer): Promise<WebSessionState>;
export declare function webEncrypt(session: WebSessionState, plaintext: ArrayBuffer): Promise<{
    ciphertext: string;
    header: string;
}>;
export declare function webDecrypt(session: WebSessionState, ciphertextB64: string, headerB64: string): Promise<ArrayBuffer>;
export interface WebIdentityKeys {
    /** ECDSA key pair — used for signing and published as identityKey to relay */
    ikEcdsaPair: {
        publicKey: CryptoKey;
        privateKey: CryptoKey;
        publicRaw: ArrayBuffer;
    };
    /** ECDH key pair — used for X3DH key agreement */
    ikEcdhPair: WebKeyPair;
    /** ECDH key pair — signed pre-key for key agreement */
    spkPair: WebKeyPair;
    /** ECDSA signature of spkPair.publicRaw using ikEcdsaPair.privateKey */
    spkSig: ArrayBuffer;
    /**
     * @deprecated Use ikEcdsaPair.publicRaw as published identity key.
     * Kept for backwards compatibility with web-sdk.ts callers.
     */
    ikPair: WebKeyPair;
}
export declare function generateWebIdentityKeys(): Promise<WebIdentityKeys>;
export declare function verifyWebSPK(spkRaw: ArrayBuffer, sigRaw: ArrayBuffer, ikEcdsaPublicRaw: ArrayBuffer): Promise<boolean>;
export interface WebSessionSerialized {
    myIKPub: string;
    peerIKPub: string;
    rk: string;
    sck: string;
    rck: string;
    mrPub: string;
    mrPriv: string;
    trpk: string | null;
    sc: number;
    rc: number;
    psc: number;
    skipped: Record<string, string>;
    peerSPK: string | null;
    mySPKPub: string | null;
    mySPKPriv: string | null;
}
export declare function serializeWebSession(s: WebSessionState): Promise<WebSessionSerialized>;
export declare function deserializeWebSession(d: WebSessionSerialized): Promise<WebSessionState>;
