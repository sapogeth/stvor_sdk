/**
 * STVOR Crypto Session Manager
 * Integrates X3DH + Double Ratchet from ratchet module
 *
 * CRITICAL: Identity keys generated ONCE per userId
 * Currently in-memory only - keys lost on restart
 *
 * TODO: Add persistent storage (IndexedDB/Keychain)
 */
export interface IdentityKeys {
    identityKeyPair: {
        publicKey: Uint8Array;
        privateKey: Uint8Array;
    };
    signedPreKeyPair: {
        publicKey: Uint8Array;
        privateKey: Uint8Array;
    };
    oneTimePreKeys: Uint8Array[];
}
export interface SerializedPublicKeys {
    identityKey: string;
    signedPreKey: string;
    signedPreKeySignature: string;
    oneTimePreKey: string;
}
/**
 * Manages cryptographic sessions for all peers
 */
export declare class CryptoSessionManager {
    private userId;
    private identityKeys;
    private sessions;
    private initialized;
    private initPromise;
    constructor(userId: string);
    /**
     * Initialize libsodium and generate identity keys
     * RACE CONDITION SAFE: Returns same promise if called concurrently
     */
    initialize(): Promise<void>;
    private _doInitialize;
    /**
     * Get serialized public keys for relay registration
     */
    getPublicKeys(): SerializedPublicKeys;
    /**
     * Establish session with peer (X3DH handshake)
     */
    establishSessionWithPeer(peerId: string, peerPublicKeys: SerializedPublicKeys): Promise<void>;
    /**
     * Encrypt message for peer using Double Ratchet
     */
    encryptForPeer(peerId: string, plaintext: string): Promise<{
        ciphertext: Uint8Array;
        header: {
            publicKey: Uint8Array;
            nonce: Uint8Array;
        };
    }>;
    /**
     * Decrypt message from peer using Double Ratchet
     */
    decryptFromPeer(peerId: string, ciphertext: Uint8Array, header: {
        publicKey: Uint8Array;
        nonce: Uint8Array;
    }): Promise<string>;
    /**
     * Check if session exists with peer
     */
    hasSession(peerId: string): boolean;
    /**
     * Destroy all sessions (cleanup)
     */
    destroy(): void;
}
