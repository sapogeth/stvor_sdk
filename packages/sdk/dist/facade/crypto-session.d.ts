/**
 * STVOR Crypto Session Manager
 * Uses ONLY Node.js built-in crypto module — zero external dependencies
 *
 * Manages identity keys (IK + SPK), ECDSA signatures,
 * X3DH session establishment, and Double Ratchet encrypt/decrypt.
 */
import { KeyPair } from '../ratchet/index.js';
export interface IdentityKeys {
    identityKeyPair: KeyPair;
    signedPreKeyPair: KeyPair;
    signedPreKeySignature: Buffer;
}
export interface SerializedPublicKeys {
    identityKey: string;
    signedPreKey: string;
    signedPreKeySignature: string;
    oneTimePreKey: string;
}
export interface IIdentityStore {
    saveIdentityKeys(userId: string, keys: {
        identityKeyPair: {
            publicKey: string;
            privateKey: string;
        };
        signedPreKeyPair: {
            publicKey: string;
            privateKey: string;
        };
        signedPreKeySignature: string;
    }): Promise<void>;
    loadIdentityKeys(userId: string): Promise<{
        identityKeyPair: {
            publicKey: string;
            privateKey: string;
        };
        signedPreKeyPair: {
            publicKey: string;
            privateKey: string;
        };
        signedPreKeySignature: string;
    } | null>;
}
export interface ISessionStore {
    saveSession(userId: string, peerId: string, sessionData: Buffer): Promise<void>;
    loadSession(userId: string, peerId: string): Promise<Buffer | null>;
    deleteSession(userId: string, peerId: string): Promise<void>;
    listSessions(userId: string): Promise<string[]>;
}
export declare class CryptoSessionManager {
    private userId;
    private identityKeys;
    private sessions;
    private initialized;
    private initPromise;
    private identityStore;
    private sessionStore;
    constructor(userId: string, identityStore?: IIdentityStore, sessionStore?: ISessionStore);
    initialize(): Promise<void>;
    private _doInit;
    getPublicKeys(): SerializedPublicKeys;
    establishSession(peerId: string, peerPublicKeys: SerializedPublicKeys): Promise<void>;
    establishSessionWithPeer(peerId: string, pk: SerializedPublicKeys): Promise<void>;
    hasSession(peerId: string): boolean;
    encryptForPeer(peerId: string, plaintext: string): {
        ciphertext: string;
        header: string;
    };
    decryptFromPeer(peerId: string, ciphertext: string, header: string): string;
    forceRatchet(peerId: string): Promise<void>;
}
