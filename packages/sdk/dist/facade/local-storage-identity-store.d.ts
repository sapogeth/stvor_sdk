/**
 * LocalStorage-based Identity Store for browser environments
 * Implements IIdentityStore for persistent identity key storage
 */
import { IIdentityStore } from './crypto-session.js';
/**
 * Browser-based identity storage using localStorage
 * CRITICAL: Keys are stored in base64url — in production, use encrypted storage
 */
export declare class LocalStorageIdentityStore implements IIdentityStore {
    private storageKey;
    constructor(userId: string, storageKeyPrefix?: string);
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
    /** Delete stored keys (for logout / account reset) */
    deleteIdentityKeys(userId: string): Promise<void>;
}
/**
 * Session storage implementation for browser environments
 */
export declare class LocalStorageSessionStore {
    private storageKey;
    constructor(userId: string, storageKeyPrefix?: string);
    saveSession(userId: string, peerId: string, _session: unknown): Promise<void>;
    loadSession(userId: string, peerId: string): Promise<unknown | null>;
    deleteSession(userId: string, peerId: string): Promise<void>;
    listSessions(userId: string): Promise<string[]>;
    private getAllSessions;
}
export default LocalStorageIdentityStore;
