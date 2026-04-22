/**
 * File-Based Encrypted Key Storage
 *
 * Stores identity keys securely in encrypted JSON files.
 * Uses AES-256-GCM with a master key derived from a passphrase.
 *
 * Perfect for Node.js servers and CLI applications.
 */
import { IIdentityStore } from './crypto-session.js';
export interface FileStorageConfig {
    directory: string;
    masterPassword: string;
}
export declare class FileIdentityStore implements IIdentityStore {
    private directory;
    private masterKey;
    constructor(config: FileStorageConfig);
    private getFilePath;
    private encrypt;
    private decrypt;
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
    deleteIdentityKeys(userId: string): Promise<void>;
    listUsers(): Promise<string[]>;
}
