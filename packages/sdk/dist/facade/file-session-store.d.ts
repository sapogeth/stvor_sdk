/**
 * File-Based Encrypted Session Storage
 *
 * Stores Double Ratchet session state securely in encrypted files.
 * Uses AES-256-GCM with master key derived from passphrase.
 */
import { ISessionStore } from './crypto-session.js';
export interface FileSessionStoreConfig {
    directory: string;
    masterPassword: string;
}
export declare class FileSessionStore implements ISessionStore {
    private directory;
    private masterKey;
    constructor(config: FileSessionStoreConfig);
    private getUserDir;
    private getSessionFile;
    private encrypt;
    private decrypt;
    saveSession(userId: string, peerId: string, sessionData: Buffer): Promise<void>;
    loadSession(userId: string, peerId: string): Promise<Buffer | null>;
    deleteSession(userId: string, peerId: string): Promise<void>;
    listSessions(userId: string): Promise<string[]>;
}
