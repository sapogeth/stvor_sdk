/**
 * One-Time Prekey Management
 *
 * Generates, rotates, and tracks one-time prekeys (OPK)
 * for Signal Protocol X3DH key exchange.
 *
 * OPKs provide forward secrecy - each key is used only once.
 */
import { KeyPair } from '../ratchet/index.js';
export interface OTPKeyStatus {
    keyId: number;
    publicKey: Buffer;
    createdAt: Date;
    usedAt?: Date;
    isUsed: boolean;
}
export interface OTPKeyBundle {
    keyId: number;
    publicKey: string;
    createdAt: string;
}
export declare class OTPKeyManager {
    private keyPairs;
    private nextKeyId;
    private maxUnusedKeys;
    private rotationInterval;
    constructor(maxUnusedKeys?: number, rotationIntervalMs?: number);
    /**
     * Initialize with random OPKs
     */
    private initializeKeys;
    /**
     * Generate new OTP key
     */
    private generateNewKey;
    /**
     * Get current OTP key for use
     */
    getOneTimePreKey(): OTPKeyBundle;
    /**
     * Mark OTP key as used
     */
    markAsUsed(keyId: number): void;
    /**
     * Get multiple OTP keys (for preloading)
     */
    getMultipleOneTimePreKeys(count: number): OTPKeyBundle[];
    /**
     * Rotate expired OTP keys
     */
    rotateExpiredKeys(): void;
    /**
     * Get OTP key status (for debugging/monitoring)
     */
    getStatus(): {
        totalKeys: number;
        unusedKeys: number;
        usedKeys: number;
        nextKeyId: number;
        oldestUnusedAge: number;
    };
    /**
     * Get private key for OTP (for decryption after receiving)
     */
    getOneTimePreKeyPair(keyId: number): KeyPair | null;
    /**
     * Cleanup very old keys
     */
    cleanup(): void;
    /**
     * Export state for persistence
     */
    exportState(): string;
    /**
     * Import state from persistence
     */
    importState(json: string): void;
    private toBundleFormat;
}
