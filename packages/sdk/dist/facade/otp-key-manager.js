/**
 * One-Time Prekey Management
 *
 * Generates, rotates, and tracks one-time prekeys (OPK)
 * for Signal Protocol X3DH key exchange.
 *
 * OPKs provide forward secrecy - each key is used only once.
 */
import { generateKeyPair } from '../ratchet/index.js';
export class OTPKeyManager {
    constructor(maxUnusedKeys = 100, rotationIntervalMs = 24 * 60 * 60 * 1000) {
        this.nextKeyId = 0;
        this.keyPairs = new Map();
        this.maxUnusedKeys = maxUnusedKeys;
        this.rotationInterval = rotationIntervalMs;
        this.initializeKeys();
    }
    /**
     * Initialize with random OPKs
     */
    initializeKeys() {
        for (let i = 0; i < this.maxUnusedKeys; i++) {
            this.generateNewKey();
        }
    }
    /**
     * Generate new OTP key
     */
    generateNewKey() {
        const keyId = this.nextKeyId++;
        const keyPair = generateKeyPair();
        this.keyPairs.set(keyId, { keyPair, createdAt: new Date() });
        return { keyId, keyPair };
    }
    /**
     * Get current OTP key for use
     */
    getOneTimePreKey() {
        // Get oldest unused key
        let oldestKeyId = -1;
        let oldestTime = Date.now();
        for (const [keyId, info] of this.keyPairs) {
            if (!info.usedAt && info.createdAt.getTime() < oldestTime) {
                oldestKeyId = keyId;
                oldestTime = info.createdAt.getTime();
            }
        }
        if (oldestKeyId === -1) {
            // No unused keys, generate new one
            const { keyId, keyPair } = this.generateNewKey();
            return this.toBundleFormat(keyId, keyPair);
        }
        const info = this.keyPairs.get(oldestKeyId);
        return this.toBundleFormat(oldestKeyId, info.keyPair);
    }
    /**
     * Mark OTP key as used
     */
    markAsUsed(keyId) {
        const info = this.keyPairs.get(keyId);
        if (info) {
            info.usedAt = new Date();
        }
    }
    /**
     * Get multiple OTP keys (for preloading)
     */
    getMultipleOneTimePreKeys(count) {
        const keys = [];
        const unused = Array.from(this.keyPairs.entries())
            .filter(([, info]) => !info.usedAt)
            .slice(0, count);
        for (const [keyId, info] of unused) {
            keys.push(this.toBundleFormat(keyId, info.keyPair));
        }
        // Generate new ones if not enough unused
        while (keys.length < count) {
            const { keyId, keyPair } = this.generateNewKey();
            keys.push(this.toBundleFormat(keyId, keyPair));
        }
        return keys;
    }
    /**
     * Rotate expired OTP keys
     */
    rotateExpiredKeys() {
        const now = Date.now();
        // Remove used keys older than rotation interval
        for (const [keyId, info] of this.keyPairs) {
            if (info.usedAt && now - info.usedAt.getTime() > this.rotationInterval) {
                this.keyPairs.delete(keyId);
            }
        }
        // Ensure we have enough unused keys
        const unusedCount = Array.from(this.keyPairs.values()).filter(info => !info.usedAt).length;
        while (unusedCount < this.maxUnusedKeys) {
            this.generateNewKey();
        }
    }
    /**
     * Get OTP key status (for debugging/monitoring)
     */
    getStatus() {
        const now = Date.now();
        let unusedCount = 0;
        let oldestUnusedAge = 0;
        for (const [, info] of this.keyPairs) {
            if (!info.usedAt) {
                unusedCount++;
                const age = now - info.createdAt.getTime();
                if (oldestUnusedAge === 0 || age > oldestUnusedAge) {
                    oldestUnusedAge = age;
                }
            }
        }
        return {
            totalKeys: this.keyPairs.size,
            unusedKeys: unusedCount,
            usedKeys: this.keyPairs.size - unusedCount,
            nextKeyId: this.nextKeyId,
            oldestUnusedAge,
        };
    }
    /**
     * Get private key for OTP (for decryption after receiving)
     */
    getOneTimePreKeyPair(keyId) {
        const info = this.keyPairs.get(keyId);
        return info ? info.keyPair : null;
    }
    /**
     * Cleanup very old keys
     */
    cleanup() {
        const now = Date.now();
        const maxAge = this.rotationInterval * 7; // Keep 7 rotation intervals
        for (const [keyId, info] of this.keyPairs) {
            if (now - info.createdAt.getTime() > maxAge) {
                this.keyPairs.delete(keyId);
            }
        }
    }
    /**
     * Export state for persistence
     */
    exportState() {
        const keys = {};
        for (const [keyId, info] of this.keyPairs) {
            keys[keyId] = {
                publicKey: info.keyPair.publicKey.toString('base64'),
                privateKey: info.keyPair.privateKey.toString('base64'),
                createdAt: info.createdAt.toISOString(),
                usedAt: info.usedAt?.toISOString(),
            };
        }
        return JSON.stringify({
            nextKeyId: this.nextKeyId,
            keys,
        });
    }
    /**
     * Import state from persistence
     */
    importState(json) {
        const data = JSON.parse(json);
        this.nextKeyId = data.nextKeyId;
        this.keyPairs.clear();
        for (const [keyIdStr, keyDataRaw] of Object.entries(data.keys)) {
            const keyId = Number(keyIdStr);
            const keyData = keyDataRaw;
            const info = {
                keyPair: {
                    publicKey: Buffer.from(keyData.publicKey, 'base64'),
                    privateKey: Buffer.from(keyData.privateKey, 'base64'),
                },
                createdAt: new Date(keyData.createdAt),
                usedAt: keyData.usedAt ? new Date(keyData.usedAt) : undefined,
            };
            this.keyPairs.set(keyId, info);
        }
    }
    toBundleFormat(keyId, keyPair) {
        return {
            keyId,
            publicKey: keyPair.publicKey.toString('base64url'),
            createdAt: new Date().toISOString(),
        };
    }
}
