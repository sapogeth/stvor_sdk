/**
 * File-Based Persistent Replay Protection
 *
 * Stores message nonces and counters securely.
 * Prevents replay attacks across app restarts.
 */
import { promises as fs } from 'fs';
import crypto from 'crypto';
import path from 'path';
export class FileReplayStore {
    constructor(config) {
        this.directory = config.directory;
        this.masterKey = crypto.pbkdf2Sync(config.masterPassword, Buffer.from('stvor-replay-store'), 100000, 32, 'sha256');
    }
    getReplayFile(userId, peerId) {
        const userSafe = userId.replace(/[^a-zA-Z0-9-_.]/g, '_');
        const peerSafe = peerId.replace(/[^a-zA-Z0-9-_.]/g, '_');
        const userDir = path.join(this.directory, userSafe);
        return path.join(userDir, `${peerSafe}.replay.enc`);
    }
    encrypt(plaintext) {
        const nonce = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', this.masterKey, nonce);
        const encrypted = Buffer.concat([
            cipher.update(plaintext, 'utf-8'),
            cipher.final(),
        ]);
        const tag = cipher.getAuthTag();
        return Buffer.concat([nonce, tag, encrypted]);
    }
    decrypt(cipherBuffer) {
        if (cipherBuffer.length < 28)
            throw new Error('Invalid encrypted data');
        const nonce = cipherBuffer.subarray(0, 12);
        const tag = cipherBuffer.subarray(12, 28);
        const encrypted = cipherBuffer.subarray(28);
        const decipher = crypto.createDecipheriv('aes-256-gcm', this.masterKey, nonce);
        decipher.setAuthTag(tag);
        return Buffer.concat([
            decipher.update(encrypted),
            decipher.final(),
        ]).toString('utf-8');
    }
    /**
     * Get or initialize replay state for a peer
     */
    async getReplayState(userId, peerId) {
        const filePath = this.getReplayFile(userId, peerId);
        try {
            const encrypted = await fs.readFile(filePath);
            const plaintext = this.decrypt(encrypted);
            const data = JSON.parse(plaintext);
            return {
                seenNonces: new Set(data.seenNonces),
                lastMessageCounter: data.lastMessageCounter,
            };
        }
        catch (e) {
            if (e.code === 'ENOENT') {
                // New conversation - initialize
                return {
                    seenNonces: new Set(),
                    lastMessageCounter: 0,
                };
            }
            throw e;
        }
    }
    /**
     * Save replay state
     */
    async saveReplayState(userId, peerId, nonces, lastMessageCounter) {
        const filePath = this.getReplayFile(userId, peerId);
        const userDir = path.dirname(filePath);
        // Ensure directory exists
        await fs.mkdir(userDir, { recursive: true });
        const plaintext = JSON.stringify({
            timestamp: new Date().toISOString(),
            seenNonces: Array.from(nonces).slice(-1000), // Keep last 1000 nonces
            lastMessageCounter,
        });
        const encrypted = this.encrypt(plaintext);
        await fs.writeFile(filePath, encrypted, { mode: 0o600 });
    }
    /**
     * Check if message is replay and add nonce
     */
    async recordNonce(userId, peerId, nonce, messageCounter) {
        const state = await this.getReplayState(userId, peerId);
        // Check for replay
        const isReplay = state.seenNonces.has(nonce) || messageCounter <= state.lastMessageCounter;
        if (!isReplay) {
            // Record new nonce
            state.seenNonces.add(nonce);
            state.lastMessageCounter = Math.max(state.lastMessageCounter, messageCounter);
            // Save updated state
            await this.saveReplayState(userId, peerId, state.seenNonces, state.lastMessageCounter);
        }
        return { isReplay, state };
    }
    /**
     * Clear replay state (e.g., after key compromise recovery)
     */
    async clearReplayState(userId, peerId) {
        const filePath = this.getReplayFile(userId, peerId);
        try {
            await fs.unlink(filePath);
        }
        catch (e) {
            if (e.code !== 'ENOENT') {
                throw e;
            }
        }
    }
}
