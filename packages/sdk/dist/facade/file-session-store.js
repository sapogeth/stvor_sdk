/**
 * File-Based Encrypted Session Storage
 *
 * Stores Double Ratchet session state securely in encrypted files.
 * Uses AES-256-GCM with master key derived from passphrase.
 */
import { promises as fs } from 'fs';
import crypto from 'crypto';
import path from 'path';
export class FileSessionStore {
    constructor(config) {
        this.directory = config.directory;
        // Derive stable master key from password
        this.masterKey = crypto.pbkdf2Sync(config.masterPassword, Buffer.from('stvor-session-store'), 100000, // iterations
        32, // key length
        'sha256');
    }
    getUserDir(userId) {
        const safe = userId.replace(/[^a-zA-Z0-9-_.]/g, '_');
        return path.join(this.directory, safe);
    }
    getSessionFile(userId, peerId) {
        const peerSafe = peerId.replace(/[^a-zA-Z0-9-_.]/g, '_');
        return path.join(this.getUserDir(userId), `${peerSafe}.session.enc`);
    }
    encrypt(plaintext) {
        const nonce = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', this.masterKey, nonce);
        const encrypted = Buffer.concat([
            cipher.update(plaintext),
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
        ]);
    }
    async saveSession(userId, peerId, sessionData) {
        const filePath = this.getSessionFile(userId, peerId);
        const userDir = this.getUserDir(userId);
        // Ensure user directory exists
        await fs.mkdir(userDir, { recursive: true });
        // Encrypt and save session
        const encrypted = this.encrypt(sessionData);
        await fs.writeFile(filePath, encrypted, { mode: 0o600 });
    }
    async loadSession(userId, peerId) {
        const filePath = this.getSessionFile(userId, peerId);
        try {
            const encrypted = await fs.readFile(filePath);
            return this.decrypt(encrypted);
        }
        catch (e) {
            if (e.code === 'ENOENT') {
                return null; // File doesn't exist
            }
            throw e;
        }
    }
    async deleteSession(userId, peerId) {
        const filePath = this.getSessionFile(userId, peerId);
        try {
            await fs.unlink(filePath);
        }
        catch (e) {
            if (e.code !== 'ENOENT') {
                throw e;
            }
        }
    }
    async listSessions(userId) {
        const userDir = this.getUserDir(userId);
        try {
            const files = await fs.readdir(userDir);
            return files
                .filter(f => f.endsWith('.session.enc'))
                .map(f => f.replace('.session.enc', ''));
        }
        catch (e) {
            if (e.code === 'ENOENT') {
                return [];
            }
            throw e;
        }
    }
}
