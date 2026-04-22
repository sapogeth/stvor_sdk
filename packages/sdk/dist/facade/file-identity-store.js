/**
 * File-Based Encrypted Key Storage
 *
 * Stores identity keys securely in encrypted JSON files.
 * Uses AES-256-GCM with a master key derived from a passphrase.
 *
 * Perfect for Node.js servers and CLI applications.
 */
import { promises as fs } from 'fs';
import crypto from 'crypto';
import path from 'path';
export class FileIdentityStore {
    constructor(config) {
        this.directory = config.directory;
        // Derive a stable master key from password using PBKDF2
        this.masterKey = crypto.pbkdf2Sync(config.masterPassword, Buffer.from('stvor-file-store'), 100000, // iterations
        32, // key length
        'sha256');
    }
    getFilePath(userId) {
        // Sanitize userId for filename
        const safe = userId.replace(/[^a-zA-Z0-9-_.]/g, '_');
        return path.join(this.directory, `${safe}.keys.enc`);
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
    async saveIdentityKeys(userId, keys) {
        const filePath = this.getFilePath(userId);
        const plaintext = JSON.stringify({
            timestamp: new Date().toISOString(),
            keys,
        });
        const encrypted = this.encrypt(plaintext);
        // Ensure directory exists
        await fs.mkdir(this.directory, { recursive: true });
        // Write with restricted permissions (owner read/write only)
        await fs.writeFile(filePath, encrypted, { mode: 0o600 });
    }
    async loadIdentityKeys(userId) {
        const filePath = this.getFilePath(userId);
        try {
            const encrypted = await fs.readFile(filePath);
            const plaintext = this.decrypt(encrypted);
            const data = JSON.parse(plaintext);
            return data.keys;
        }
        catch (e) {
            if (e.code === 'ENOENT') {
                return null; // File doesn't exist
            }
            throw e;
        }
    }
    async deleteIdentityKeys(userId) {
        const filePath = this.getFilePath(userId);
        try {
            await fs.unlink(filePath);
        }
        catch (e) {
            if (e.code !== 'ENOENT') {
                throw e;
            }
        }
    }
    async listUsers() {
        try {
            const files = await fs.readdir(this.directory);
            return files
                .filter(f => f.endsWith('.keys.enc'))
                .map(f => f.replace('.keys.enc', ''));
        }
        catch (e) {
            if (e.code === 'ENOENT') {
                return [];
            }
            throw e;
        }
    }
}
