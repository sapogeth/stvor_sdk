/**
 * File-Based Encrypted Session Storage
 * 
 * Stores Double Ratchet session state securely in encrypted files.
 * Uses AES-256-GCM with master key derived from passphrase.
 */

import { promises as fs } from 'fs';
import crypto from 'crypto';
import path from 'path';
import { ISessionStore } from './crypto-session.js';

export interface FileSessionStoreConfig {
  directory: string;  // Where to store encrypted sessions
  masterPassword: string; // To derive encryption key
}

export class FileSessionStore implements ISessionStore {
  private directory: string;
  private masterKey: Buffer;

  constructor(config: FileSessionStoreConfig) {
    this.directory = config.directory;
    // Derive stable master key from password
    this.masterKey = crypto.pbkdf2Sync(
      config.masterPassword,
      Buffer.from('stvor-session-store'),
      100000, // iterations
      32,      // key length
      'sha256'
    );
  }

  private getUserDir(userId: string): string {
    const safe = userId.replace(/[^a-zA-Z0-9-_.]/g, '_');
    return path.join(this.directory, safe);
  }

  private getSessionFile(userId: string, peerId: string): string {
    const peerSafe = peerId.replace(/[^a-zA-Z0-9-_.]/g, '_');
    return path.join(this.getUserDir(userId), `${peerSafe}.session.enc`);
  }

  private encrypt(plaintext: Buffer): Buffer {
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.masterKey, nonce);
    const encrypted = Buffer.concat([
      cipher.update(plaintext),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([nonce, tag, encrypted]);
  }

  private decrypt(cipherBuffer: Buffer): Buffer {
    if (cipherBuffer.length < 28) throw new Error('Invalid encrypted data');
    
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

  async saveSession(userId: string, peerId: string, sessionData: Buffer): Promise<void> {
    const filePath = this.getSessionFile(userId, peerId);
    const userDir = this.getUserDir(userId);
    
    // Ensure user directory exists
    await fs.mkdir(userDir, { recursive: true });
    
    // Encrypt and save session
    const encrypted = this.encrypt(sessionData);
    await fs.writeFile(filePath, encrypted, { mode: 0o600 });
  }

  async loadSession(userId: string, peerId: string): Promise<Buffer | null> {
    const filePath = this.getSessionFile(userId, peerId);
    
    try {
      const encrypted = await fs.readFile(filePath);
      return this.decrypt(encrypted);
    } catch (e: any) {
      if (e.code === 'ENOENT') {
        return null; // File doesn't exist
      }
      throw e;
    }
  }

  async deleteSession(userId: string, peerId: string): Promise<void> {
    const filePath = this.getSessionFile(userId, peerId);
    try {
      await fs.unlink(filePath);
    } catch (e: any) {
      if (e.code !== 'ENOENT') {
        throw e;
      }
    }
  }

  async listSessions(userId: string): Promise<string[]> {
    const userDir = this.getUserDir(userId);
    
    try {
      const files = await fs.readdir(userDir);
      return files
        .filter(f => f.endsWith('.session.enc'))
        .map(f => f.replace('.session.enc', ''));
    } catch (e: any) {
      if (e.code === 'ENOENT') {
        return [];
      }
      throw e;
    }
  }
}
