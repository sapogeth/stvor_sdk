import crypto from 'crypto';
/**
 * Constant-time comparison to prevent timing attacks
 */
function constantTimeCompare(a, b) {
    if (a.length !== b.length)
        return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i];
    }
    return result === 0;
}
export class CryptoSession {
    constructor() {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        const spki = publicKey.export({ type: 'spki', format: 'der' });
        this.publicKeyBase64 = spki.toString('base64');
    }
    exportPublic() {
        return this.publicKeyBase64;
    }
    deriveShared(remotePubBase64) {
        const remoteDer = Buffer.from(remotePubBase64, 'base64');
        const remoteKey = crypto.createPublicKey({ key: remoteDer, type: 'spki', format: 'der' });
        const shared = crypto.diffieHellman({ privateKey: this.privateKey, publicKey: remoteKey });
        // HKDF-SHA256 to 32 bytes
        const key = crypto.hkdfSync('sha256', shared, Buffer.alloc(0), Buffer.from('stvor v0.1'), 32);
        return Buffer.from(key);
    }
    encrypt(plaintext, remotePubBase64) {
        const key = this.deriveShared(remotePubBase64);
        const nonce = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
        const ct = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
        const tag = cipher.getAuthTag();
        return {
            version: 1,
            senderPub: this.publicKeyBase64,
            nonce: nonce.toString('base64'),
            ciphertext: ct.toString('base64'),
            tag: tag.toString('base64'),
        };
    }
    decrypt(msg, remotePubBase64) {
        if (msg.version !== 1) {
            throw new Error(`Unsupported message version: ${msg.version}`);
        }
        const key = this.deriveShared(remotePubBase64);
        const nonce = Buffer.from(msg.nonce, 'base64');
        const ct = Buffer.from(msg.ciphertext, 'base64');
        const tag = Buffer.from(msg.tag, 'base64');
        // Verify tag length (16 bytes for AES-GCM)
        if (tag.length !== 16) {
            throw new Error('Invalid authentication tag length');
        }
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
        decipher.setAuthTag(tag);
        try {
            const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
            return new Uint8Array(pt);
        }
        catch (e) {
            throw new Error('Decryption failed: authentication tag verification failed');
        }
    }
}
export default CryptoSession;
