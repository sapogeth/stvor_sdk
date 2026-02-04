import crypto from 'crypto';

export type EncryptedMessage = {
  version: number;
  senderPub: string; // base64 DER spki
  nonce: string; // base64
  ciphertext: string; // base64
  tag: string; // base64
};

export class CryptoSession {
  privateKey: crypto.KeyObject;
  publicKey: crypto.KeyObject;
  public readonly publicKeyBase64: string;

  constructor() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    const spki = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
    this.publicKeyBase64 = spki.toString('base64');
  }

  exportPublic(): string {
    return this.publicKeyBase64;
  }

  private deriveShared(remotePubBase64: string): Buffer {
    const remoteDer = Buffer.from(remotePubBase64, 'base64');
    const remoteKey = crypto.createPublicKey({ key: remoteDer, type: 'spki', format: 'der' });
    const shared = crypto.diffieHellman({ privateKey: this.privateKey, publicKey: remoteKey });
    // HKDF-SHA256 to 32 bytes
    const key = crypto.hkdfSync('sha256', shared, Buffer.alloc(0), Buffer.from('stvor v0.1'), 32);
    return Buffer.from(key as ArrayBuffer);
  }

  encrypt(plaintext: Uint8Array, remotePubBase64: string): EncryptedMessage {
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

  decrypt(msg: EncryptedMessage, remotePubBase64: string): Uint8Array {
    const key = this.deriveShared(remotePubBase64);
    const nonce = Buffer.from(msg.nonce, 'base64');
    const ct = Buffer.from(msg.ciphertext, 'base64');
    const tag = Buffer.from(msg.tag, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAuthTag(tag);
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
    return new Uint8Array(pt);
  }
}

export default CryptoSession;
