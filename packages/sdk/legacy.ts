/**
 * STVOR SDK - Legacy Core API
 * Kept for backwards compatibility
 */

export interface StvorConfig {
  apiKey: string;
  serverUrl?: string;
}

export interface Peer {
  id: string;
  publicKey: any;
}

export interface EncryptedMessage {
  ciphertext: string;
  nonce: string;
  from: string;
}

export class StvorClient {
  private config: StvorConfig;
  private myKeyPair: CryptoKeyPair | null = null;
  private myId: string = '';
  private peers: Map<string, CryptoKey> = new Map();

  constructor(config: StvorConfig) {
    this.config = {
      serverUrl: 'http://localhost:3001',
      ...config,
    };
  }

  async ready(): Promise<void> {
    if (!this.config.apiKey) {
      throw new Error('API key is required');
    }
    this.myKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey', 'deriveBits']
    );
    this.myId = this.config.apiKey.substring(0, 8);
  }

  async createPeer(name: string): Promise<Peer> {
    if (!this.myKeyPair) throw new Error('Call ready() first');

    const publicKey = await crypto.subtle.exportKey('jwk', this.myKeyPair.publicKey);

    const res = await fetch(`${this.config.serverUrl}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: name, publicKey }),
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(`Registration failed: ${JSON.stringify(err)}`);
    }

    return { id: name, publicKey };
  }

  async send({ to, message }: { to: string; message: string }): Promise<EncryptedMessage> {
    if (!this.myKeyPair) throw new Error('Call ready() first');

    let recipientKey = this.peers.get(to);
    if (!recipientKey) {
      const res = await fetch(`${this.config.serverUrl}/public-key/${to}`);
      if (!res.ok) throw new Error(`Peer ${to} not found`);
      const { publicKey } = await res.json();
      recipientKey = await crypto.subtle.importKey(
        'jwk',
        publicKey,
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        []
      );
      this.peers.set(to, recipientKey);
    }

    const sharedKey = await crypto.subtle.deriveKey(
      { name: 'ECDH', public: recipientKey },
      this.myKeyPair.privateKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      sharedKey,
      encoder.encode(message)
    );

    const sendRes = await fetch(`${this.config.serverUrl}/message`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: this.myId,
        to,
        ciphertext: Buffer.from(encrypted).toString('base64'),
        nonce: Buffer.from(iv).toString('base64'),
      }),
    });

    if (!sendRes.ok) {
      throw new Error('Failed to send message');
    }

    return { 
      ciphertext: Buffer.from(encrypted).toString('base64'), 
      nonce: Buffer.from(iv).toString('base64'), 
      from: this.myId 
    };
  }

  async receive(encrypted: EncryptedMessage): Promise<string> {
    if (!this.myKeyPair) throw new Error('Call ready() first');

    let senderKey = this.peers.get(encrypted.from);
    if (!senderKey) {
      const res = await fetch(`${this.config.serverUrl}/public-key/${encrypted.from}`);
      if (!res.ok) throw new Error(`Sender ${encrypted.from} not found`);
      const { publicKey } = await res.json();
      senderKey = await crypto.subtle.importKey(
        'jwk',
        publicKey,
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        []
      );
      this.peers.set(encrypted.from, senderKey);
    }

    const sharedKey = await crypto.subtle.deriveKey(
      { name: 'ECDH', public: senderKey },
      this.myKeyPair.privateKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    const iv = Buffer.from(encrypted.nonce, 'base64');
    const ciphertext = Buffer.from(encrypted.ciphertext, 'base64');
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      sharedKey,
      ciphertext
    );

    return new TextDecoder().decode(decrypted);
  }
}
