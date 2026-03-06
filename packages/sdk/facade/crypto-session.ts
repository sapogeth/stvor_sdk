/**
 * STVOR Crypto Session Manager
 * Uses ONLY Node.js built-in crypto module — zero external dependencies
 *
 * Manages identity keys (IK + SPK), ECDSA signatures,
 * X3DH session establishment, and Double Ratchet encrypt/decrypt.
 */

import {
  SessionState,
  KeyPair,
  generateKeyPair,
  encryptMessage as ratchetEncrypt,
  decryptMessage as ratchetDecrypt,
  establishSession as ratchetEstablishSession,
  serializeSession,
  deserializeSession,
  initializeCrypto,
  ecSign,
  ecVerify,
} from '../ratchet/index.js';

/* ================================================================
 * Public interfaces
 * ================================================================ */

export interface IdentityKeys {
  identityKeyPair: KeyPair;
  signedPreKeyPair: KeyPair;
  signedPreKeySignature: Buffer;
}

export interface SerializedPublicKeys {
  identityKey: string;
  signedPreKey: string;
  signedPreKeySignature: string;
  oneTimePreKey: string; // kept for relay compat — always empty
}

/* ================================================================
 * Storage interfaces
 * ================================================================ */

export interface IIdentityStore {
  saveIdentityKeys(
    userId: string,
    keys: {
      identityKeyPair: { publicKey: string; privateKey: string };
      signedPreKeyPair: { publicKey: string; privateKey: string };
      signedPreKeySignature: string;
    },
  ): Promise<void>;
  loadIdentityKeys(
    userId: string,
  ): Promise<{
    identityKeyPair: { publicKey: string; privateKey: string };
    signedPreKeyPair: { publicKey: string; privateKey: string };
    signedPreKeySignature: string;
  } | null>;
}

export interface ISessionStore {
  saveSession(userId: string, peerId: string, sessionData: Buffer): Promise<void>;
  loadSession(userId: string, peerId: string): Promise<Buffer | null>;
  deleteSession(userId: string, peerId: string): Promise<void>;
  listSessions(userId: string): Promise<string[]>;
}

/* ================================================================
 * Helpers
 * ================================================================ */

function toB64(buf: Buffer): string { return buf.toString('base64url'); }
function fromB64(s: string): Buffer { return Buffer.from(s, 'base64url'); }

/* ================================================================
 * CryptoSessionManager
 * ================================================================ */

export class CryptoSessionManager {
  private userId: string;
  private identityKeys: IdentityKeys | null = null;
  private sessions: Map<string, SessionState> = new Map();
  private initialized = false;
  private initPromise: Promise<void> | null = null;
  private identityStore: IIdentityStore | null = null;
  private sessionStore: ISessionStore | null = null;

  constructor(userId: string, identityStore?: IIdentityStore, sessionStore?: ISessionStore) {
    this.userId = userId;
    this.identityStore = identityStore || null;
    this.sessionStore = sessionStore || null;
  }

  /* ---- Initialisation ---- */

  async initialize(): Promise<void> {
    if (this.initialized && this.identityKeys) return;
    if (this.initPromise) return this.initPromise;
    this.initPromise = this._doInit();
    return this.initPromise;
  }

  private async _doInit(): Promise<void> {
    await initializeCrypto();

    if (this.identityStore) {
      try {
        const stored = await this.identityStore.loadIdentityKeys(this.userId);
        if (stored) {
          this.identityKeys = {
            identityKeyPair: {
              publicKey: fromB64(stored.identityKeyPair.publicKey),
              privateKey: fromB64(stored.identityKeyPair.privateKey),
            },
            signedPreKeyPair: {
              publicKey: fromB64(stored.signedPreKeyPair.publicKey),
              privateKey: fromB64(stored.signedPreKeyPair.privateKey),
            },
            signedPreKeySignature: fromB64(stored.signedPreKeySignature),
          };
          this.initialized = true;
          return;
        }
      } catch (e) {
        console.warn('Failed to load identity keys:', e);
      }
    }

    const ik = generateKeyPair();
    const spk = generateKeyPair();
    const sig = ecSign(spk.publicKey, ik);

    this.identityKeys = {
      identityKeyPair: ik,
      signedPreKeyPair: spk,
      signedPreKeySignature: sig,
    };

    if (this.identityStore) {
      try {
        await this.identityStore.saveIdentityKeys(this.userId, {
          identityKeyPair: { publicKey: toB64(ik.publicKey), privateKey: toB64(ik.privateKey) },
          signedPreKeyPair: { publicKey: toB64(spk.publicKey), privateKey: toB64(spk.privateKey) },
          signedPreKeySignature: toB64(sig),
        });
      } catch (e) {
        console.warn('Failed to save identity keys:', e);
      }
    }

    this.initialized = true;
  }

  /* ---- Public keys ---- */

  getPublicKeys(): SerializedPublicKeys {
    if (!this.identityKeys) throw new Error('Not initialized');
    return {
      identityKey: toB64(this.identityKeys.identityKeyPair.publicKey),
      signedPreKey: toB64(this.identityKeys.signedPreKeyPair.publicKey),
      signedPreKeySignature: toB64(this.identityKeys.signedPreKeySignature),
      oneTimePreKey: '',
    };
  }

  /* ---- Session establishment ---- */

  async establishSession(peerId: string, peerPublicKeys: SerializedPublicKeys): Promise<void> {
    if (!this.identityKeys) throw new Error('Not initialized');

    const peerIK = fromB64(peerPublicKeys.identityKey);
    const peerSPK = fromB64(peerPublicKeys.signedPreKey);
    const peerSig = peerPublicKeys.signedPreKeySignature
      ? fromB64(peerPublicKeys.signedPreKeySignature)
      : Buffer.alloc(0);

    if (peerSig.length > 0 && !ecVerify(peerSPK, peerSig, peerIK)) {
      throw new Error('Invalid signed pre-key signature — possible MITM attack');
    }

    const session = ratchetEstablishSession(
      this.identityKeys.identityKeyPair,
      this.identityKeys.signedPreKeyPair,
      peerIK,
      peerSPK,
    );

    this.sessions.set(peerId, session);

    if (this.sessionStore) {
      try {
        await this.sessionStore.saveSession(this.userId, peerId, serializeSession(session));
      } catch (e) {
        console.warn('Failed to save session:', e);
      }
    }
  }

  async establishSessionWithPeer(peerId: string, pk: SerializedPublicKeys): Promise<void> {
    return this.establishSession(peerId, pk);
  }

  hasSession(peerId: string): boolean {
    return this.sessions.has(peerId);
  }

  /* ---- Encrypt ---- */

  encryptForPeer(peerId: string, plaintext: string): { ciphertext: string; header: string } {
    const session = this.sessions.get(peerId);
    if (!session) throw new Error('No session with peer');

    const { ciphertext, header } = ratchetEncrypt(session, Buffer.from(plaintext, 'utf-8'));
    return { ciphertext: toB64(ciphertext), header: toB64(header) };
  }

  /* ---- Decrypt ---- */

  decryptFromPeer(peerId: string, ciphertext: string, header: string): string {
    const session = this.sessions.get(peerId);
    if (!session) throw new Error('No session with peer');

    const pt = ratchetDecrypt(session, fromB64(ciphertext), fromB64(header));
    return pt.toString('utf-8');
  }

  /* ---- Post-compromise ---- */

  async forceRatchet(peerId: string): Promise<void> {
    const session = this.sessions.get(peerId);
    if (session) {
      session.myRatchetKeyPair = generateKeyPair();
      session.sendCount = 0;
      session.recvCount = 0;
      session.prevSendCount = 0;
      session.isPostCompromise = true;
    }
  }
}
