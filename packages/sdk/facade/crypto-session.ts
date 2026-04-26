/**
 * STVOR Crypto Session Manager
 * Uses ONLY Node.js built-in crypto module — zero external dependencies
 *
 * Manages identity keys (IK + SPK), ECDSA signatures,
 * X3DH session establishment, and Double Ratchet encrypt/decrypt.
 */

import nodeCrypto from 'node:crypto';
import { pqcKeyGen, pqcEncaps, pqcDecaps, hybridKDF, pqcEkToBase64, pqcEkFromBase64, pqcCtFromBase64 } from '../pqc/index.js';
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
  pqcEk?: string;        // ML-KEM-768 encapsulation key (base64url), present when pqc: true
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
 * Group session types
 * ================================================================ */

export interface GroupMemberState {
  chainKey: Buffer;       // receiving chain key for this member's messages
  counter: number;        // last received message counter
  generation: number;     // sender key generation number
  skippedKeys: Map<number, Buffer>; // counter -> message key (out-of-order)
}

export interface GroupSessionState {
  groupId: string;
  members: Set<string>;
  // Sending state (our sender key chain)
  sendChainKey: Buffer;
  sendCounter: number;
  sendGeneration: number;
  createdAt: number;
  // Receiving state per member
  memberStates: Map<string, GroupMemberState>;
}

/* ================================================================
 * Helpers
 * ================================================================ */

function toB64(buf: Buffer): string { return buf.toString('base64url'); }
function fromB64(s: string): Buffer { return Buffer.from(s, 'base64url'); }

// Sender Keys chain KDF: HMAC-SHA256 based ratchet
// Input: 32-byte chain key
// Output: 32-byte message key + 32-byte next chain key
function kdfGroupChain(chainKey: Buffer): { messageKey: Buffer; nextChainKey: Buffer } {
  const messageKey  = nodeCrypto.createHmac('sha256', chainKey).update(Buffer.from([0x01])).digest();
  const nextChainKey = nodeCrypto.createHmac('sha256', chainKey).update(Buffer.from([0x02])).digest();
  return { messageKey, nextChainKey };
}

/* ================================================================
 * CryptoSessionManager
 * ================================================================ */

export class CryptoSessionManager {
  private userId: string;
  private identityKeys: IdentityKeys | null = null;
  private sessions: Map<string, SessionState> = new Map();
  private groupSessions: Map<string, GroupSessionState> = new Map();
  private initialized = false;
  private initPromise: Promise<void> | null = null;
  private identityStore: IIdentityStore | null = null;
  private sessionStore: ISessionStore | null = null;
  private pqcEnabled: boolean = false;
  private pqcKeyPair: { ek: Uint8Array; dk: Uint8Array } | null = null;
  private peerPqcEks: Map<string, Uint8Array> = new Map();
  // Pending PQC ciphertexts to include in the first outgoing message
  private pendingPqcCt: Map<string, string> = new Map();
  // PQC shared secrets derived but not yet mixed (waiting for first message)
  private pendingPqcSS: Map<string, Uint8Array> = new Map();

  constructor(userId: string, identityStore?: IIdentityStore, sessionStore?: ISessionStore, pqc = false) {
    this.userId = userId;
    this.identityStore = identityStore || null;
    this.sessionStore = sessionStore || null;
    this.pqcEnabled = pqc;
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

    // Generate ML-KEM-768 key pair if PQC enabled
    if (this.pqcEnabled) {
      this.pqcKeyPair = pqcKeyGen();
    }

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

  /* ---- Identity key access for sealed sender ---- */

  getIdentityPrivateKey(): Buffer {
    if (!this.identityKeys) throw new Error('Not initialized');
    return Buffer.from(this.identityKeys.identityKeyPair.privateKey);
  }

  /* ---- Public keys ---- */

  getPublicKeys(): SerializedPublicKeys {
    if (!this.identityKeys) throw new Error('Not initialized');
    return {
      identityKey: toB64(this.identityKeys.identityKeyPair.publicKey),
      signedPreKey: toB64(this.identityKeys.signedPreKeyPair.publicKey),
      signedPreKeySignature: toB64(this.identityKeys.signedPreKeySignature),
      oneTimePreKey: '',
      // Include ML-KEM public key when PQC is enabled
      ...(this.pqcEnabled && this.pqcKeyPair
        ? { pqcEk: pqcEkToBase64(this.pqcKeyPair.ek) }
        : {}),
    };
  }

  /* ---- PQC methods ---- */

  isPqcEnabled(): boolean { return this.pqcEnabled; }

  /**
   * Encapsulate a shared secret to a peer who has a PQC key.
   * Called by sender during session setup.
   * Returns { ciphertext, pqcSharedSecret } — ciphertext sent to peer in register message.
   */
  pqcEncapsForPeer(peerEkB64: string): { ctB64: string; ss: Uint8Array } {
    const peerEk = pqcEkFromBase64(peerEkB64);
    const { ciphertext, sharedSecret } = pqcEncaps(peerEk);
    return { ctB64: Buffer.from(ciphertext).toString('base64url'), ss: sharedSecret };
  }

  /**
   * Decapsulate a PQC ciphertext sent by a peer.
   * Returns the shared secret.
   */
  pqcDecapsFromPeer(ctB64: string): Uint8Array {
    if (!this.pqcKeyPair) throw new Error('PQC not enabled or key not generated');
    const ct = pqcCtFromBase64(ctB64);
    return pqcDecaps(ct, this.pqcKeyPair.dk);
  }

  /**
   * Derive hybrid session key combining classical X3DH and PQC shared secrets.
   */
  hybridSessionKey(classicalSS: Uint8Array, pqcSS: Uint8Array): Uint8Array {
    return hybridKDF(classicalSS, pqcSS);
  }

  /**
   * Cache a peer's PQC encapsulation key (received during key exchange).
   */
  storePeerPqcEk(peerId: string, ekB64: string): void {
    this.peerPqcEks.set(peerId, pqcEkFromBase64(ekB64));
  }

  getPeerPqcEk(peerId: string): Uint8Array | undefined {
    return this.peerPqcEks.get(peerId);
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

    // Classical X3DH session
    const session = ratchetEstablishSession(
      this.identityKeys.identityKeyPair,
      this.identityKeys.signedPreKeyPair,
      peerIK,
      peerSPK,
    );

    // PQC hybrid — full KEM encaps/decaps (no deterministic shortcut).
    //
    // Protocol (no extra round-trip needed):
    //   Initiator (the side calling establishSession first / sending first):
    //     1. mlkemEncaps(peerEk) → (ct, ss)
    //     2. Store ct in pendingPqcCt[peerId] — sent inside the first message
    //     3. Store ss in pendingPqcSS[peerId] — mixed into root key on first encrypt
    //
    //   Responder (the side that receives the first message):
    //     1. Extracts ct from the incoming message header (pqcCt field)
    //     2. mlkemDecaps(ct, myDk) → ss
    //     3. Calls applyPqcSS(peerId, ss) to mix into root key
    //
    // Both sides end up with the same ss (KEM correctness) mixed into root key.
    // The ss is never transmitted — only the ciphertext, which is useless without dk.
    if (this.pqcEnabled && this.pqcKeyPair && peerPublicKeys.pqcEk) {
      const { ctB64, ss } = this.pqcEncapsForPeer(peerPublicKeys.pqcEk);
      this.pendingPqcCt.set(peerId, ctB64);
      this.pendingPqcSS.set(peerId, ss);
      // Root key will be mixed when first message is sent (applyPendingPqcSS)
    }

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

  /* ---- Group sessions ---- */

  createGroupSession(groupId: string, memberIds: string[]): GroupSessionState {
    const sendChainKey = nodeCrypto.randomBytes(32);
    const session: GroupSessionState = {
      groupId,
      members: new Set(memberIds),
      sendChainKey,
      sendCounter: 0,
      sendGeneration: 0,
      createdAt: Date.now(),
      memberStates: new Map(),
    };
    this.groupSessions.set(groupId, session);
    return session;
  }

  getGroupSession(groupId: string): GroupSessionState | undefined {
    return this.groupSessions.get(groupId);
  }

  hasGroupSession(groupId: string): boolean {
    return this.groupSessions.has(groupId);
  }

  // Returns the sender key distribution payload to send to each member
  getSenderKeyDistribution(groupId: string): { chainKey: string; generation: number; counter: number } {
    const session = this.groupSessions.get(groupId);
    if (!session) throw new Error(`No group session: ${groupId}`);
    return {
      chainKey: toB64(session.sendChainKey),
      generation: session.sendGeneration,
      counter: session.sendCounter,
    };
  }

  // Install sender key from another group member (received via 1-to-1 session)
  installSenderKey(groupId: string, fromUserId: string, chainKey: string, generation: number): void {
    let session = this.groupSessions.get(groupId);
    if (!session) {
      session = {
        groupId,
        members: new Set([fromUserId]),
        sendChainKey: nodeCrypto.randomBytes(32),
        sendCounter: 0,
        sendGeneration: 0,
        createdAt: Date.now(),
        memberStates: new Map(),
      };
      this.groupSessions.set(groupId, session);
    }
    session.members.add(fromUserId);
    session.memberStates.set(fromUserId, {
      chainKey: fromB64(chainKey),
      counter: 0,
      generation,
      skippedKeys: new Map(),
    });
  }

  // Encrypt a group message — returns ciphertext + group header
  encryptForGroup(groupId: string, plaintext: string): { ciphertext: string; groupHeader: string } {
    const session = this.groupSessions.get(groupId);
    if (!session) throw new Error(`No group session: ${groupId}`);

    // Ratchet send chain: new chainKey + messageKey via HMAC
    const { messageKey, nextChainKey } = kdfGroupChain(session.sendChainKey);
    session.sendChainKey = nextChainKey;
    const counter = session.sendCounter++;

    // Encrypt with AES-256-GCM
    const nonce = nodeCrypto.randomBytes(12);
    const keyBuf = messageKey;
    const cipher = nodeCrypto.createCipheriv('aes-256-gcm', keyBuf, nonce);
    const pt = Buffer.from(plaintext, 'utf-8');
    const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
    const tag = cipher.getAuthTag();

    // Group header: [generation u32 BE][counter u32 BE][nonce 12B] = 20 bytes
    const groupHeader = Buffer.allocUnsafe(20);
    groupHeader.writeUInt32BE(session.sendGeneration, 0);
    groupHeader.writeUInt32BE(counter, 4);
    nonce.copy(groupHeader, 8);

    return {
      ciphertext: toB64(Buffer.concat([ct, tag])),
      groupHeader: toB64(groupHeader),
    };
  }

  // Decrypt a group message from a specific sender
  decryptFromGroup(groupId: string, fromUserId: string, ciphertext: string, groupHeader: string): string {
    const session = this.groupSessions.get(groupId);
    if (!session) throw new Error(`No group session: ${groupId}`);

    const memberState = session.memberStates.get(fromUserId);
    if (!memberState) throw new Error(`No sender key from ${fromUserId} in group ${groupId}`);

    const headerBuf = fromB64(groupHeader);
    const generation = headerBuf.readUInt32BE(0);
    const counter = headerBuf.readUInt32BE(4);
    const nonce = headerBuf.subarray(8, 20);

    if (generation !== memberState.generation) {
      throw new Error(`Sender key generation mismatch from ${fromUserId}`);
    }

    // Advance chain to reach the right counter, caching skipped keys
    let messageKey: Buffer;
    if (counter < memberState.counter) {
      // Out-of-order: try skipped keys cache
      const skipped = memberState.skippedKeys.get(counter);
      if (!skipped) throw new Error(`Missing skipped message key counter=${counter}`);
      messageKey = skipped;
      memberState.skippedKeys.delete(counter);
    } else {
      // Advance chain, cache skipped keys along the way
      let ck = memberState.chainKey;
      for (let i = memberState.counter; i < counter; i++) {
        const derived = kdfGroupChain(ck);
        memberState.skippedKeys.set(i, derived.messageKey);
        ck = derived.nextChainKey;
        if (memberState.skippedKeys.size > 256) {
          // Drop oldest to bound memory
          const oldest = memberState.skippedKeys.keys().next().value;
          if (oldest !== undefined) memberState.skippedKeys.delete(oldest);
        }
      }
      const derived = kdfGroupChain(ck);
      messageKey = derived.messageKey;
      memberState.chainKey = derived.nextChainKey;
      memberState.counter = counter + 1;
    }

    // Decrypt AES-256-GCM
    const ctBuf = fromB64(ciphertext);
    const tag = ctBuf.subarray(ctBuf.length - 16);
    const ct = ctBuf.subarray(0, ctBuf.length - 16);
    const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', messageKey, nonce);
    decipher.setAuthTag(tag);
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
    return pt.toString('utf-8');
  }

  // Ratchet our sender key and return new distribution payload
  ratchetGroupSenderKey(groupId: string): { chainKey: string; generation: number } {
    const session = this.groupSessions.get(groupId);
    if (!session) throw new Error(`No group session: ${groupId}`);
    session.sendChainKey = nodeCrypto.randomBytes(32);
    session.sendCounter = 0;
    session.sendGeneration++;
    session.createdAt = Date.now();
    return { chainKey: toB64(session.sendChainKey), generation: session.sendGeneration };
  }

  addGroupMember(groupId: string, memberId: string): void {
    const session = this.groupSessions.get(groupId);
    if (!session) throw new Error(`No group session: ${groupId}`);
    session.members.add(memberId);
  }

  removeGroupMember(groupId: string, memberId: string): void {
    const session = this.groupSessions.get(groupId);
    if (!session) throw new Error(`No group session: ${groupId}`);
    session.members.delete(memberId);
    session.memberStates.delete(memberId);
    // Ratchet sender key so removed member can't decrypt future messages
    session.sendChainKey = nodeCrypto.randomBytes(32);
    session.sendCounter = 0;
    session.sendGeneration++;
    session.createdAt = Date.now();
  }

  getGroupMembers(groupId: string): string[] {
    const session = this.groupSessions.get(groupId);
    if (!session) return [];
    return [...session.members];
  }

  /* ---- PQC KEM handshake helpers ---- */

  /**
   * Called by sender before first encrypt.
   * Returns the ML-KEM ciphertext to embed in the first message,
   * and mixes the PQC shared secret into the session root key.
   */
  popPendingPqcCt(peerId: string): string | null {
    const ct = this.pendingPqcCt.get(peerId);
    if (!ct) return null;
    this.pendingPqcCt.delete(peerId);

    const ss = this.pendingPqcSS.get(peerId);
    if (ss) {
      this.pendingPqcSS.delete(peerId);
      this._mixPqcSS(peerId, ss);
    }
    return ct;
  }

  /**
   * Called by recipient when first message arrives with a pqcCt field.
   * Decapsulates the ciphertext and mixes PQC SS into the session root key.
   */
  applyIncomingPqcCt(peerId: string, ctB64: string): void {
    if (!this.pqcKeyPair) return;
    const ss = this.pqcDecapsFromPeer(ctB64);
    this._mixPqcSS(peerId, ss);
  }

  private _mixPqcSS(peerId: string, ss: Uint8Array): void {
    const session = this.sessions.get(peerId);
    if (!session) return;
    const hybridRoot = hybridKDF(
      new Uint8Array(session.rootKey),
      ss,
      'stvor-hybrid-root-v1',
    );
    session.rootKey = Buffer.from(hybridRoot);
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
