/**
 * STVOR Crypto Session Manager
 * Uses ONLY Node.js built-in crypto module — zero external dependencies
 *
 * Manages identity keys (IK + SPK), ECDSA signatures,
 * X3DH session establishment, and Double Ratchet encrypt/decrypt.
 */

import nodeCrypto from 'node:crypto';
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
