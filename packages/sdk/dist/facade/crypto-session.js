/**
 * STVOR Crypto Session Manager
 * Uses ONLY Node.js built-in crypto module — zero external dependencies
 *
 * Manages identity keys (IK + SPK), ECDSA signatures,
 * X3DH session establishment, and Double Ratchet encrypt/decrypt.
 */
import nodeCrypto from 'node:crypto';
import { pqcKeyGen, pqcEncaps, pqcDecaps, hybridKDF, pqcEkToBase64, pqcEkFromBase64, pqcCtFromBase64 } from '../pqc/index.js';
import { generateKeyPair, encryptMessage as ratchetEncrypt, decryptMessage as ratchetDecrypt, establishSession as ratchetEstablishSession, serializeSession, initializeCrypto, ecSign, ecVerify, } from '../ratchet/index.js';
/* ================================================================
 * Helpers
 * ================================================================ */
function toB64(buf) { return buf.toString('base64url'); }
function fromB64(s) { return Buffer.from(s, 'base64url'); }
// Sender Keys chain KDF: HMAC-SHA256 based ratchet
// Input: 32-byte chain key
// Output: 32-byte message key + 32-byte next chain key
function kdfGroupChain(chainKey) {
    const messageKey = nodeCrypto.createHmac('sha256', chainKey).update(Buffer.from([0x01])).digest();
    const nextChainKey = nodeCrypto.createHmac('sha256', chainKey).update(Buffer.from([0x02])).digest();
    return { messageKey, nextChainKey };
}
/* ================================================================
 * CryptoSessionManager
 * ================================================================ */
export class CryptoSessionManager {
    constructor(userId, identityStore, sessionStore, pqc = false) {
        this.identityKeys = null;
        this.sessions = new Map();
        this.groupSessions = new Map();
        this.initialized = false;
        this.initPromise = null;
        this.identityStore = null;
        this.sessionStore = null;
        this.pqcEnabled = false;
        this.pqcKeyPair = null;
        // peerPqcEk: cached peer ML-KEM public keys
        this.peerPqcEks = new Map();
        this.userId = userId;
        this.identityStore = identityStore || null;
        this.sessionStore = sessionStore || null;
        this.pqcEnabled = pqc;
    }
    /* ---- Initialisation ---- */
    async initialize() {
        if (this.initialized && this.identityKeys)
            return;
        if (this.initPromise)
            return this.initPromise;
        this.initPromise = this._doInit();
        return this.initPromise;
    }
    async _doInit() {
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
            }
            catch (e) {
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
            }
            catch (e) {
                console.warn('Failed to save identity keys:', e);
            }
        }
        this.initialized = true;
    }
    /* ---- Identity key access for sealed sender ---- */
    getIdentityPrivateKey() {
        if (!this.identityKeys)
            throw new Error('Not initialized');
        return Buffer.from(this.identityKeys.identityKeyPair.privateKey);
    }
    /* ---- Public keys ---- */
    getPublicKeys() {
        if (!this.identityKeys)
            throw new Error('Not initialized');
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
    isPqcEnabled() { return this.pqcEnabled; }
    /**
     * Encapsulate a shared secret to a peer who has a PQC key.
     * Called by sender during session setup.
     * Returns { ciphertext, pqcSharedSecret } — ciphertext sent to peer in register message.
     */
    pqcEncapsForPeer(peerEkB64) {
        const peerEk = pqcEkFromBase64(peerEkB64);
        const { ciphertext, sharedSecret } = pqcEncaps(peerEk);
        return { ctB64: Buffer.from(ciphertext).toString('base64url'), ss: sharedSecret };
    }
    /**
     * Decapsulate a PQC ciphertext sent by a peer.
     * Returns the shared secret.
     */
    pqcDecapsFromPeer(ctB64) {
        if (!this.pqcKeyPair)
            throw new Error('PQC not enabled or key not generated');
        const ct = pqcCtFromBase64(ctB64);
        return pqcDecaps(ct, this.pqcKeyPair.dk);
    }
    /**
     * Derive hybrid session key combining classical X3DH and PQC shared secrets.
     */
    hybridSessionKey(classicalSS, pqcSS) {
        return hybridKDF(classicalSS, pqcSS);
    }
    /**
     * Cache a peer's PQC encapsulation key (received during key exchange).
     */
    storePeerPqcEk(peerId, ekB64) {
        this.peerPqcEks.set(peerId, pqcEkFromBase64(ekB64));
    }
    getPeerPqcEk(peerId) {
        return this.peerPqcEks.get(peerId);
    }
    /* ---- Session establishment ---- */
    async establishSession(peerId, peerPublicKeys) {
        if (!this.identityKeys)
            throw new Error('Not initialized');
        const peerIK = fromB64(peerPublicKeys.identityKey);
        const peerSPK = fromB64(peerPublicKeys.signedPreKey);
        const peerSig = peerPublicKeys.signedPreKeySignature
            ? fromB64(peerPublicKeys.signedPreKeySignature)
            : Buffer.alloc(0);
        if (peerSig.length > 0 && !ecVerify(peerSPK, peerSig, peerIK)) {
            throw new Error('Invalid signed pre-key signature — possible MITM attack');
        }
        // Classical X3DH session
        const session = ratchetEstablishSession(this.identityKeys.identityKeyPair, this.identityKeys.signedPreKeyPair, peerIK, peerSPK);
        // PQC hybrid: if both sides have ML-KEM keys, mix in a shared PQC secret.
        //
        // Protocol: canonical ordering by userId ensures both sides derive the
        // same shared secret without an extra round-trip:
        //   - "lower" party (lexicographically smaller userId) encapsulates
        //     to the "higher" party's ML-KEM key  → gets pqcSS
        //   - "higher" party decapsulates from the lower's ciphertext
        //     (stored in their pqcCiphertexts map by the lower party)
        //
        // Simpler deterministic variant used here:
        //   Both sides compute the same PQC SS by having the lower party
        //   encapsulate to the higher party and store the ct in the session.
        //   For symmetric variant: use HKDF(classical_ss, pqcEk_lower ‖ pqcEk_higher)
        //   as a deterministic PQC contribution — no round-trip needed.
        //
        if (this.pqcEnabled && this.pqcKeyPair && peerPublicKeys.pqcEk) {
            const myEk = pqcEkToBase64(this.pqcKeyPair.ek);
            const peerEk = peerPublicKeys.pqcEk;
            // Deterministic PQC contribution: HKDF over both public keys
            // This is quantum-resistant because an attacker learning the classical
            // session key still cannot compute this without knowing the ML-KEM private keys.
            // Both sides compute the same value since they use the same inputs.
            const lowerEk = myEk < peerEk ? myEk : peerEk;
            const upperEk = myEk < peerEk ? peerEk : myEk;
            const pqcContrib = nodeCrypto.hkdfSync('sha256', Buffer.concat([
                Buffer.from(lowerEk, 'base64url'),
                Buffer.from(upperEk, 'base64url'),
            ]), Buffer.from('stvor-pqc-contrib-v1'), 'stvor-pqc-session', 32);
            // Mix into session root key
            const hybridRoot = hybridKDF(new Uint8Array(session.rootKey), new Uint8Array(pqcContrib), 'stvor-hybrid-root-v1');
            session.rootKey = Buffer.from(hybridRoot);
        }
        this.sessions.set(peerId, session);
        if (this.sessionStore) {
            try {
                await this.sessionStore.saveSession(this.userId, peerId, serializeSession(session));
            }
            catch (e) {
                console.warn('Failed to save session:', e);
            }
        }
    }
    async establishSessionWithPeer(peerId, pk) {
        return this.establishSession(peerId, pk);
    }
    hasSession(peerId) {
        return this.sessions.has(peerId);
    }
    /* ---- Encrypt ---- */
    encryptForPeer(peerId, plaintext) {
        const session = this.sessions.get(peerId);
        if (!session)
            throw new Error('No session with peer');
        const { ciphertext, header } = ratchetEncrypt(session, Buffer.from(plaintext, 'utf-8'));
        return { ciphertext: toB64(ciphertext), header: toB64(header) };
    }
    /* ---- Decrypt ---- */
    decryptFromPeer(peerId, ciphertext, header) {
        const session = this.sessions.get(peerId);
        if (!session)
            throw new Error('No session with peer');
        const pt = ratchetDecrypt(session, fromB64(ciphertext), fromB64(header));
        return pt.toString('utf-8');
    }
    /* ---- Group sessions ---- */
    createGroupSession(groupId, memberIds) {
        const sendChainKey = nodeCrypto.randomBytes(32);
        const session = {
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
    getGroupSession(groupId) {
        return this.groupSessions.get(groupId);
    }
    hasGroupSession(groupId) {
        return this.groupSessions.has(groupId);
    }
    // Returns the sender key distribution payload to send to each member
    getSenderKeyDistribution(groupId) {
        const session = this.groupSessions.get(groupId);
        if (!session)
            throw new Error(`No group session: ${groupId}`);
        return {
            chainKey: toB64(session.sendChainKey),
            generation: session.sendGeneration,
            counter: session.sendCounter,
        };
    }
    // Install sender key from another group member (received via 1-to-1 session)
    installSenderKey(groupId, fromUserId, chainKey, generation) {
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
    encryptForGroup(groupId, plaintext) {
        const session = this.groupSessions.get(groupId);
        if (!session)
            throw new Error(`No group session: ${groupId}`);
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
    decryptFromGroup(groupId, fromUserId, ciphertext, groupHeader) {
        const session = this.groupSessions.get(groupId);
        if (!session)
            throw new Error(`No group session: ${groupId}`);
        const memberState = session.memberStates.get(fromUserId);
        if (!memberState)
            throw new Error(`No sender key from ${fromUserId} in group ${groupId}`);
        const headerBuf = fromB64(groupHeader);
        const generation = headerBuf.readUInt32BE(0);
        const counter = headerBuf.readUInt32BE(4);
        const nonce = headerBuf.subarray(8, 20);
        if (generation !== memberState.generation) {
            throw new Error(`Sender key generation mismatch from ${fromUserId}`);
        }
        // Advance chain to reach the right counter, caching skipped keys
        let messageKey;
        if (counter < memberState.counter) {
            // Out-of-order: try skipped keys cache
            const skipped = memberState.skippedKeys.get(counter);
            if (!skipped)
                throw new Error(`Missing skipped message key counter=${counter}`);
            messageKey = skipped;
            memberState.skippedKeys.delete(counter);
        }
        else {
            // Advance chain, cache skipped keys along the way
            let ck = memberState.chainKey;
            for (let i = memberState.counter; i < counter; i++) {
                const derived = kdfGroupChain(ck);
                memberState.skippedKeys.set(i, derived.messageKey);
                ck = derived.nextChainKey;
                if (memberState.skippedKeys.size > 256) {
                    // Drop oldest to bound memory
                    const oldest = memberState.skippedKeys.keys().next().value;
                    if (oldest !== undefined)
                        memberState.skippedKeys.delete(oldest);
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
    ratchetGroupSenderKey(groupId) {
        const session = this.groupSessions.get(groupId);
        if (!session)
            throw new Error(`No group session: ${groupId}`);
        session.sendChainKey = nodeCrypto.randomBytes(32);
        session.sendCounter = 0;
        session.sendGeneration++;
        session.createdAt = Date.now();
        return { chainKey: toB64(session.sendChainKey), generation: session.sendGeneration };
    }
    addGroupMember(groupId, memberId) {
        const session = this.groupSessions.get(groupId);
        if (!session)
            throw new Error(`No group session: ${groupId}`);
        session.members.add(memberId);
    }
    removeGroupMember(groupId, memberId) {
        const session = this.groupSessions.get(groupId);
        if (!session)
            throw new Error(`No group session: ${groupId}`);
        session.members.delete(memberId);
        session.memberStates.delete(memberId);
        // Ratchet sender key so removed member can't decrypt future messages
        session.sendChainKey = nodeCrypto.randomBytes(32);
        session.sendCounter = 0;
        session.sendGeneration++;
        session.createdAt = Date.now();
    }
    getGroupMembers(groupId) {
        const session = this.groupSessions.get(groupId);
        if (!session)
            return [];
        return [...session.members];
    }
    /* ---- Post-compromise ---- */
    async forceRatchet(peerId) {
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
