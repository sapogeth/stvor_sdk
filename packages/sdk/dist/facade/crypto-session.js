/**
 * STVOR Crypto Session Manager
 * Uses ONLY Node.js built-in crypto module — zero external dependencies
 *
 * Manages identity keys (IK + SPK), ECDSA signatures,
 * X3DH session establishment, and Double Ratchet encrypt/decrypt.
 */
import { generateKeyPair, encryptMessage as ratchetEncrypt, decryptMessage as ratchetDecrypt, establishSession as ratchetEstablishSession, serializeSession, initializeCrypto, ecSign, ecVerify, } from '../ratchet/index.js';
/* ================================================================
 * Helpers
 * ================================================================ */
function toB64(buf) { return buf.toString('base64url'); }
function fromB64(s) { return Buffer.from(s, 'base64url'); }
/* ================================================================
 * CryptoSessionManager
 * ================================================================ */
export class CryptoSessionManager {
    constructor(userId, identityStore, sessionStore) {
        this.identityKeys = null;
        this.sessions = new Map();
        this.initialized = false;
        this.initPromise = null;
        this.identityStore = null;
        this.sessionStore = null;
        this.userId = userId;
        this.identityStore = identityStore || null;
        this.sessionStore = sessionStore || null;
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
    /* ---- Public keys ---- */
    getPublicKeys() {
        if (!this.identityKeys)
            throw new Error('Not initialized');
        return {
            identityKey: toB64(this.identityKeys.identityKeyPair.publicKey),
            signedPreKey: toB64(this.identityKeys.signedPreKeyPair.publicKey),
            signedPreKeySignature: toB64(this.identityKeys.signedPreKeySignature),
            oneTimePreKey: '',
        };
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
        const session = ratchetEstablishSession(this.identityKeys.identityKeyPair, this.identityKeys.signedPreKeyPair, peerIK, peerSPK);
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
