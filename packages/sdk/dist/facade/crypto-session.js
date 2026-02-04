/**
 * STVOR Crypto Session Manager
 * Integrates X3DH + Double Ratchet from ratchet module
 *
 * CRITICAL: Identity keys generated ONCE per userId
 * Currently in-memory only - keys lost on restart
 *
 * TODO: Add persistent storage (IndexedDB/Keychain)
 */
import sodium from 'libsodium-wrappers';
import { ensureSodiumReady } from './sodium-singleton.js';
import { encryptMessage as ratchetEncrypt, decryptMessage as ratchetDecrypt, incrementMessageCounter, } from '../ratchet/index.js';
/**
 * Manages cryptographic sessions for all peers
 */
export class CryptoSessionManager {
    constructor(userId) {
        this.identityKeys = null;
        this.sessions = new Map();
        this.initialized = false;
        this.initPromise = null;
        this.userId = userId;
    }
    /**
     * Initialize libsodium and generate identity keys
     * RACE CONDITION SAFE: Returns same promise if called concurrently
     */
    async initialize() {
        // Already initialized
        if (this.initialized && this.identityKeys) {
            return;
        }
        // Initialization in progress - return existing promise
        if (this.initPromise) {
            return this.initPromise;
        }
        // Start initialization
        this.initPromise = this._doInitialize();
        return this.initPromise;
    }
    async _doInitialize() {
        // Ensure libsodium ready (singleton - safe to call multiple times)
        await ensureSodiumReady();
        // CRITICAL: Check again after await (another call might have completed)
        if (this.initialized && this.identityKeys) {
            return;
        }
        // Generate long-term identity key pair (Ed25519 for signing)
        const identityKeyPair = sodium.crypto_sign_keypair();
        // Generate semi-ephemeral signed pre-key (X25519 for DH)
        const signedPreKeyPair = sodium.crypto_kx_keypair();
        // Generate pool of one-time pre-keys
        const oneTimePreKeys = [];
        for (let i = 0; i < 10; i++) {
            const keypair = sodium.crypto_kx_keypair();
            oneTimePreKeys.push(keypair.publicKey);
        }
        this.identityKeys = {
            identityKeyPair: {
                publicKey: identityKeyPair.publicKey,
                privateKey: identityKeyPair.privateKey,
            },
            signedPreKeyPair: {
                publicKey: signedPreKeyPair.publicKey,
                privateKey: signedPreKeyPair.privateKey,
            },
            oneTimePreKeys,
        };
        this.initialized = true;
        this.initPromise = null;
        console.log(`[Crypto] Identity keys generated for ${this.userId}`);
    }
    /**
     * Get serialized public keys for relay registration
     */
    getPublicKeys() {
        if (!this.identityKeys) {
            throw new Error('CryptoSessionManager not initialized');
        }
        // Sign the pre-key
        const signedPreKeySignature = sodium.crypto_sign_detached(this.identityKeys.signedPreKeyPair.publicKey, this.identityKeys.identityKeyPair.privateKey);
        return {
            identityKey: sodium.to_base64(this.identityKeys.identityKeyPair.publicKey),
            signedPreKey: sodium.to_base64(this.identityKeys.signedPreKeyPair.publicKey),
            signedPreKeySignature: sodium.to_base64(signedPreKeySignature),
            oneTimePreKey: sodium.to_base64(this.identityKeys.oneTimePreKeys[0] || new Uint8Array(32)),
        };
    }
    /**
     * Establish session with peer (X3DH handshake)
     */
    async establishSessionWithPeer(peerId, peerPublicKeys) {
        if (!this.identityKeys) {
            throw new Error('CryptoSessionManager not initialized');
        }
        // Skip if session already exists
        if (this.sessions.has(peerId)) {
            return;
        }
        // Deserialize peer's public keys
        const recipientIdentityKey = sodium.from_base64(peerPublicKeys.identityKey);
        const recipientSignedPreKey = sodium.from_base64(peerPublicKeys.signedPreKey);
        const recipientSPKSignature = sodium.from_base64(peerPublicKeys.signedPreKeySignature);
        const recipientOneTimePreKey = sodium.from_base64(peerPublicKeys.oneTimePreKey);
        // Verify SPK signature
        const isValid = sodium.crypto_sign_verify_detached(recipientSPKSignature, recipientSignedPreKey, recipientIdentityKey);
        if (!isValid) {
            throw new Error(`Invalid SPK signature for peer ${peerId}`);
        }
        // Perform X3DH to derive shared secret
        const dh1 = sodium.crypto_scalarmult(this.identityKeys.signedPreKeyPair.privateKey, recipientSignedPreKey);
        const dh2 = sodium.crypto_scalarmult(this.identityKeys.identityKeyPair.privateKey, recipientOneTimePreKey);
        const dh3 = sodium.crypto_scalarmult(this.identityKeys.signedPreKeyPair.privateKey, recipientOneTimePreKey);
        // Combine DH outputs
        const sharedSecret = sodium.crypto_generichash(32, new Uint8Array([...dh1, ...dh2, ...dh3]));
        // Derive root key
        const rootKey = sodium.crypto_generichash(32, new Uint8Array([
            ...sharedSecret,
            ...sodium.from_string('x3dh-root-key-v1'),
        ]));
        // Create initial session state
        const session = {
            identityKey: this.identityKeys.identityKeyPair.publicKey,
            signedPreKey: this.identityKeys.signedPreKeyPair.publicKey,
            oneTimePreKey: this.identityKeys.oneTimePreKeys[0] || new Uint8Array(32),
            rootKey,
            sendingChainKey: rootKey,
            receivingChainKey: rootKey,
            skippedMessageKeys: new Map(),
            isPostCompromise: false,
        };
        this.sessions.set(peerId, session);
    }
    /**
     * Encrypt message for peer using Double Ratchet
     */
    async encryptForPeer(peerId, plaintext) {
        const session = this.sessions.get(peerId);
        if (!session) {
            throw new Error(`No session with peer ${peerId}`);
        }
        // Encrypt using Double Ratchet
        const result = ratchetEncrypt(plaintext, session);
        // Enforce DH ratchet policy (Forward Secrecy + PCS)
        const recipientKey = session.identityKey;
        incrementMessageCounter(session, recipientKey);
        return result;
    }
    /**
     * Decrypt message from peer using Double Ratchet
     */
    async decryptFromPeer(peerId, ciphertext, header) {
        const session = this.sessions.get(peerId);
        if (!session) {
            throw new Error(`No session with peer ${peerId}`);
        }
        // Decrypt using Double Ratchet
        const plaintext = ratchetDecrypt(ciphertext, header, session);
        return plaintext;
    }
    /**
     * Check if session exists with peer
     */
    hasSession(peerId) {
        return this.sessions.has(peerId);
    }
    /**
     * Destroy all sessions (cleanup)
     */
    destroy() {
        this.sessions.clear();
        this.identityKeys = null;
        this.initialized = false;
    }
}
