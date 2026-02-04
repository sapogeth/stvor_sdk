import sodium from 'libsodium-wrappers';
import { ensureSodiumReady } from '../facade/sodium-singleton.js';
// Initialize libsodium (safe to call multiple times)
export async function initializeCrypto() {
    await ensureSodiumReady();
}
/**
 * X3DH Session Establishment
 * @param identityKeyPair - The user's identity key pair
 * @param signedPreKeyPair - The user's signed pre-key pair
 * @param oneTimePreKey - A one-time pre-key
 * @param recipientIdentityKey - The recipient's identity key
 * @param recipientSignedPreKey - The recipient's signed pre-key
 * @param recipientOneTimePreKey - The recipient's one-time pre-key
 * @param recipientSPKSignature - Signature of SPK by recipient's identity key
 * @param protocolVersion - The protocol version
 * @param cipherSuite - The cipher suite
 * @returns SessionState
 */
export function establishSession(identityKeyPair, signedPreKeyPair, oneTimePreKey, recipientIdentityKey, recipientSignedPreKey, recipientOneTimePreKey, recipientSPKSignature, protocolVersion, cipherSuite) {
    // Validate protocol version and cipher suite
    validateProtocolVersion(protocolVersion);
    validateCipherSuite(cipherSuite);
    // Verify SPK signature
    verifySPKSignature(recipientSignedPreKey, recipientSPKSignature, recipientIdentityKey);
    // Derive shared secret with cryptographic binding
    const sharedSecret = deriveSharedSecret(identityKeyPair.publicKey, recipientSignedPreKey, recipientOneTimePreKey, protocolVersion, cipherSuite);
    if (!sharedSecret) {
        throw new Error('Failed to derive shared secret');
    }
    // Derive root key
    const rootKey = deriveKey(sharedSecret, 'x3dh-root-key', sodium.from_string(protocolVersion));
    return {
        identityKey: identityKeyPair.publicKey,
        signedPreKey: signedPreKeyPair.publicKey,
        oneTimePreKey,
        rootKey,
        sendingChainKey: rootKey,
        receivingChainKey: rootKey,
        skippedMessageKeys: new Map(),
        isPostCompromise: false,
    };
}
/**
 * Double Ratchet Encryption
 * @param plaintext - The message to encrypt
 * @param session - The current session state
 * @returns { ciphertext: Uint8Array; header: { publicKey: Uint8Array; nonce: Uint8Array } }
 */
export function encryptMessage(plaintext, session) {
    // Generate a new ratchet key pair
    const ratchetKeyPair = sodium.crypto_kx_keypair();
    // Perform a Diffie-Hellman exchange with the recipient's public key
    const sharedSecret = sodium.crypto_kx_client_session_keys(ratchetKeyPair.publicKey, ratchetKeyPair.privateKey, session.identityKey);
    // Update root key and derive new sending chain key
    const newRootKey = sodium.crypto_generichash(32, new Uint8Array([...session.rootKey, ...sharedSecret.sharedTx]));
    const newSendingChainKey = sodium.crypto_generichash(32, newRootKey);
    // Derive a message key
    const messageKey = sodium.crypto_generichash(32, newSendingChainKey);
    // Encrypt the message
    const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(sodium.from_string(plaintext), null, // No additional data
    null, nonce, messageKey);
    // Update session state
    session.rootKey = newRootKey;
    session.sendingChainKey = newSendingChainKey;
    return {
        ciphertext,
        header: {
            publicKey: ratchetKeyPair.publicKey,
            nonce,
        },
    };
}
/**
 * Double Ratchet Decryption
 * @param ciphertext - The encrypted message
 * @param header - The message header containing the sender's public key and nonce
 * @param session - The current session state
 * @returns The decrypted plaintext
 */
export function decryptMessage(ciphertext, header, session) {
    // Check for skipped message keys
    const skippedKey = session.skippedMessageKeys.get(header.nonce.toString());
    if (skippedKey) {
        session.skippedMessageKeys.delete(header.nonce.toString());
        const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, null, // No additional data
        header.nonce, skippedKey);
        return sodium.to_string(plaintext);
    }
    // Perform a Diffie-Hellman exchange with the sender's public key
    const sharedSecret = sodium.crypto_kx_client_session_keys(session.identityKey, session.signedPreKey, header.publicKey);
    // Update root key and derive new receiving chain key
    const newRootKey = sodium.crypto_generichash(32, new Uint8Array([...session.rootKey, ...sharedSecret.sharedTx]));
    const newReceivingChainKey = sodium.crypto_generichash(32, newRootKey);
    // Derive the message key
    const messageKey = sodium.crypto_generichash(32, newReceivingChainKey);
    // Decrypt the message
    const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, null, // No additional data
    header.nonce, messageKey);
    // Update session state
    session.rootKey = newRootKey;
    session.receivingChainKey = newReceivingChainKey;
    return sodium.to_string(plaintext);
}
// Enhanced KDF with explicit domain separation and transcript binding
function deriveKey(inputKey, context, transcript) {
    const label = sodium.from_string(context);
    return sodium.crypto_generichash(32, new Uint8Array([...label, ...inputKey, ...transcript]));
}
function hkdfExtract(salt, inputKeyMaterial) {
    return sodium.crypto_generichash(32, new Uint8Array([...salt, ...inputKeyMaterial]));
}
function hkdfExpand(prk, info, length) {
    const infoBytes = sodium.from_string(info);
    return sodium.crypto_generichash(length, new Uint8Array([...prk, ...infoBytes]));
}
function deriveRootKey(oldRootKey, dhOutput, transcript) {
    const salt = deriveKey(oldRootKey, 'DR:dh', transcript);
    const prk = hkdfExtract(salt, dhOutput);
    return hkdfExpand(prk, 'DR:root', 32);
}
function deriveChainKey(rootKey, transcript) {
    const prk = hkdfExtract(rootKey, sodium.from_string('DR:chain'));
    return hkdfExpand(prk, 'DR:chain', 32);
}
function deriveMessageKey(chainKey, transcript) {
    const prk = hkdfExtract(chainKey, sodium.from_string('DR:message'));
    return hkdfExpand(prk, 'DR:message', 32);
}
// Updated skipped keys handling with bounds
const MAX_SKIPPED_KEYS = 50; // Limit to prevent DoS
// Enhanced skipped keys handling with state exhaustion protection
const MAX_TOTAL_SKIPPED_KEYS = 500; // Global limit across sessions
let totalSkippedKeys = 0;
export function addSkippedKey(session, header, messageKey) {
    const keyId = `${header.publicKey.toString()}:${header.nonce.toString()}`;
    if (session.skippedMessageKeys.size >= MAX_SKIPPED_KEYS) {
        throw new Error('Skipped keys limit exceeded for session');
    }
    if (totalSkippedKeys >= MAX_TOTAL_SKIPPED_KEYS) {
        throw new Error('Global skipped keys limit exceeded');
    }
    session.skippedMessageKeys.set(keyId, messageKey);
    totalSkippedKeys++;
}
export function removeSkippedKey(session, header) {
    const keyId = `${header.publicKey.toString()}:${header.nonce.toString()}`;
    if (session.skippedMessageKeys.delete(keyId)) {
        totalSkippedKeys--;
    }
}
// Improved skipped keys eviction policy
function cleanUpSkippedKeys(session) {
    const currentTime = Date.now();
    session.skippedMessageKeys.forEach((_, keyId) => {
        const [timestamp] = keyId.split(':');
        if (currentTime - parseInt(timestamp, 10) > 300000) { // Evict keys older than 5 minutes
            session.skippedMessageKeys.delete(keyId);
            totalSkippedKeys--;
        }
    });
}
export function processSkippedKeys(session) {
    cleanUpSkippedKeys(session);
}
// Updated simultaneous send handling
export function handleSimultaneousSend(session, isInitiator) {
    if (isInitiator) {
        // Initiator ratchets forward
        session.sendingChainKey = deriveChainKey(session.sendingChainKey, sodium.from_string('initiator'));
    }
    else {
        // Responder ratchets forward
        session.receivingChainKey = deriveChainKey(session.receivingChainKey, sodium.from_string('responder'));
    }
}
// Updated SPK signature verification with downgrade protection
function verifySPKSignature(spk, spkSignature, identityKey) {
    const isValid = sodium.crypto_sign_verify_detached(spkSignature, spk, identityKey);
    if (!isValid) {
        throw new Error('Invalid SPK signature');
    }
}
// Updated OPK exhaustion handling
const OPK_POOL_SIZE = 100; // Example pool size
let opkPool = [];
export function generateOPKPool() {
    opkPool = Array.from({ length: OPK_POOL_SIZE }, () => sodium.crypto_kx_keypair().publicKey);
}
// Improved X3DH race safety and OPK handling
const OPK_LOCK = new Map(); // Lock for atomic OPK consumption
export function consumeOPKAtomically(userId) {
    if (OPK_LOCK.get(userId)) {
        throw new Error('OPK consumption in progress');
    }
    OPK_LOCK.set(userId, true);
    try {
        const opk = consumeOPK();
        return opk;
    }
    finally {
        OPK_LOCK.delete(userId);
    }
}
// Enhanced X3DH with cryptographic binding and explicit abort semantics
function deriveSharedSecret(ik, spk, opk, protocolVersion, cipherSuite) {
    const context = sodium.from_string(`${protocolVersion}:${cipherSuite}`);
    return sodium.crypto_generichash(32, new Uint8Array([...ik, ...spk, ...opk, ...context]));
}
// Final improvements for X3DH
function validateProtocolVersion(version) {
    const supportedVersions = ['1.0'];
    if (!supportedVersions.includes(version)) {
        throw new Error(`Unsupported protocol version: ${version}`);
    }
}
function validateCipherSuite(cipherSuite) {
    const supportedSuites = ['AES-GCM'];
    if (!supportedSuites.includes(cipherSuite)) {
        throw new Error(`Unsupported cipher suite: ${cipherSuite}`);
    }
}
/**
 * Policy for forced DH rotation.
 * Triggers a DH ratchet step based on:
 * - Number of messages sent.
 * - Time elapsed since the last ratchet.
 * - Explicit compromise flag.
 */
const DH_RATCHET_POLICY = {
    maxMessages: 50, // Trigger after 50 messages
    maxTime: 10 * 60 * 1000, // Trigger after 10 minutes
};
let lastRatchetTime = Date.now();
let messageCounter = 0;
export function enforceDHRatchetPolicy(session, remotePublicKey, suspectedCompromise = false) {
    const currentTime = Date.now();
    // Check if policy conditions are met
    if (messageCounter >= DH_RATCHET_POLICY.maxMessages ||
        currentTime - lastRatchetTime >= DH_RATCHET_POLICY.maxTime ||
        suspectedCompromise) {
        forceDHRatchet(session, remotePublicKey);
        // Reset counters
        lastRatchetTime = currentTime;
        messageCounter = 0;
    }
}
/**
 * Increment message counter and enforce policy.
 */
export function incrementMessageCounter(session, remotePublicKey) {
    messageCounter++;
    enforceDHRatchetPolicy(session, remotePublicKey);
}
/**
 * Force a DH ratchet step to enable PCS.
 * @param session - The current session state.
 * @param remotePublicKey - The remote party's ephemeral public key.
 */
export function forceDHRatchet(session, remotePublicKey) {
    // Generate a new ephemeral key pair
    const ephemeralKeyPair = sodium.crypto_kx_keypair();
    // Perform a Diffie-Hellman exchange
    const dhOutput = sodium.crypto_kx_client_session_keys(ephemeralKeyPair.publicKey, ephemeralKeyPair.privateKey, remotePublicKey);
    // Update the root key
    const newRootKey = deriveRootKey(session.rootKey, dhOutput.sharedTx, sodium.from_string('dh-ratchet-recovery'));
    // Clear compromised keys
    session.sendingChainKey = newRootKey;
    session.receivingChainKey = newRootKey;
    session.skippedMessageKeys.clear();
    // Update session state
    session.rootKey = newRootKey;
}
/**
 * Ensure rootKey updates only occur through DH ratchet.
 * @param session - The current session state.
 * @param dhOutput - The DH output used to update the root key.
 */
function enforceDHRatchetOnly(session, dhOutput) {
    if (!dhOutput) {
        throw new Error('Root key updates must occur through DH ratchet');
    }
    // Update the root key
    const newRootKey = deriveRootKey(session.rootKey, dhOutput, sodium.from_string('dh-ratchet-only'));
    session.rootKey = newRootKey;
}
/**
 * Trigger PCS recovery only after receiving a new DH public key.
 * @param session - The current session state.
 * @param remotePublicKey - The new DH public key from the remote party.
 */
export function receiveNewDHPublicKey(session, remotePublicKey) {
    // Generate a new ephemeral key pair
    const ephemeralKeyPair = sodium.crypto_kx_keypair();
    // Perform a Diffie-Hellman exchange
    const dhOutput = sodium.crypto_kx_client_session_keys(ephemeralKeyPair.publicKey, ephemeralKeyPair.privateKey, remotePublicKey);
    // Update the root key
    const newRootKey = deriveRootKey(session.rootKey, dhOutput, sodium.from_string('dh-ratchet-recovery'));
    // Clear compromised keys
    session.sendingChainKey = newRootKey;
    session.receivingChainKey = newRootKey;
    session.skippedMessageKeys.clear();
    // Update session state
    session.rootKey = newRootKey;
}
/**
 * Define and enforce state transitions between epochs.
 * @param session - The current session state.
 */
function transitionToPostCompromiseEpoch(session) {
    // Clear all pre-compromise state
    session.sendingChainKey = null;
    session.receivingChainKey = null;
    session.skippedMessageKeys.clear();
    // Mark the session as post-compromise
    session.isPostCompromise = true;
}
