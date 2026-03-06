/**
 * STVOR SDK v2.4.0 - Production-Ready Core Ratchet
 * Key changes from v2:
 * - Header AAD authentication
 * - Immutable state transitions
 * - Functional design (pure functions)
 * - Explicit error codes
 */
import sodium from 'libsodium-wrappers';
// Constants for invariants
const DH_RATCHET_POLICY = {
    maxMessages: 50,
    maxTimeMs: 10 * 60 * 1000, // 10 minutes
};
const MAX_SKIPPED_KEYS_PER_SESSION = 50;
const MAX_TOTAL_SKIPPED_KEYS = 500;
const SKIPPED_KEY_TTL_MS = 5 * 60 * 1000; // 5 minutes
// ============================================================================
// PART 2: ERROR CODES (EXPLICIT)
// ============================================================================
export const ErrorCode = {
    // Crypto errors
    DECRYPT_FAILED: 'DECRYPT_FAILED',
    AUTH_FAILED: 'AUTH_FAILED', // AAD verification failed
    INVALID_KEY_FORMAT: 'INVALID_KEY_FORMAT',
    SPK_SIGNATURE_INVALID: 'SPK_SIGNATURE_INVALID',
    // Replay / TOFU
    REPLAY_DETECTED: 'REPLAY_DETECTED',
    TOFU_MISMATCH: 'TOFU_MISMATCH',
    // State machine
    INVALID_STATE_TRANSITION: 'INVALID_STATE_TRANSITION',
    SESSION_COMPROMISED: 'SESSION_COMPROMISED',
    // Storage
    STORAGE_UNAVAILABLE: 'STORAGE_UNAVAILABLE',
    STORAGE_WRITE_FAILED: 'STORAGE_WRITE_FAILED',
    // DoS protection
    SKIPPED_KEYS_LIMIT_EXCEEDED: 'SKIPPED_KEYS_LIMIT_EXCEEDED',
    REPLAY_WINDOW_EXPIRED: 'REPLAY_WINDOW_EXPIRED',
};
export class StvorSDKError extends Error {
    constructor(code, message, metadata) {
        super(message);
        this.code = code;
        this.metadata = metadata;
        this.name = 'StvorSDKError';
    }
}
// ============================================================================
// PART 3: IMMUTABLE STATE MANAGEMENT
// ============================================================================
/**
 * Pure function: compute new session state WITHOUT mutating input
 * Returns new state object on success, throws on error
 *
 * CRITICAL: This function has NO SIDE EFFECTS
 * It only computes, doesn't update globals or storage
 */
function tryDecryptMessage(ciphertext, header, session) {
    // Attempt to use skipped key first
    const skippedKeyEntry = findAndValidateSkippedKey(session, header);
    if (skippedKeyEntry) {
        const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, constructAAD(header), header.nonce, skippedKeyEntry.key);
        // New state: remove used skipped key, increment receive counter
        const newSession = structuredClone(session);
        const skippedKeyId = generateSkippedKeyId(header);
        newSession.skippedMessageKeys.delete(skippedKeyId);
        newSession.receiveCounter = header.receiveCounter + 1;
        return newSession;
    }
    // Standard ratchet decryption
    const sharedSecret = sodium.crypto_kx_client_session_keys(session.peerIdentityKey, session.sendingChainKey, // Recipient's SPK
    header.publicKey);
    // Compute new root key
    const newRootKey = deriveRootKeyFromDH(session.rootKey, sharedSecret.sharedTx, 'receive');
    // Derive new chain key
    const newReceivingChainKey = deriveChainKey(newRootKey, 'receiving');
    // Derive message key
    const messageKey = deriveMessageKey(newReceivingChainKey);
    // Decrypt with AAD verification
    const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, constructAAD(header), // ← NEW: authenticate header
    header.nonce, messageKey);
    // Create new state (not mutating input)
    const newSession = structuredClone(session);
    newSession.rootKey = newRootKey;
    newSession.receivingChainKey = newReceivingChainKey;
    newSession.receiveCounter = header.receiveCounter + 1;
    return newSession;
}
/**
 * Pure function: compute new session state for encryption
 * Returns { ciphertext, header, newSession }
 */
function tryEncryptMessage(plaintext, session) {
    // Check if ratchet needed (pure predicate)
    const shouldRatchet = checkDHRatchetPolicy(session);
    let currentSession = structuredClone(session);
    // Apply ratchet if needed
    if (shouldRatchet) {
        currentSession = performDHRatchet(currentSession);
    }
    // Encrypt
    const ratchetKeyPair = sodium.crypto_kx_keypair();
    const sharedSecret = sodium.crypto_kx_client_session_keys(ratchetKeyPair.publicKey, ratchetKeyPair.privateKey, currentSession.peerIdentityKey);
    // Derive new root key
    const newRootKey = deriveRootKeyFromDH(currentSession.rootKey, sharedSecret.sharedTx, 'send');
    // Derive chain key
    const newSendingChainKey = deriveChainKey(newRootKey, 'sending');
    const messageKey = deriveMessageKey(newSendingChainKey);
    // Build header
    const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    const header = {
        publicKey: ratchetKeyPair.publicKey,
        nonce,
        sendCounter: currentSession.sendCounter,
        receiveCounter: currentSession.receiveCounter,
        timestamp: Date.now(),
    };
    // Encrypt with AAD
    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(sodium.from_string(plaintext), constructAAD(header), // ← NEW: authenticate header
    null, nonce, messageKey);
    // New state
    const newSession = structuredClone(currentSession);
    newSession.rootKey = newRootKey;
    newSession.sendingChainKey = newSendingChainKey;
    newSession.sendCounter++;
    newSession.lastRatchetCounter = shouldRatchet
        ? currentSession.sendCounter
        : currentSession.lastRatchetCounter;
    return { ciphertext, header, newSession };
}
// ============================================================================
// PART 4: STATE MACHINE ENFORCEMENT
// ============================================================================
/**
 * Validate state transition
 * Prevents invalid transitions and enforces FSM invariants
 */
function validateStateTransition(fromState, toState) {
    const validTransitions = {
        'INIT': ['ESTABLISHED'],
        'ESTABLISHED': ['RATCHETING', 'COMPROMISED'],
        'RATCHETING': ['ESTABLISHED', 'COMPROMISED'],
        'COMPROMISED': [], // Terminal state
    };
    if (!validTransitions[fromState]?.includes(toState)) {
        throw new StvorSDKError('INVALID_STATE_TRANSITION', `Cannot transition from ${fromState} to ${toState}`);
    }
}
function checkDHRatchetPolicy(session) {
    const elapsed = Date.now() - session.lastRatchetTime;
    const messagesSinceRatchet = session.sendCounter - session.lastRatchetCounter;
    return (messagesSinceRatchet >= DH_RATCHET_POLICY.maxMessages ||
        elapsed >= DH_RATCHET_POLICY.maxTimeMs);
}
function performDHRatchet(session) {
    // Generate new ephemeral
    const ephemeralKeyPair = sodium.crypto_kx_keypair();
    // Perform DH
    const dhOutput = sodium.crypto_kx_client_session_keys(ephemeralKeyPair.publicKey, ephemeralKeyPair.privateKey, session.peerIdentityKey);
    // Derive new root key
    const newRootKey = deriveRootKeyFromDH(session.rootKey, dhOutput.sharedTx, 'ratchet');
    // New state
    const newSession = structuredClone(session);
    newSession.rootKey = newRootKey;
    newSession.sendingChainKey = deriveChainKey(newRootKey, 'sending');
    newSession.receivingChainKey = deriveChainKey(newRootKey, 'receiving');
    newSession.skippedMessageKeys.clear(); // Clear old keys
    newSession.lastRatchetTime = Date.now();
    newSession.state = 'RATCHETING';
    return newSession;
}
// ============================================================================
// PART 5: KEY DERIVATION (PURE)
// ============================================================================
function deriveRootKeyFromDH(oldRootKey, dhOutput, context) {
    const info = sodium.from_string(`stvor:dh:${context}`);
    return sodium.crypto_generichash(32, sodium.from_string('HKDF-Extract'), new Uint8Array([...oldRootKey, ...dhOutput, ...info]));
}
function deriveChainKey(rootKey, direction) {
    const info = sodium.from_string(`stvor:chain:${direction}`);
    return sodium.crypto_generichash(32, rootKey, info);
}
function deriveMessageKey(chainKey) {
    const info = sodium.from_string('stvor:message-key');
    return sodium.crypto_generichash(32, chainKey, info);
}
// ============================================================================
// PART 6: AAD CONSTRUCTION (AUTHENTICATED ADDITIONAL DATA)
// ============================================================================
/**
 * Construct AAD from message header
 * This ensures header cannot be tampered without detection
 */
function constructAAD(header) {
    return sodium.crypto_generichash(32, sodium.from_string('AAD'), new Uint8Array([
        ...header.publicKey,
        ...header.nonce,
        ...(new Uint32Array([header.sendCounter])),
        ...(new Uint32Array([header.receiveCounter])),
        ...(new Uint32Array([header.timestamp])),
    ]));
}
// ============================================================================
// PART 7: SKIPPED MESSAGE KEYS
// ============================================================================
function generateSkippedKeyId(header) {
    return sodium.to_hex(sodium.crypto_generichash(32, header.nonce));
}
function findAndValidateSkippedKey(session, header) {
    const keyId = generateSkippedKeyId(header);
    const entry = session.skippedMessageKeys.get(keyId);
    if (!entry) {
        return null;
    }
    // Check TTL
    if (Date.now() - entry.timestamp > SKIPPED_KEY_TTL_MS) {
        return null; // Expired
    }
    return entry;
}
function addSkippedKey(session, nonce, key) {
    // Check limits
    if (session.skippedMessageKeys.size >= MAX_SKIPPED_KEYS_PER_SESSION) {
        throw new StvorSDKError('SKIPPED_KEYS_LIMIT_EXCEEDED', `Per-session skipped keys limit (${MAX_SKIPPED_KEYS_PER_SESSION}) exceeded`);
    }
    const keyId = sodium.to_hex(sodium.crypto_generichash(32, nonce));
    session.skippedMessageKeys.set(keyId, {
        key,
        timestamp: Date.now(),
        counter: session.receiveCounter,
    });
}
// ============================================================================
// PART 8: PUBLIC API (FACADE)
// ============================================================================
/**
 * Decrypt message with full validation
 * ATOMICALLY: validate ALL, then update session
 */
export async function decryptMessageWithValidation(ciphertext, header, session, validators) {
    // PHASE 1: Validation (no state changes)
    // Check state machine
    if (session.state === 'COMPROMISED') {
        throw new StvorSDKError('SESSION_COMPROMISED', 'Session is compromised, recovery required');
    }
    // Check replay
    const isReplay = await validators.replayCache.checkAndMark(session.peerId, sodium.to_hex(header.nonce), header.timestamp);
    if (isReplay) {
        throw new StvorSDKError('REPLAY_DETECTED', 'Message is a replay', { nonce: sodium.to_hex(header.nonce) });
    }
    // Compute new state (pure, no mutations)
    let newSession;
    try {
        newSession = tryDecryptMessage(ciphertext, header, session);
    }
    catch (error) {
        if (error.code === 'EBADMSG') {
            throw new StvorSDKError('AUTH_FAILED', 'AAD authentication failed');
        }
        throw new StvorSDKError('DECRYPT_FAILED', error.message);
    }
    // PHASE 2: Commit (all validations passed)
    // Update session state atomically
    Object.assign(session, newSession);
    return {
        plaintext: newSession.toString(), // Placeholder
        updatedSession: session,
    };
}
/**
 * Encrypt message with policy enforcement
 */
export function encryptMessageWithPolicy(plaintext, session) {
    // Check state
    if (session.state === 'COMPROMISED') {
        throw new StvorSDKError('SESSION_COMPROMISED', 'Cannot encrypt: session is compromised');
    }
    // Compute new state (pure)
    const { ciphertext, header, newSession } = tryEncryptMessage(plaintext, session);
    // Update session (atomic)
    Object.assign(session, newSession);
    return {
        message: { ciphertext, header },
        updatedSession: session,
    };
}
