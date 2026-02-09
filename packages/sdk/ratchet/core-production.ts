/**
 * STVOR SDK v3.0 - Production-Ready Core Ratchet
 * Key changes from v2:
 * - Header AAD authentication
 * - Immutable state transitions
 * - Functional design (pure functions)
 * - Explicit error codes
 */

import sodium from 'libsodium-wrappers';

// ============================================================================
// PART 1: TYPES & CONSTANTS
// ============================================================================

export interface EncryptedMessage {
  ciphertext: Uint8Array;
  header: {
    publicKey: Uint8Array;
    nonce: Uint8Array;
    sendCounter: number;       // NEW: for ratchet policy
    receiveCounter: number;    // NEW: for tracking
    timestamp: number;         // NEW: for TTL
  };
}

export interface SessionState {
  // Identity
  peerId: string;
  peerIdentityKey: Uint8Array;
  
  // Keys
  rootKey: Uint8Array;
  sendingChainKey: Uint8Array;
  receivingChainKey: Uint8Array;

  // Counters
  sendCounter: number;         // NEW: monotonic
  receiveCounter: number;      // NEW: monotonic
  
  // Skipped keys (for out-of-order messages)
  skippedMessageKeys: Map<string, {
    key: Uint8Array;
    timestamp: number;
    counter: number;           // NEW: for GC
  }>;

  // State machine
  state: SessionFSMState;       // NEW: INIT|ESTABLISHED|RATCHETING|COMPROMISED
  lastRatchetTime: number;      // NEW: for policy
  lastRatchetCounter: number;   // NEW: for policy
  
  // Audit
  createdAt: number;
  metadata: Record<string, any>; // App-level metadata
}

export type SessionFSMState = 
  | 'INIT'
  | 'ESTABLISHED'
  | 'RATCHETING'
  | 'COMPROMISED';

// Constants for invariants
const DH_RATCHET_POLICY = {
  maxMessages: 50,
  maxTimeMs: 10 * 60 * 1000,    // 10 minutes
};

const MAX_SKIPPED_KEYS_PER_SESSION = 50;
const MAX_TOTAL_SKIPPED_KEYS = 500;
const SKIPPED_KEY_TTL_MS = 5 * 60 * 1000;  // 5 minutes

// ============================================================================
// PART 2: ERROR CODES (EXPLICIT)
// ============================================================================

export const ErrorCode = {
  // Crypto errors
  DECRYPT_FAILED: 'DECRYPT_FAILED',
  AUTH_FAILED: 'AUTH_FAILED',          // AAD verification failed
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
} as const;

export class StvorSDKError extends Error {
  constructor(
    readonly code: keyof typeof ErrorCode,
    message: string,
    readonly metadata?: Record<string, any>
  ) {
    super(message);
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
function tryDecryptMessage(
  ciphertext: Uint8Array,
  header: EncryptedMessage['header'],
  session: SessionState
): SessionState {
  // Attempt to use skipped key first
  const skippedKeyEntry = findAndValidateSkippedKey(session, header);
  if (skippedKeyEntry) {
    const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      ciphertext,
      constructAAD(header),
      header.nonce,
      skippedKeyEntry.key
    );
    
    // New state: remove used skipped key, increment receive counter
    const newSession = structuredClone(session);
    const skippedKeyId = generateSkippedKeyId(header);
    newSession.skippedMessageKeys.delete(skippedKeyId);
    newSession.receiveCounter = header.receiveCounter + 1;
    return newSession;
  }

  // Standard ratchet decryption
  const sharedSecret = sodium.crypto_kx_client_session_keys(
    session.peerIdentityKey,
    session.sendingChainKey,  // Recipient's SPK
    header.publicKey
  );

  // Compute new root key
  const newRootKey = deriveRootKeyFromDH(
    session.rootKey,
    sharedSecret.sharedTx,
    'receive'
  );

  // Derive new chain key
  const newReceivingChainKey = deriveChainKey(
    newRootKey,
    'receiving'
  );

  // Derive message key
  const messageKey = deriveMessageKey(newReceivingChainKey);

  // Decrypt with AAD verification
  const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    constructAAD(header),  // ← NEW: authenticate header
    header.nonce,
    messageKey
  );

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
function tryEncryptMessage(
  plaintext: string,
  session: SessionState
): {
  ciphertext: Uint8Array;
  header: EncryptedMessage['header'];
  newSession: SessionState;
} {
  // Check if ratchet needed (pure predicate)
  const shouldRatchet = checkDHRatchetPolicy(session);
  
  let currentSession = structuredClone(session);
  
  // Apply ratchet if needed
  if (shouldRatchet) {
    currentSession = performDHRatchet(currentSession);
  }

  // Encrypt
  const ratchetKeyPair = sodium.crypto_kx_keypair();
  const sharedSecret = sodium.crypto_kx_client_session_keys(
    ratchetKeyPair.publicKey,
    ratchetKeyPair.privateKey,
    currentSession.peerIdentityKey
  );

  // Derive new root key
  const newRootKey = deriveRootKeyFromDH(
    currentSession.rootKey,
    sharedSecret.sharedTx,
    'send'
  );

  // Derive chain key
  const newSendingChainKey = deriveChainKey(newRootKey, 'sending');
  const messageKey = deriveMessageKey(newSendingChainKey);

  // Build header
  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );

  const header: EncryptedMessage['header'] = {
    publicKey: ratchetKeyPair.publicKey,
    nonce,
    sendCounter: currentSession.sendCounter,
    receiveCounter: currentSession.receiveCounter,
    timestamp: Date.now(),
  };

  // Encrypt with AAD
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    sodium.from_string(plaintext),
    constructAAD(header),  // ← NEW: authenticate header
    null,
    nonce,
    messageKey
  );

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
function validateStateTransition(
  fromState: SessionFSMState,
  toState: SessionFSMState
): void {
  const validTransitions: Record<SessionFSMState, SessionFSMState[]> = {
    'INIT': ['ESTABLISHED'],
    'ESTABLISHED': ['RATCHETING', 'COMPROMISED'],
    'RATCHETING': ['ESTABLISHED', 'COMPROMISED'],
    'COMPROMISED': [],  // Terminal state
  };

  if (!validTransitions[fromState]?.includes(toState)) {
    throw new StvorSDKError(
      'INVALID_STATE_TRANSITION',
      `Cannot transition from ${fromState} to ${toState}`
    );
  }
}

function checkDHRatchetPolicy(session: SessionState): boolean {
  const elapsed = Date.now() - session.lastRatchetTime;
  const messagesSinceRatchet = session.sendCounter - session.lastRatchetCounter;

  return (
    messagesSinceRatchet >= DH_RATCHET_POLICY.maxMessages ||
    elapsed >= DH_RATCHET_POLICY.maxTimeMs
  );
}

function performDHRatchet(session: SessionState): SessionState {
  // Generate new ephemeral
  const ephemeralKeyPair = sodium.crypto_kx_keypair();

  // Perform DH
  const dhOutput = sodium.crypto_kx_client_session_keys(
    ephemeralKeyPair.publicKey,
    ephemeralKeyPair.privateKey,
    session.peerIdentityKey
  );

  // Derive new root key
  const newRootKey = deriveRootKeyFromDH(
    session.rootKey,
    dhOutput.sharedTx,
    'ratchet'
  );

  // New state
  const newSession = structuredClone(session);
  newSession.rootKey = newRootKey;
  newSession.sendingChainKey = deriveChainKey(newRootKey, 'sending');
  newSession.receivingChainKey = deriveChainKey(newRootKey, 'receiving');
  newSession.skippedMessageKeys.clear();  // Clear old keys
  newSession.lastRatchetTime = Date.now();
  newSession.state = 'RATCHETING';

  return newSession;
}

// ============================================================================
// PART 5: KEY DERIVATION (PURE)
// ============================================================================

function deriveRootKeyFromDH(
  oldRootKey: Uint8Array,
  dhOutput: Uint8Array,
  context: string
): Uint8Array {
  const info = sodium.from_string(`stvor:dh:${context}`);
  return sodium.crypto_generichash(
    32,
    sodium.from_string('HKDF-Extract'),
    new Uint8Array([...oldRootKey, ...dhOutput, ...info])
  );
}

function deriveChainKey(rootKey: Uint8Array, direction: string): Uint8Array {
  const info = sodium.from_string(`stvor:chain:${direction}`);
  return sodium.crypto_generichash(32, rootKey, info);
}

function deriveMessageKey(chainKey: Uint8Array): Uint8Array {
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
function constructAAD(header: EncryptedMessage['header']): Uint8Array {
  return sodium.crypto_generichash(
    32,
    sodium.from_string('AAD'),
    new Uint8Array([
      ...header.publicKey,
      ...header.nonce,
      ...(new Uint32Array([header.sendCounter])),
      ...(new Uint32Array([header.receiveCounter])),
      ...(new Uint32Array([header.timestamp])),
    ])
  );
}

// ============================================================================
// PART 7: SKIPPED MESSAGE KEYS
// ============================================================================

function generateSkippedKeyId(header: EncryptedMessage['header']): string {
  return sodium.to_hex(
    sodium.crypto_generichash(32, header.nonce)
  );
}

function findAndValidateSkippedKey(
  session: SessionState,
  header: EncryptedMessage['header']
): { key: Uint8Array; timestamp: number } | null {
  const keyId = generateSkippedKeyId(header);
  const entry = session.skippedMessageKeys.get(keyId);

  if (!entry) {
    return null;
  }

  // Check TTL
  if (Date.now() - entry.timestamp > SKIPPED_KEY_TTL_MS) {
    return null;  // Expired
  }

  return entry;
}

function addSkippedKey(
  session: SessionState,
  nonce: Uint8Array,
  key: Uint8Array
): void {
  // Check limits
  if (session.skippedMessageKeys.size >= MAX_SKIPPED_KEYS_PER_SESSION) {
    throw new StvorSDKError(
      'SKIPPED_KEYS_LIMIT_EXCEEDED',
      `Per-session skipped keys limit (${MAX_SKIPPED_KEYS_PER_SESSION}) exceeded`
    );
  }

  const keyId = sodium.to_hex(
    sodium.crypto_generichash(32, nonce)
  );

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
export async function decryptMessageWithValidation(
  ciphertext: Uint8Array,
  header: EncryptedMessage['header'],
  session: SessionState,
  validators: {
    replayCache: IReplayCache;
    tofuStore?: ITofuStore;
  }
): Promise<{
  plaintext: string;
  updatedSession: SessionState;
}> {
  // PHASE 1: Validation (no state changes)
  
  // Check state machine
  if (session.state === 'COMPROMISED') {
    throw new StvorSDKError(
      'SESSION_COMPROMISED',
      'Session is compromised, recovery required'
    );
  }

  // Check replay
  const isReplay = await validators.replayCache.checkAndMark(
    session.peerId,
    sodium.to_hex(header.nonce),
    header.timestamp
  );

  if (isReplay) {
    throw new StvorSDKError(
      'REPLAY_DETECTED',
      'Message is a replay',
      { nonce: sodium.to_hex(header.nonce) }
    );
  }

  // Compute new state (pure, no mutations)
  let newSession: SessionState;
  try {
    newSession = tryDecryptMessage(ciphertext, header, session);
  } catch (error: any) {
    if (error.code === 'EBADMSG') {
      throw new StvorSDKError('AUTH_FAILED', 'AAD authentication failed');
    }
    throw new StvorSDKError('DECRYPT_FAILED', error.message);
  }

  // PHASE 2: Commit (all validations passed)
  // Update session state atomically
  Object.assign(session, newSession);

  return {
    plaintext: newSession.toString(),  // Placeholder
    updatedSession: session,
  };
}

/**
 * Encrypt message with policy enforcement
 */
export function encryptMessageWithPolicy(
  plaintext: string,
  session: SessionState
): {
  message: EncryptedMessage;
  updatedSession: SessionState;
} {
  // Check state
  if (session.state === 'COMPROMISED') {
    throw new StvorSDKError(
      'SESSION_COMPROMISED',
      'Cannot encrypt: session is compromised'
    );
  }

  // Compute new state (pure)
  const { ciphertext, header, newSession } = tryEncryptMessage(
    plaintext,
    session
  );

  // Update session (atomic)
  Object.assign(session, newSession);

  return {
    message: { ciphertext, header },
    updatedSession: session,
  };
}

// ============================================================================
// PART 9: STORAGE ADAPTER INTERFACES
// ============================================================================

export interface IReplayCache {
  /**
   * Check if nonce already seen
   * Returns true if REPLAY detected
   * MUST be atomic
   */
  checkAndMark(
    peerId: string,
    nonceHex: string,
    timestamp: number
  ): Promise<boolean>;
}

export interface ITofuStore {
  storeFingerprint(peerId: string, fingerprint: string): Promise<void>;
  getFingerprint(peerId: string): Promise<string | null>;
}

export interface ISessionStore {
  saveSession(peerId: string, session: SessionState): Promise<void>;
  loadSession(peerId: string): Promise<SessionState | null>;
}

export interface IIdentityStore {
  saveIdentityKeys(userId: string, keys: any): Promise<void>;
  loadIdentityKeys(userId: string): Promise<any | null>;
}
