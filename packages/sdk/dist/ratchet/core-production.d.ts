/**
 * STVOR SDK v2.4.0 - Production-Ready Core Ratchet
 * Key changes from v2:
 * - Header AAD authentication
 * - Immutable state transitions
 * - Functional design (pure functions)
 * - Explicit error codes
 */
export interface EncryptedMessage {
    ciphertext: Uint8Array;
    header: {
        publicKey: Uint8Array;
        nonce: Uint8Array;
        sendCounter: number;
        receiveCounter: number;
        timestamp: number;
    };
}
export interface SessionState {
    peerId: string;
    peerIdentityKey: Uint8Array;
    rootKey: Uint8Array;
    sendingChainKey: Uint8Array;
    receivingChainKey: Uint8Array;
    sendCounter: number;
    receiveCounter: number;
    skippedMessageKeys: Map<string, {
        key: Uint8Array;
        timestamp: number;
        counter: number;
    }>;
    state: SessionFSMState;
    lastRatchetTime: number;
    lastRatchetCounter: number;
    createdAt: number;
    metadata: Record<string, any>;
}
export type SessionFSMState = 'INIT' | 'ESTABLISHED' | 'RATCHETING' | 'COMPROMISED';
export declare const ErrorCode: {
    readonly DECRYPT_FAILED: "DECRYPT_FAILED";
    readonly AUTH_FAILED: "AUTH_FAILED";
    readonly INVALID_KEY_FORMAT: "INVALID_KEY_FORMAT";
    readonly SPK_SIGNATURE_INVALID: "SPK_SIGNATURE_INVALID";
    readonly REPLAY_DETECTED: "REPLAY_DETECTED";
    readonly TOFU_MISMATCH: "TOFU_MISMATCH";
    readonly INVALID_STATE_TRANSITION: "INVALID_STATE_TRANSITION";
    readonly SESSION_COMPROMISED: "SESSION_COMPROMISED";
    readonly STORAGE_UNAVAILABLE: "STORAGE_UNAVAILABLE";
    readonly STORAGE_WRITE_FAILED: "STORAGE_WRITE_FAILED";
    readonly SKIPPED_KEYS_LIMIT_EXCEEDED: "SKIPPED_KEYS_LIMIT_EXCEEDED";
    readonly REPLAY_WINDOW_EXPIRED: "REPLAY_WINDOW_EXPIRED";
};
export declare class StvorSDKError extends Error {
    readonly code: keyof typeof ErrorCode;
    readonly metadata?: Record<string, any>;
    constructor(code: keyof typeof ErrorCode, message: string, metadata?: Record<string, any>);
}
/**
 * Decrypt message with full validation
 * ATOMICALLY: validate ALL, then update session
 */
export declare function decryptMessageWithValidation(ciphertext: Uint8Array, header: EncryptedMessage['header'], session: SessionState, validators: {
    replayCache: IReplayCache;
    tofuStore?: ITofuStore;
}): Promise<{
    plaintext: string;
    updatedSession: SessionState;
}>;
/**
 * Encrypt message with policy enforcement
 */
export declare function encryptMessageWithPolicy(plaintext: string, session: SessionState): {
    message: EncryptedMessage;
    updatedSession: SessionState;
};
export interface IReplayCache {
    /**
     * Check if nonce already seen
     * Returns true if REPLAY detected
     * MUST be atomic
     */
    checkAndMark(peerId: string, nonceHex: string, timestamp: number): Promise<boolean>;
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
