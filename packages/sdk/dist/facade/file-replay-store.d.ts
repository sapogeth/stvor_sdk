/**
 * File-Based Persistent Replay Protection
 *
 * Stores message nonces and counters securely.
 * Prevents replay attacks across app restarts.
 */
export interface PersistentReplayProtection {
    directory: string;
    masterPassword: string;
}
export declare class FileReplayStore {
    private directory;
    private masterKey;
    constructor(config: PersistentReplayProtection);
    private getReplayFile;
    private encrypt;
    private decrypt;
    /**
     * Get or initialize replay state for a peer
     */
    getReplayState(userId: string, peerId: string): Promise<{
        seenNonces: Set<string>;
        lastMessageCounter: number;
    }>;
    /**
     * Save replay state
     */
    saveReplayState(userId: string, peerId: string, nonces: Set<string>, lastMessageCounter: number): Promise<void>;
    /**
     * Check if message is replay and add nonce
     */
    recordNonce(userId: string, peerId: string, nonce: string, messageCounter: number): Promise<{
        isReplay: boolean;
        state: any;
    }>;
    /**
     * Clear replay state (e.g., after key compromise recovery)
     */
    clearReplayState(userId: string, peerId: string): Promise<void>;
}
