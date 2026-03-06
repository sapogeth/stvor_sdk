import type { StvorAppConfig, UserId, MessageContent } from './types.js';
import { RelayClient } from './relay-client.js';
type MessageHandler = (from: UserId, msg: string | Uint8Array) => void;
type UserAvailableHandler = (userId: UserId) => void;
export declare class StvorFacadeClient {
    readonly userId: UserId;
    private readonly relay;
    private readonly defaultTimeout;
    private crypto;
    private handlers;
    private userAvailableHandlers;
    private knownPubKeys;
    private pendingKeyResolvers;
    constructor(userId: UserId, relay: RelayClient, defaultTimeout?: number);
    private handleRelayMessage;
    internalInitialize(): Promise<void>;
    /**
     * Check if a user's public key is available locally
     */
    isUserAvailable(userId: UserId): boolean;
    /**
     * Get list of all known users (whose public keys we have)
     */
    getAvailableUsers(): UserId[];
    /**
     * Wait until a specific user's public key becomes available.
     * This is the recommended way to ensure you can send messages.
     *
     * @param userId - The user to wait for
     * @param timeoutMs - Maximum time to wait (default: 10000ms)
     * @throws StvorError with RECIPIENT_TIMEOUT if timeout expires
     *
     * @example
     * ```typescript
     * await alice.waitForUser('bob@example.com');
     * await alice.send('bob@example.com', 'Hello!');
     * ```
     */
    waitForUser(userId: UserId, timeoutMs?: number): Promise<void>;
    /**
     * Send an encrypted message to a recipient.
     *
     * If the recipient's public key is not yet available, this method will
     * automatically wait up to `timeoutMs` for the key to arrive via the relay.
     *
     * @param recipientId - The recipient's user ID
     * @param content - Message content (string or Uint8Array)
     * @param options - Optional: { timeout: number, waitForRecipient: boolean }
     * @throws StvorError with RECIPIENT_TIMEOUT if recipient key doesn't arrive in time
     *
     * @example
     * ```typescript
     * // Auto-waits for recipient (recommended)
     * await alice.send('bob@example.com', 'Hello!');
     *
     * // Skip waiting (throws immediately if not available)
     * await alice.send('bob@example.com', 'Hello!', { waitForRecipient: false });
     * ```
     */
    send(recipientId: UserId, content: MessageContent, options?: {
        timeout?: number;
        waitForRecipient?: boolean;
    }): Promise<void>;
    /**
     * Register a handler for incoming messages
     */
    onMessage(handler: MessageHandler): () => void;
    /**
     * Register a handler that fires when a new user becomes available.
     * This is triggered when we receive a user's public key announcement.
     *
     * **Edge-triggered**: Fires only ONCE per user, on first key discovery.
     * Will NOT fire again if user reconnects with same identity.
     *
     * @example
     * ```typescript
     * client.onUserAvailable((userId) => {
     *   console.log(`${userId} is now available for messaging`);
     * });
     * ```
     */
    onUserAvailable(handler: UserAvailableHandler): () => void;
}
export declare class StvorApp {
    private readonly config;
    private clients;
    constructor(config: StvorAppConfig);
    connect(userId: UserId): Promise<StvorFacadeClient>;
    /**
     * Get a connected client by user ID
     */
    getClient(userId: UserId): StvorFacadeClient | undefined;
    /**
     * Check if a user is connected locally
     */
    isConnected(userId: UserId): boolean;
    disconnect(userId?: UserId): Promise<void>;
}
export declare function init(config: StvorAppConfig): Promise<StvorApp>;
export declare const createApp: typeof init;
export declare const Stvor: {
    init: typeof init;
    createApp: typeof init;
};
export {};
