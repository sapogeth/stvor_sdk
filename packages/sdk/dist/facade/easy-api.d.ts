/**
 * STVOR Easy-to-Use High-Level API
 *
 * Simple, intuitive interface for end-to-end encryption
 * - Works with ANY data type (strings, objects, binary, files)
 * - Automatic type preservation
 * - One-line messaging
 *
 * @example
 * import { StvorEasyAPI } from '@stvor/sdk';
 *
 * // Initialize
 * const api = await StvorEasyAPI.init({
 *   appToken: 'stvor_live_...',
 *   userId: 'alice@example.com'
 * });
 *
 * // Send ANY data type - automatically encrypted & type-preserved
 * await api.send('bob@example.com', { message: 'Hello', file: Buffer.from([1,2,3]) });
 * await api.send('bob@example.com', 'Simple text message');
 * await api.send('bob@example.com', 42);
 * await api.send('bob@example.com', { complex: { nested: { data: true } } });
 *
 * // Receive with automatic type restoration
 * api.onMessage((from, data) => {
 *   console.log(`Got from ${from}:`, data); // Data is automatically typed!
 * });
 */
import type { SerializedPublicKeys } from './crypto-session';
export interface StvorEasyAPIConfig {
    appToken: string;
    userId: string;
    relayUrl?: string;
}
export interface MessageHandler {
    (from: string, data: unknown): void | Promise<void>;
}
/**
 * High-level STVOR API that abstracts away cryptography
 *
 * Handles:
 * - Automatic type encoding/decoding
 * - Session management
 * - Message routing
 * - Error handling
 */
export declare class StvorEasyAPI {
    private userId;
    private cryptoManager;
    private relayClient;
    private messageHandlers;
    private polling;
    private constructor();
    /**
     * Initialize the API
     */
    static init(config: StvorEasyAPIConfig): Promise<StvorEasyAPI>;
    /**
     * Send ANY data type to peer - automatically encrypted
     *
     * @example
     * await api.send('bob@example.com', 'Hello Bob');
     * await api.send('bob@example.com', { greeting: 'Hello', emoji: '👋' });
     * await api.send('bob@example.com', 42);
     * await api.send('bob@example.com', Buffer.from([1, 2, 3]));
     */
    send(peerId: string, data: unknown): Promise<void>;
    /**
     * Register handler for incoming messages
     * Data is automatically decoded to original type
     *
     * @example
     * api.onMessage((from, data) => {
     *   console.log(`From ${from}:`, data);
     *   // data is automatically typed (string, object, number, etc.)
     * });
     */
    onMessage(handler: MessageHandler): void;
    /**
     * Remove message handler
     */
    offMessage(handler: MessageHandler): void;
    /**
     * Get user's public keys (for registering with peers)
     */
    getPublicKeys(): SerializedPublicKeys;
    /**
     * Connect to a peer (establish session)
     */
    connectToPeer(peerId: string): Promise<void>;
    /**
     * Check if connected to peer
     */
    isConnected(peerId: string): boolean;
    /**
     * Disconnect and stop polling
     */
    disconnect(): Promise<void>;
    private startPolling;
    private stopPolling;
    private checkMessages;
}
/**
 * Quick initialization shorthand
 *
 * @example
 * const api = await stvorInit({
 *   appToken: process.env.STVOR_TOKEN,
 *   userId: 'user@example.com'
 * });
 */
export declare function stvorInit(config: StvorEasyAPIConfig): Promise<StvorEasyAPI>;
/**
 * Create minimal example
 *
 * @example
 * const api = await stvorInit({ appToken: 'token', userId: 'alice' });
 * await api.send('bob', 'Hello!');
 * api.onMessage((from, msg) => console.log(`From ${from}: ${msg}`));
 */
export declare function quickStart(token: string, userId: string): Promise<StvorEasyAPI>;
