/**
 * STVOR DX Facade - Main Application Classes
 *
 * Security Guarantees:
 * - X3DH + Double Ratchet (Signal Protocol)
 * - Forward Secrecy via automatic DH ratchet rotation
 * - Post-Compromise Security via forced ratchet steps
 * - TOFU (Trust On First Use) for identity verification
 * - Replay protection via nonce validation
 * - Cryptographically verified metrics (HMAC-SHA256)
 * - Node.js crypto for all cryptographic operations
 */
import { StvorAppConfig, UserId, MessageContent } from './types';
import { DecryptedMessage } from './types';
import { Errors, StvorError, ErrorCode } from './errors';
import { SealedPayload } from './types';
export type { DecryptedMessage, SealedPayload, ErrorCode };
export { StvorError, Errors };
import { RelayClient } from './relay-client';
import { MetricsAttestationEngine } from './metrics-attestation';
declare const messagesDeliveredTotal: {
    inc: () => number;
};
declare const quotaExceededTotal: {
    inc: () => number;
};
declare const rateLimitedTotal: {
    inc: () => number;
};
export { messagesDeliveredTotal, quotaExceededTotal, rateLimitedTotal };
export declare class StvorApp {
    private relay;
    private config;
    private connectedClients;
    private metricsAttestation;
    private backendUrl;
    private appToken;
    constructor(config: Required<StvorAppConfig>);
    isReady(): boolean;
    /**
     * Get attestation engine for recording metrics
     */
    getMetricsAttestationEngine(): MetricsAttestationEngine;
    /**
     * Periodically send metrics attestations to backend
     * Backend verifies and stores only valid attestations
     */
    sendMetricsAttestation(): Promise<void>;
    /**
     * Flush metrics to backend
     * Sends current metrics attestation (if there is any activity)
     * Called explicitly by user or on disconnect
     */
    flushMetrics(): Promise<void>;
    connect(userId: UserId): Promise<StvorFacadeClient>;
    disconnect(userId?: UserId): Promise<void>;
    private initClient;
}
export declare class StvorFacadeClient {
    private userId;
    private relay;
    private metricsAttestation;
    private initialized;
    private cryptoSession;
    private messageHandlers;
    constructor(userId: UserId, relay: RelayClient, metricsAttestation: MetricsAttestationEngine);
    internalInitialize(): Promise<void>;
    private initialize;
    /**
     * Send an encrypted message to a recipient.
     *
     * By default, if the recipient is not yet registered, the method will
     * poll up to `options.timeout` ms for their keys to appear on the relay.
     * Set `options.waitForRecipient: false` to throw immediately instead.
     *
     * @param recipientId  - The recipient's user ID
     * @param content      - Message content (string or Uint8Array)
     * @param options      - Optional settings:
     *   - `timeout`           — Max wait time in ms (default: 10 000)
     *   - `waitForRecipient`  — Auto-wait for recipient keys (default: true)
     */
    send(recipientId: UserId, content: MessageContent, options?: {
        timeout?: number;
        waitForRecipient?: boolean;
    }): Promise<void>;
    /**
     * Check current quota usage from the relay server
     */
    private checkQuota;
    /**
     * Wait for a specific recipient's public keys to become available on the relay.
     * Polls the relay at 500ms intervals until the keys appear or timeout expires.
     *
     * @param recipientId - The user ID of the recipient
     * @param timeoutMs   - Max time to wait in milliseconds (default: 10000)
     * @returns The recipient's serialized public keys, or null if timeout
     */
    waitForUser(recipientId: UserId, timeoutMs?: number): Promise<boolean>;
    private waitForRecipientKeys;
    onMessage(handler: (msg: DecryptedMessage) => void): () => void;
    getUserId(): UserId;
    private decryptMessage;
    private startMessagePolling;
    /**
     * Disconnect the client from the relay server.
     */
    disconnect(): Promise<void>;
}
export declare function init(config: StvorAppConfig): Promise<StvorApp>;
export declare const createApp: typeof init;
export declare const Stvor: {
    init: typeof init;
    createApp: typeof init;
};
