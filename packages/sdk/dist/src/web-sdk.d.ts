/**
 * STVOR Web SDK — Browser edition with full Double Ratchet
 *
 * Works in any modern browser (Chrome 89+, Firefox 90+, Safari 15+).
 * Zero Node.js dependencies — uses only Web Crypto API and fetch.
 * Same relay protocol as the Node.js SDK.
 *
 * @example
 * import { StvorWebSDK } from '@stvor/sdk/web';
 *
 * const sdk = await StvorWebSDK.create({
 *   userId:   'alice',
 *   appToken: 'stvor_live_xxx',
 *   relayUrl: 'http://localhost:4444',
 * });
 *
 * sdk.onMessage((from, data) => console.log(from, data));
 * await sdk.send('bob', { text: 'Hello!' });
 * sdk.disconnect();
 */
export type MessageHandler = (from: string, data: unknown) => void | Promise<void>;
export interface WebSDKOptions {
    userId: string;
    appToken: string;
    relayUrl: string;
    pollIntervalMs?: number;
}
export declare class StvorWebSDK {
    private readonly userId;
    private readonly relay;
    private readonly store;
    private identity;
    private sessions;
    private handlers;
    private pollTimer;
    private alive;
    private readonly pollIntervalMs;
    private constructor();
    static create(opts: WebSDKOptions): Promise<StvorWebSDK>;
    private _init;
    private _loadOrGenerateIdentity;
    private _persistIdentity;
    private _serializePublicKeys;
    private _loadSessions;
    private _saveSession;
    private _getOrEstablishSession;
    send(recipientId: string, data: unknown): Promise<void>;
    onMessage(handler: MessageHandler): () => void;
    waitForUser(userId: string, timeoutMs?: number): Promise<boolean>;
    getUserId(): string;
    disconnect(): void;
    private _startPolling;
    private _processRaw;
}
export default StvorWebSDK;
