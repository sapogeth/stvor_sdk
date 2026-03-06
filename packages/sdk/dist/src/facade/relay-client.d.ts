/**
 * STVOR DX Facade - Relay Client
 */
type JSONable = Record<string, any>;
export type RelayHandler = (msg: JSONable) => void;
export declare class RelayClient {
    private relayUrl;
    private timeout;
    private appToken;
    private ws?;
    private connected;
    private handshakeComplete;
    private backoff;
    private queue;
    private handlers;
    private reconnecting;
    private connectPromise?;
    private connectResolve?;
    private connectReject?;
    private authFailed;
    constructor(relayUrl: string, appToken: string, timeout?: number);
    /**
     * Initialize the connection and wait for handshake.
     * Throws StvorError if API key is rejected.
     */
    init(): Promise<void>;
    private getAuthHeaders;
    private connect;
    private scheduleReconnect;
    private doSend;
    send(obj: JSONable): void;
    onMessage(h: RelayHandler): void;
    isConnected(): boolean;
    isAuthenticated(): boolean;
}
export {};
