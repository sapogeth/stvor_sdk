/**
 * STVOR DX Facade - Relay Client
 */
import type { SerializedPublicKeys } from './crypto-session';
interface OutgoingMessage {
    to: string;
    from: string;
    ciphertext: string;
    header: string;
}
interface IncomingMessage {
    id?: string;
    from: string;
    ciphertext: string;
    header: string;
    timestamp: string;
}
export declare class RelayClient {
    private relayUrl;
    private timeout;
    private appToken;
    private connected;
    constructor(relayUrl: string, appToken: string, timeout?: number);
    getAppToken(): string;
    getBaseUrl(): string;
    private getAuthHeaders;
    healthCheck(): Promise<void>;
    isConnected(): boolean;
    register(userId: string, publicKeys: SerializedPublicKeys): Promise<void>;
    getPublicKeys(userId: string): Promise<SerializedPublicKeys | null>;
    send(message: OutgoingMessage): Promise<void>;
    fetchMessages(userId: string): Promise<IncomingMessage[]>;
    deleteMessage(messageId: string): Promise<void>;
    disconnect(): void;
}
export {};
