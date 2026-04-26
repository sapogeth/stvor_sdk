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
    groupId?: string;
    groupHeader?: string;
}
interface OutgoingGroupMessage {
    groupId: string;
    from: string;
    members: string[];
    ciphertext: string;
    groupHeader: string;
}
export interface SenderKeyDistributionPayload {
    groupId: string;
    from: string;
    chainKey: string;
    generation: number;
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
    deleteUser(userId: string): Promise<{
        deletedAt: string;
        messagesDeleted: number;
    }>;
    exportUserData(userId: string): Promise<unknown>;
    sendToGroup(message: OutgoingGroupMessage): Promise<void>;
    sendSenderKeyDistribution(payload: SenderKeyDistributionPayload, recipientId: string): Promise<void>;
    disconnect(): void;
}
export {};
