/**
 * STVOR SDK - Legacy Core API
 * Kept for backwards compatibility
 */
export interface StvorConfig {
    apiKey: string;
    serverUrl?: string;
}
export interface Peer {
    id: string;
    publicKey: any;
}
export interface EncryptedMessage {
    ciphertext: string;
    nonce: string;
    from: string;
}
export declare class StvorClient {
    private config;
    private myKeyPair;
    private myId;
    private peers;
    constructor(config: StvorConfig);
    ready(): Promise<void>;
    createPeer(name: string): Promise<Peer>;
    send({ to, message }: {
        to: string;
        message: string;
    }): Promise<EncryptedMessage>;
    receive(encrypted: EncryptedMessage): Promise<string>;
}
