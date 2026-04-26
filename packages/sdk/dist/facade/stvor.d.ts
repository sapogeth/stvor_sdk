/**
 * Stvor SDK — единственный публичный API
 *
 * Одинаковый интерфейс для Node.js и браузера.
 * Вся криптография скрыта внутри.
 *
 * @example
 * // Node.js
 * import { Stvor } from '@stvor/sdk';
 *
 * const alice = await Stvor.connect({
 *   userId:   'alice',
 *   appToken: 'stvor_live_xxx',
 *   relayUrl: 'https://relay.example.com',
 * });
 *
 * alice.onMessage(msg => console.log(msg.from, msg.data));
 * await alice.send('bob', { text: 'Hello!' });
 * await alice.disconnect();
 */
import { CryptoSessionManager } from './crypto-session.js';
import { RelayClient } from './relay-client.js';
import { StvorError } from './errors.js';
export { StvorError };
export interface StvorConfig {
    userId: string;
    appToken: string;
    relayUrl: string;
    timeout?: number;
    pollIntervalMs?: number;
    /**
     * Hide sender identity from the relay server.
     * When true, the relay only sees `to` — never `from`.
     * Uses ephemeral ECDH + AES-256-GCM to seal the sender inside the envelope.
     * Default: false
     */
    sealedSender?: boolean;
    /**
     * Enable Post-Quantum Cryptography (ML-KEM-768 / Kyber).
     * When true, key exchange uses a hybrid scheme:
     *   Classical X3DH + ML-KEM-768 → HKDF(classical_ss ‖ pqc_ss)
     * Secure if EITHER classical OR post-quantum is secure.
     * Default: false
     */
    pqc?: boolean;
}
export interface StvorMessage {
    from: string;
    data: unknown;
    timestamp: Date;
    id: string;
}
export interface StvorGroupMessage {
    groupId: string;
    from: string;
    data: unknown;
    timestamp: Date;
    id: string;
}
export type MessageHandler = (msg: StvorMessage) => void | Promise<void>;
export type GroupMessageHandler = (msg: StvorGroupMessage) => void | Promise<void>;
export declare class StvorClient {
    private readonly userId;
    private readonly relay;
    private readonly crypto;
    private readonly handlers;
    private readonly groupHandlers;
    private pollTimer;
    private alive;
    private readonly pollIntervalMs;
    private readonly sealedSender;
    /** @internal */
    constructor(userId: string, relay: RelayClient, crypto: CryptoSessionManager, pollIntervalMs: number, sealedSender: boolean);
    /**
     * Отправить любые данные получателю.
     * Сессия устанавливается автоматически при первом обращении.
     *
     * @param recipientId  userId получателя
     * @param data         любой тип: string, number, object, Buffer, Uint8Array, Date, Set, Map…
     * @param options.waitForRecipient  ждать появления получателя (default: true)
     * @param options.timeout           макс. ожидание мс (default: 10 000)
     */
    send(recipientId: string, data: unknown, options?: {
        waitForRecipient?: boolean;
        timeout?: number;
    }): Promise<void>;
    /**
     * Подписаться на входящие сообщения.
     * Возвращает функцию отписки.
     */
    onMessage(handler: MessageHandler): () => void;
    /**
     * Подождать появления пользователя на relay.
     * Возвращает true когда пользователь зарегистрировался, false при таймауте.
     */
    waitForUser(userId: string, timeoutMs?: number): Promise<boolean>;
    getUserId(): string;
    /**
     * GDPR Art. 17 — Right to erasure.
     * Deletes all relay-side data for this user: public keys, queued messages.
     * Message content was already E2EE and inaccessible to the relay.
     */
    deleteMyData(): Promise<{
        deletedAt: string;
        messagesDeleted: number;
    }>;
    /**
     * GDPR Art. 20 — Right to data portability.
     * Returns what the relay stores about this user (metadata only).
     */
    exportMyData(): Promise<unknown>;
    /**
     * Create an E2EE group and invite members.
     * Sends sender key distribution to each member via their 1-to-1 session.
     *
     * @param groupId  Unique group identifier (any string)
     * @param memberIds  Array of userIds to invite
     */
    createGroup(groupId: string, memberIds: string[]): Promise<void>;
    /**
     * Send an encrypted message to a group.
     * All members will receive it via their own polling.
     */
    sendToGroup(groupId: string, data: unknown): Promise<void>;
    /**
     * Subscribe to incoming group messages.
     * Returns an unsubscribe function.
     */
    onGroupMessage(handler: GroupMessageHandler): () => void;
    /**
     * Add a member to an existing group.
     * Sends them the current sender key distribution.
     */
    addGroupMember(groupId: string, memberId: string): Promise<void>;
    /**
     * Remove a member from the group.
     * Automatically ratchets the sender key so they can't decrypt future messages.
     */
    removeGroupMember(groupId: string, memberId: string): Promise<void>;
    /** Отключиться и остановить поллинг */
    disconnect(): Promise<void>;
    /** @internal — вызывается из Stvor.connect() */
    startPolling(): void;
    private processRaw;
    private processGroupRaw;
    private waitForKeys;
}
/**
 * Подключиться к relay и получить готового к работе клиента.
 *
 * @example
 * const alice = await Stvor.connect({
 *   userId:   'alice',
 *   appToken: 'stvor_live_xxx',
 *   relayUrl: 'http://localhost:4444',
 * });
 */
declare function connect(config: StvorConfig): Promise<StvorClient>;
export declare const Stvor: {
    connect: typeof connect;
};
export default Stvor;
