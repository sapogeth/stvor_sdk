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
    /** Ваш userId — email, UUID, username — любая строка */
    userId: string;
    /** AppToken из дашборда, начинается с 'stvor_' */
    appToken: string;
    /** URL relay-сервера */
    relayUrl: string;
    /** Таймаут запросов, мс (default: 10 000) */
    timeout?: number;
    /** Интервал поллинга, мс (default: 1 000) */
    pollIntervalMs?: number;
}
export interface StvorMessage {
    /** Кто прислал */
    from: string;
    /** Расшифрованные данные (любой тип) */
    data: unknown;
    /** Время отправки */
    timestamp: Date;
    /** Уникальный ID */
    id: string;
}
export type MessageHandler = (msg: StvorMessage) => void | Promise<void>;
export declare class StvorClient {
    private readonly userId;
    private readonly relay;
    private readonly crypto;
    private readonly handlers;
    private pollTimer;
    private alive;
    private readonly pollIntervalMs;
    /** @internal */
    constructor(userId: string, relay: RelayClient, crypto: CryptoSessionManager, pollIntervalMs: number);
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
    /** Отключиться и остановить поллинг */
    disconnect(): Promise<void>;
    /** @internal — вызывается из Stvor.connect() */
    startPolling(): void;
    private processRaw;
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
