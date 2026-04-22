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
import { verifyFingerprint } from './tofu-manager.js';
import { validateMessageWithNonce } from './replay-manager.js';
import { encodeData, decodeData } from './data-codec.js';
import { StvorError, Errors } from './errors.js';
export { StvorError };
// ─── Client ───────────────────────────────────────────────────────────────────
export class StvorClient {
    /** @internal */
    constructor(userId, relay, crypto, pollIntervalMs) {
        this.handlers = new Set();
        this.pollTimer = null;
        this.alive = true;
        this.userId = userId;
        this.relay = relay;
        this.crypto = crypto;
        this.pollIntervalMs = pollIntervalMs;
    }
    // ── Send ──────────────────────────────────────────────────────────────
    /**
     * Отправить любые данные получателю.
     * Сессия устанавливается автоматически при первом обращении.
     *
     * @param recipientId  userId получателя
     * @param data         любой тип: string, number, object, Buffer, Uint8Array, Date, Set, Map…
     * @param options.waitForRecipient  ждать появления получателя (default: true)
     * @param options.timeout           макс. ожидание мс (default: 10 000)
     */
    async send(recipientId, data, options) {
        if (!this.alive)
            throw Errors.clientNotReady();
        const { waitForRecipient = true, timeout = 10000 } = options ?? {};
        if (!this.crypto.hasSession(recipientId)) {
            let peerKeys = await this.relay.getPublicKeys(recipientId);
            if (!peerKeys && waitForRecipient) {
                peerKeys = await this.waitForKeys(recipientId, timeout);
            }
            if (!peerKeys)
                throw Errors.recipientNotFound(recipientId);
            const identityKey = Buffer.from(peerKeys.identityKey, 'base64url');
            await verifyFingerprint(recipientId, identityKey);
            await this.crypto.establishSessionWithPeer(recipientId, peerKeys);
        }
        const encoded = encodeData(data);
        const plaintext = encoded.toString('base64url');
        const { ciphertext, header } = this.crypto.encryptForPeer(recipientId, plaintext);
        await this.relay.send({ to: recipientId, from: this.userId, ciphertext, header });
    }
    /**
     * Подписаться на входящие сообщения.
     * Возвращает функцию отписки.
     */
    onMessage(handler) {
        this.handlers.add(handler);
        return () => this.handlers.delete(handler);
    }
    /**
     * Подождать появления пользователя на relay.
     * Возвращает true когда пользователь зарегистрировался, false при таймауте.
     */
    async waitForUser(userId, timeoutMs = 10000) {
        return (await this.waitForKeys(userId, timeoutMs)) !== null;
    }
    getUserId() { return this.userId; }
    /** Отключиться и остановить поллинг */
    async disconnect() {
        this.alive = false;
        if (this.pollTimer) {
            clearTimeout(this.pollTimer);
            this.pollTimer = null;
        }
        this.relay.disconnect();
        this.handlers.clear();
    }
    // ── Internal ──────────────────────────────────────────────────────────
    /** @internal — вызывается из Stvor.connect() */
    startPolling() {
        const tick = async () => {
            if (!this.alive)
                return;
            try {
                const messages = await this.relay.fetchMessages(this.userId);
                for (const raw of messages) {
                    try {
                        await this.processRaw(raw);
                    }
                    catch (e) {
                        console.error('[Stvor] Failed to process message from', raw.from, e);
                    }
                }
            }
            catch { /* сетевые ошибки не смертельны */ }
            if (this.alive) {
                this.pollTimer = setTimeout(tick, this.pollIntervalMs);
            }
        };
        tick().catch(() => { });
    }
    async processRaw(raw) {
        if (!this.crypto.hasSession(raw.from)) {
            const peerKeys = await this.relay.getPublicKeys(raw.from);
            if (!peerKeys)
                throw new Error(`No public keys for ${raw.from}`);
            const identityKey = Buffer.from(peerKeys.identityKey, 'base64url');
            await verifyFingerprint(raw.from, identityKey);
            await this.crypto.establishSessionWithPeer(raw.from, peerKeys);
        }
        // Replay protection через nonce из header (байты 73-84 в 85-байтовом header)
        const headerBuf = Buffer.from(raw.header, 'base64url');
        if (headerBuf.length >= 85) {
            const nonce = headerBuf.subarray(73, 85);
            const timestamp = Math.floor(new Date(raw.timestamp).getTime() / 1000);
            await validateMessageWithNonce(raw.from, nonce, timestamp);
        }
        const encodedB64 = this.crypto.decryptFromPeer(raw.from, raw.ciphertext, raw.header);
        const decoded = decodeData(Buffer.from(encodedB64, 'base64url'));
        const msg = {
            id: raw.id ?? crypto.randomUUID(),
            from: raw.from,
            data: decoded,
            timestamp: new Date(raw.timestamp),
        };
        // Delete message from relay after successful decryption
        if (raw.id) {
            try {
                await this.relay.deleteMessage(raw.id);
            }
            catch { /* non-fatal */ }
        }
        for (const h of this.handlers) {
            try {
                await h(msg);
            }
            catch (e) {
                console.error('[Stvor] Handler error:', e);
            }
        }
    }
    async waitForKeys(userId, timeoutMs) {
        const deadline = Date.now() + timeoutMs;
        while (Date.now() < deadline) {
            const keys = await this.relay.getPublicKeys(userId);
            if (keys)
                return keys;
            await sleep(500);
        }
        return null;
    }
}
// ─── Factory ──────────────────────────────────────────────────────────────────
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
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
async function connect(config) {
    if (!config.appToken?.startsWith('stvor_'))
        throw Errors.invalidAppToken();
    const timeout = config.timeout ?? 10000;
    const pollIntervalMs = config.pollIntervalMs ?? 1000;
    const relay = new RelayClient(config.relayUrl, config.appToken, timeout);
    const crypto = new CryptoSessionManager(config.userId);
    await crypto.initialize();
    // проверяем что relay жив
    try {
        await relay.healthCheck();
    }
    catch {
        throw Errors.relayUnavailable();
    }
    await relay.register(config.userId, crypto.getPublicKeys());
    const client = new StvorClient(config.userId, relay, crypto, pollIntervalMs);
    client.startPolling();
    return client;
}
export const Stvor = { connect };
export default Stvor;
