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
import { sealEnvelope, unsealEnvelope } from './sealed-sender.js';
export { StvorError };
const SKD_HEADER_MARKER = Buffer.from('__SKD__').toString('base64url');
// ─── Client ───────────────────────────────────────────────────────────────────
export class StvorClient {
    /** @internal */
    constructor(userId, relay, crypto, pollIntervalMs, sealedSender) {
        this.handlers = new Set();
        this.groupHandlers = new Set();
        this.pollTimer = null;
        this.alive = true;
        this.userId = userId;
        this.relay = relay;
        this.crypto = crypto;
        this.pollIntervalMs = pollIntervalMs;
        this.sealedSender = sealedSender;
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
        // PQC: on first message, embed the ML-KEM ciphertext so recipient can decaps
        const pqcCt = this.crypto.popPendingPqcCt(recipientId) ?? undefined;
        if (this.sealedSender) {
            const recipientIK = Buffer.from((await this.relay.getPublicKeys(recipientId)).identityKey, 'base64url');
            const sealed = sealEnvelope({ from: this.userId, ciphertext, header }, recipientIK);
            await this.relay.send({ to: recipientId, from: '', ciphertext: sealed, header: '__SEALED__', pqcCt });
        }
        else {
            await this.relay.send({ to: recipientId, from: this.userId, ciphertext, header, pqcCt });
        }
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
    // ── Compliance (GDPR) ─────────────────────────────────────────────────
    /**
     * GDPR Art. 17 — Right to erasure.
     * Deletes all relay-side data for this user: public keys, queued messages.
     * Message content was already E2EE and inaccessible to the relay.
     */
    async deleteMyData() {
        return this.relay.deleteUser(this.userId);
    }
    /**
     * GDPR Art. 20 — Right to data portability.
     * Returns what the relay stores about this user (metadata only).
     */
    async exportMyData() {
        return this.relay.exportUserData(this.userId);
    }
    // ── Group API ─────────────────────────────────────────────────────────
    /**
     * Create an E2EE group and invite members.
     * Sends sender key distribution to each member via their 1-to-1 session.
     *
     * @param groupId  Unique group identifier (any string)
     * @param memberIds  Array of userIds to invite
     */
    async createGroup(groupId, memberIds) {
        if (!this.alive)
            throw Errors.clientNotReady();
        this.crypto.createGroupSession(groupId, memberIds);
        const dist = this.crypto.getSenderKeyDistribution(groupId);
        // Ensure 1-to-1 session with each member, then distribute sender key
        for (const memberId of memberIds) {
            if (!this.crypto.hasSession(memberId)) {
                let peerKeys = await this.relay.getPublicKeys(memberId);
                if (!peerKeys)
                    peerKeys = await this.waitForKeys(memberId, 10000);
                if (!peerKeys)
                    throw Errors.recipientNotFound(memberId);
                const identityKey = Buffer.from(peerKeys.identityKey, 'base64url');
                await verifyFingerprint(memberId, identityKey);
                await this.crypto.establishSessionWithPeer(memberId, peerKeys);
            }
            // Encrypt & send SKD via 1-to-1 session
            const skdPayload = JSON.stringify({
                groupId,
                from: this.userId,
                chainKey: dist.chainKey,
                generation: dist.generation,
            });
            const encoded = encodeData(skdPayload);
            const plaintext = encoded.toString('base64url');
            const { ciphertext, header } = this.crypto.encryptForPeer(memberId, plaintext);
            await this.relay.send({
                to: memberId,
                from: this.userId,
                ciphertext,
                // Mark as SKD by prepending marker to header
                header: SKD_HEADER_MARKER + '.' + header,
            });
        }
    }
    /**
     * Send an encrypted message to a group.
     * All members will receive it via their own polling.
     */
    async sendToGroup(groupId, data) {
        if (!this.alive)
            throw Errors.clientNotReady();
        if (!this.crypto.hasGroupSession(groupId))
            throw new Error(`Not in group: ${groupId}`);
        const encoded = encodeData(data);
        const plaintext = encoded.toString('base64url');
        const { ciphertext, groupHeader } = this.crypto.encryptForGroup(groupId, plaintext);
        const members = this.crypto.getGroupMembers(groupId);
        await this.relay.sendToGroup({
            groupId,
            from: this.userId,
            members,
            ciphertext,
            groupHeader,
        });
    }
    /**
     * Subscribe to incoming group messages.
     * Returns an unsubscribe function.
     */
    onGroupMessage(handler) {
        this.groupHandlers.add(handler);
        return () => this.groupHandlers.delete(handler);
    }
    /**
     * Add a member to an existing group.
     * Sends them the current sender key distribution.
     */
    async addGroupMember(groupId, memberId) {
        if (!this.alive)
            throw Errors.clientNotReady();
        this.crypto.addGroupMember(groupId, memberId);
        if (!this.crypto.hasSession(memberId)) {
            let peerKeys = await this.relay.getPublicKeys(memberId);
            if (!peerKeys)
                peerKeys = await this.waitForKeys(memberId, 10000);
            if (!peerKeys)
                throw Errors.recipientNotFound(memberId);
            const identityKey = Buffer.from(peerKeys.identityKey, 'base64url');
            await verifyFingerprint(memberId, identityKey);
            await this.crypto.establishSessionWithPeer(memberId, peerKeys);
        }
        const dist = this.crypto.getSenderKeyDistribution(groupId);
        const skdPayload = JSON.stringify({ groupId, from: this.userId, chainKey: dist.chainKey, generation: dist.generation });
        const encoded = encodeData(skdPayload);
        const { ciphertext, header } = this.crypto.encryptForPeer(memberId, encoded.toString('base64url'));
        await this.relay.send({ to: memberId, from: this.userId, ciphertext, header: SKD_HEADER_MARKER + '.' + header });
    }
    /**
     * Remove a member from the group.
     * Automatically ratchets the sender key so they can't decrypt future messages.
     */
    async removeGroupMember(groupId, memberId) {
        if (!this.alive)
            throw Errors.clientNotReady();
        this.crypto.removeGroupMember(groupId, memberId);
        // Distribute new sender key to remaining members
        const members = this.crypto.getGroupMembers(groupId);
        const dist = this.crypto.getSenderKeyDistribution(groupId);
        for (const remainingMember of members) {
            if (!this.crypto.hasSession(remainingMember))
                continue;
            const skdPayload = JSON.stringify({ groupId, from: this.userId, chainKey: dist.chainKey, generation: dist.generation });
            const encoded = encodeData(skdPayload);
            const { ciphertext, header } = this.crypto.encryptForPeer(remainingMember, encoded.toString('base64url'));
            await this.relay.send({ to: remainingMember, from: this.userId, ciphertext, header: SKD_HEADER_MARKER + '.' + header });
        }
    }
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
        // ── Group message (broadcast from relay) ──
        if (raw.groupId && raw.groupHeader) {
            await this.processGroupRaw(raw);
            if (raw.id) {
                try {
                    await this.relay.deleteMessage(raw.id);
                }
                catch { /* non-fatal */ }
            }
            return;
        }
        // ── Sealed sender: unseal envelope first ──
        if (raw.header === '__SEALED__') {
            const inner = unsealEnvelope(raw.ciphertext, this.crypto.getIdentityPrivateKey());
            raw = { ...raw, from: inner.from, ciphertext: inner.ciphertext, header: inner.header };
        }
        // ── SKD or regular 1-to-1 ──
        if (!this.crypto.hasSession(raw.from)) {
            const peerKeys = await this.relay.getPublicKeys(raw.from);
            if (!peerKeys)
                throw new Error(`No public keys for ${raw.from}`);
            const identityKey = Buffer.from(peerKeys.identityKey, 'base64url');
            await verifyFingerprint(raw.from, identityKey);
            await this.crypto.establishSessionWithPeer(raw.from, peerKeys);
        }
        // PQC: if first message carries a ML-KEM ciphertext, decaps and mix into root key
        if (raw.pqcCt && this.crypto.isPqcEnabled()) {
            this.crypto.applyIncomingPqcCt(raw.from, raw.pqcCt);
        }
        // Detect SKD marker: header starts with SKD_HEADER_MARKER + '.'
        if (raw.header.startsWith(SKD_HEADER_MARKER + '.')) {
            const realHeader = raw.header.slice(SKD_HEADER_MARKER.length + 1);
            const encodedB64 = this.crypto.decryptFromPeer(raw.from, raw.ciphertext, realHeader);
            const decoded = decodeData(Buffer.from(encodedB64, 'base64url'));
            const skd = JSON.parse(decoded);
            this.crypto.installSenderKey(skd.groupId, skd.from, skd.chainKey, skd.generation);
            if (raw.id) {
                try {
                    await this.relay.deleteMessage(raw.id);
                }
                catch { /* non-fatal */ }
            }
            return;
        }
        // Replay protection via nonce from header (bytes 73-84)
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
    async processGroupRaw(raw) {
        if (!this.crypto.hasGroupSession(raw.groupId)) {
            throw new Error(`Received group message for unknown group: ${raw.groupId}`);
        }
        const encodedB64 = this.crypto.decryptFromGroup(raw.groupId, raw.from, raw.ciphertext, raw.groupHeader);
        const decoded = decodeData(Buffer.from(encodedB64, 'base64url'));
        const msg = {
            id: raw.id ?? crypto.randomUUID(),
            groupId: raw.groupId,
            from: raw.from,
            data: decoded,
            timestamp: new Date(raw.timestamp),
        };
        for (const h of this.groupHandlers) {
            try {
                await h(msg);
            }
            catch (e) {
                console.error('[Stvor] Group handler error:', e);
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
    const crypto = new CryptoSessionManager(config.userId, undefined, undefined, config.pqc ?? false);
    await crypto.initialize();
    // проверяем что relay жив
    try {
        await relay.healthCheck();
    }
    catch {
        throw Errors.relayUnavailable();
    }
    await relay.register(config.userId, crypto.getPublicKeys());
    const client = new StvorClient(config.userId, relay, crypto, pollIntervalMs, config.sealedSender ?? false);
    client.startPolling();
    return client;
}
export const Stvor = { connect };
export default Stvor;
