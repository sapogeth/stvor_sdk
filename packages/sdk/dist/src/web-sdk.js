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
/// <reference lib="dom" />
/// <reference lib="dom.iterable" />
import { generateWebIdentityKeys, webEstablishSession, webEncrypt, webDecrypt, serializeWebSession, deserializeWebSession, verifyWebSPK, } from './web-ratchet.js';
// ── Data codec (browser-compatible, matches Node.js data-codec.ts markers) ────
// Markers: 0x01=string 0x02=number 0x03=boolean 0x04=null 0x05=binary 0x06=json
//          0x07=date 0x08=set 0x09=map
function encodePayload(data) {
    const enc = new TextEncoder();
    if (typeof data === 'string') {
        const b = enc.encode(data);
        const out = new Uint8Array(1 + b.length);
        out[0] = 0x01;
        out.set(b, 1);
        return out.buffer;
    }
    if (typeof data === 'number') {
        const out = new Uint8Array(9);
        out[0] = 0x02;
        new DataView(out.buffer).setFloat64(1, data, false);
        return out.buffer;
    }
    if (typeof data === 'boolean') {
        return new Uint8Array([0x03, data ? 1 : 0]).buffer;
    }
    if (data === null || data === undefined) {
        return new Uint8Array([0x04]).buffer;
    }
    if (data instanceof Uint8Array || data instanceof ArrayBuffer) {
        const src = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
        const out = new Uint8Array(1 + src.length);
        out[0] = 0x05;
        out.set(src, 1);
        return out.buffer;
    }
    if (data instanceof Date) {
        const b = enc.encode(data.toISOString());
        const out = new Uint8Array(1 + b.length);
        out[0] = 0x07;
        out.set(b, 1);
        return out.buffer;
    }
    if (data instanceof Set) {
        const b = enc.encode(JSON.stringify(Array.from(data)));
        const out = new Uint8Array(1 + b.length);
        out[0] = 0x08;
        out.set(b, 1);
        return out.buffer;
    }
    if (data instanceof Map) {
        const b = enc.encode(JSON.stringify(Array.from(data.entries())));
        const out = new Uint8Array(1 + b.length);
        out[0] = 0x09;
        out.set(b, 1);
        return out.buffer;
    }
    // Default: JSON
    const b = enc.encode(JSON.stringify(data));
    const out = new Uint8Array(1 + b.length);
    out[0] = 0x06;
    out.set(b, 1);
    return out.buffer;
}
function decodePayload(buf) {
    const bytes = new Uint8Array(buf);
    if (bytes.length === 0)
        throw new Error('Empty payload');
    const marker = bytes[0];
    const rest = buf.slice(1);
    const dec = new TextDecoder();
    switch (marker) {
        case 0x01: return dec.decode(rest);
        case 0x02: return new DataView(buf).getFloat64(1, false);
        case 0x03: return bytes[1] === 1;
        case 0x04: return null;
        case 0x05: return new Uint8Array(rest);
        case 0x06: return JSON.parse(dec.decode(rest));
        case 0x07: return new Date(dec.decode(rest));
        case 0x08: return new Set(JSON.parse(dec.decode(rest)));
        case 0x09: return new Map(JSON.parse(dec.decode(rest)));
        default: return dec.decode(buf);
    }
}
// ── IDB-based key/session store ───────────────────────────────────────────────
class IDBStore {
    constructor(name) {
        this.db = null;
        this.name = name;
    }
    async open() {
        return new Promise((resolve, reject) => {
            const req = indexedDB.open(this.name, 1);
            req.onupgradeneeded = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains('kv'))
                    db.createObjectStore('kv');
            };
            req.onsuccess = () => { this.db = req.result; resolve(); };
            req.onerror = () => reject(req.error);
        });
    }
    async get(key) {
        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('kv', 'readonly');
            const req = tx.objectStore('kv').get(key);
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error);
        });
    }
    async set(key, value) {
        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('kv', 'readwrite');
            const req = tx.objectStore('kv').put(value, key);
            req.onsuccess = () => resolve();
            req.onerror = () => reject(req.error);
        });
    }
    async del(key) {
        return new Promise((resolve, reject) => {
            const tx = this.db.transaction('kv', 'readwrite');
            const req = tx.objectStore('kv').delete(key);
            req.onsuccess = () => resolve();
            req.onerror = () => reject(req.error);
        });
    }
}
// ── HTTP relay client ─────────────────────────────────────────────────────────
class HttpRelay {
    constructor(url, token) {
        this.url = url;
        this.token = token;
    }
    headers() {
        return { 'Authorization': `Bearer ${this.token}`, 'Content-Type': 'application/json' };
    }
    async healthCheck() {
        const res = await fetch(`${this.url}/health`);
        if (!res.ok)
            throw new Error(`Relay unavailable: HTTP ${res.status}`);
    }
    async register(userId, publicKeys) {
        const res = await fetch(`${this.url}/register`, {
            method: 'POST',
            headers: this.headers(),
            body: JSON.stringify({ user_id: userId, publicKeys }),
        });
        if (!res.ok)
            throw new Error(`Register failed: ${res.status}`);
    }
    async getPublicKeys(userId) {
        const res = await fetch(`${this.url}/public-key/${encodeURIComponent(userId)}`, {
            headers: this.headers(),
        });
        if (res.status === 404)
            return null;
        if (!res.ok)
            throw new Error(`getPublicKeys failed: ${res.status}`);
        const d = await res.json();
        return d.publicKeys;
    }
    async sendMessage(to, from, ciphertext, header) {
        const res = await fetch(`${this.url}/message`, {
            method: 'POST',
            headers: this.headers(),
            body: JSON.stringify({ to, from, ciphertext, header }),
        });
        if (!res.ok)
            throw new Error(`Send failed: ${res.status}`);
    }
    async fetchMessages(userId) {
        const res = await fetch(`${this.url}/messages/${encodeURIComponent(userId)}`, {
            headers: this.headers(),
        });
        if (!res.ok)
            return [];
        const d = await res.json();
        return d.messages ?? [];
    }
    async deleteMessage(id) {
        try {
            await fetch(`${this.url}/message/${encodeURIComponent(id)}`, {
                method: 'DELETE',
                headers: this.headers(),
            });
        }
        catch { /* non-fatal */ }
    }
}
// ── b64url helpers ────────────────────────────────────────────────────────────
function ab2b64(buf) {
    let s = '';
    new Uint8Array(buf).forEach(b => s += String.fromCharCode(b));
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function b642ab(s) {
    const b = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
    const a = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++)
        a[i] = b.charCodeAt(i);
    return a.buffer;
}
// ── Main Web SDK ──────────────────────────────────────────────────────────────
export class StvorWebSDK {
    constructor(opts) {
        this.identity = null;
        this.sessions = new Map();
        this.handlers = new Set();
        this.pollTimer = null;
        this.alive = true;
        this.userId = opts.userId;
        this.relay = new HttpRelay(opts.relayUrl, opts.appToken);
        this.store = new IDBStore(`stvor-${opts.userId}`);
        this.pollIntervalMs = opts.pollIntervalMs ?? 1000;
    }
    static async create(opts) {
        if (!opts.appToken?.startsWith('stvor_'))
            throw new Error('Invalid appToken');
        if (!opts.userId || !opts.relayUrl)
            throw new Error('userId and relayUrl are required');
        const sdk = new StvorWebSDK(opts);
        await sdk._init();
        return sdk;
    }
    async _init() {
        await this.store.open();
        await this._loadOrGenerateIdentity();
        try {
            await this.relay.healthCheck();
        }
        catch {
            throw new Error('Relay unavailable');
        }
        const publicKeys = this._serializePublicKeys();
        await this.relay.register(this.userId, publicKeys);
        await this._loadSessions();
        this._startPolling();
    }
    async _loadOrGenerateIdentity() {
        const stored = await this.store.get('identity');
        if (stored) {
            // Restore identity keys from IndexedDB
            const subtle = globalThis.crypto.subtle;
            const importECDH = async (pubB64, privB64) => {
                const pubRaw = b642ab(pubB64);
                const privRaw = b642ab(privB64);
                const [pub, priv] = await Promise.all([
                    subtle.importKey('raw', pubRaw, { name: 'ECDH', namedCurve: 'P-256' }, true, []),
                    subtle.importKey('pkcs8', privRaw, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']),
                ]);
                return { publicKey: pub, privateKey: priv, publicRaw: pubRaw };
            };
            const importECDSA = async (pubB64, privB64) => {
                const pubRaw = b642ab(pubB64);
                const privRaw = b642ab(privB64);
                const [pub, priv] = await Promise.all([
                    subtle.importKey('raw', pubRaw, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']),
                    subtle.importKey('pkcs8', privRaw, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']),
                ]);
                return { publicKey: pub, privateKey: priv, publicRaw: pubRaw };
            };
            const ikEcdsaPair = await importECDSA(stored.ikEcdsaPub, stored.ikEcdsaPriv);
            const ikEcdhPair = await importECDH(stored.ikEcdhPub, stored.ikEcdhPriv);
            const spkPair = await importECDH(stored.spkPub, stored.spkPriv);
            const spkSig = b642ab(stored.spkSig);
            this.identity = { ikEcdsaPair, ikEcdhPair, spkPair, spkSig, ikPair: ikEcdhPair };
        }
        else {
            this.identity = await generateWebIdentityKeys();
            await this._persistIdentity();
        }
    }
    async _persistIdentity() {
        const subtle = globalThis.crypto.subtle;
        const id = this.identity;
        const [ikEcdsaPrivRaw, ikEcdhPrivRaw, spkPrivRaw] = await Promise.all([
            subtle.exportKey('pkcs8', id.ikEcdsaPair.privateKey),
            subtle.exportKey('pkcs8', id.ikEcdhPair.privateKey),
            subtle.exportKey('pkcs8', id.spkPair.privateKey),
        ]);
        await this.store.set('identity', {
            ikEcdsaPub: ab2b64(id.ikEcdsaPair.publicRaw),
            ikEcdsaPriv: ab2b64(ikEcdsaPrivRaw),
            ikEcdhPub: ab2b64(id.ikEcdhPair.publicRaw),
            ikEcdhPriv: ab2b64(ikEcdhPrivRaw),
            spkPub: ab2b64(id.spkPair.publicRaw),
            spkPriv: ab2b64(spkPrivRaw),
            spkSig: ab2b64(id.spkSig),
        });
    }
    _serializePublicKeys() {
        const id = this.identity;
        return {
            // Publish the ECDSA public key as identityKey (used for SPK signature verification)
            identityKey: ab2b64(id.ikEcdsaPair.publicRaw),
            signedPreKey: ab2b64(id.spkPair.publicRaw),
            signedPreKeySignature: ab2b64(id.spkSig),
            oneTimePreKey: ab2b64(id.ikEcdhPair.publicRaw), // ECDH key as fallback OTK
        };
    }
    async _loadSessions() {
        const keys = await this.store.get('session-keys') ?? [];
        for (const peerId of keys) {
            const raw = await this.store.get(`session-${peerId}`);
            if (raw) {
                try {
                    const session = await deserializeWebSession(raw);
                    this.sessions.set(peerId, session);
                }
                catch { /* corrupt session, skip */ }
            }
        }
    }
    async _saveSession(peerId, session) {
        const serialized = await serializeWebSession(session);
        await this.store.set(`session-${peerId}`, serialized);
        const keys = await this.store.get('session-keys') ?? [];
        if (!keys.includes(peerId)) {
            keys.push(peerId);
            await this.store.set('session-keys', keys);
        }
    }
    async _getOrEstablishSession(peerId) {
        if (this.sessions.has(peerId))
            return this.sessions.get(peerId);
        const peerKeys = await this.relay.getPublicKeys(peerId);
        if (!peerKeys)
            throw new Error(`Peer ${peerId} not found on relay`);
        // identityKey = peer's ECDSA public key (for SPK signature verification)
        const peerIKEcdsaRaw = b642ab(peerKeys.identityKey);
        const peerSPKRaw = b642ab(peerKeys.signedPreKey);
        // oneTimePreKey carries the peer's ECDH identity key for X3DH key agreement
        const peerIKEcdhRaw = peerKeys.oneTimePreKey
            ? b642ab(peerKeys.oneTimePreKey)
            : peerIKEcdsaRaw; // fallback (same peer, old format)
        // Always verify SPK signature using the ECDSA identity key
        const sigRaw = peerKeys.signedPreKeySignature
            ? b642ab(peerKeys.signedPreKeySignature)
            : new ArrayBuffer(0);
        const valid = await verifyWebSPK(peerSPKRaw, sigRaw, peerIKEcdsaRaw);
        if (!valid)
            throw new Error(`SPK signature invalid for ${peerId}`);
        const id = this.identity;
        // Use ECDH key pairs for X3DH key agreement
        const session = await webEstablishSession(id.ikEcdhPair, id.spkPair, peerIKEcdhRaw, peerSPKRaw);
        this.sessions.set(peerId, session);
        await this._saveSession(peerId, session);
        return session;
    }
    async send(recipientId, data) {
        if (!this.alive)
            throw new Error('Client is disconnected');
        const session = await this._getOrEstablishSession(recipientId);
        const { ciphertext, header } = await webEncrypt(session, encodePayload(data));
        await this._saveSession(recipientId, session);
        await this.relay.sendMessage(recipientId, this.userId, ciphertext, header);
    }
    onMessage(handler) {
        this.handlers.add(handler);
        return () => this.handlers.delete(handler);
    }
    async waitForUser(userId, timeoutMs = 10000) {
        const deadline = Date.now() + timeoutMs;
        while (Date.now() < deadline) {
            const keys = await this.relay.getPublicKeys(userId);
            if (keys)
                return true;
            await new Promise(r => setTimeout(r, 500));
        }
        return false;
    }
    getUserId() { return this.userId; }
    disconnect() {
        this.alive = false;
        if (this.pollTimer) {
            clearTimeout(this.pollTimer);
            this.pollTimer = null;
        }
        this.handlers.clear();
    }
    _startPolling() {
        const tick = async () => {
            if (!this.alive)
                return;
            try {
                const messages = await this.relay.fetchMessages(this.userId);
                for (const raw of messages) {
                    try {
                        await this._processRaw(raw);
                    }
                    catch (e) {
                        console.error('[StvorWeb] Failed to process message from', raw.from, e);
                    }
                }
            }
            catch { /* non-fatal network errors */ }
            if (this.alive) {
                this.pollTimer = setTimeout(tick, this.pollIntervalMs);
            }
        };
        tick().catch(() => { });
    }
    async _processRaw(raw) {
        const session = await this._getOrEstablishSession(raw.from);
        const plaintextBuf = await webDecrypt(session, raw.ciphertext, raw.header);
        await this._saveSession(raw.from, session);
        const decoded = decodePayload(plaintextBuf);
        // Delete message from relay after successful decryption
        if (raw.id) {
            await this.relay.deleteMessage(raw.id);
        }
        for (const h of this.handlers) {
            try {
                await h(raw.from, decoded);
            }
            catch (e) {
                console.error('[StvorWeb] Handler error:', e);
            }
        }
    }
}
if (typeof window !== 'undefined') {
    window.StvorWebSDK = StvorWebSDK;
}
export default StvorWebSDK;
