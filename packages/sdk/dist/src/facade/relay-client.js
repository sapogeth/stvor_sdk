/**
 * STVOR DX Facade - Relay Client
 */
import { Errors, StvorError } from './errors.js';
import * as WS from 'ws';
export class RelayClient {
    constructor(relayUrl, appToken, timeout = 10000) {
        this.connected = false;
        this.handshakeComplete = false;
        this.backoff = 1000;
        this.queue = [];
        this.handlers = [];
        this.reconnecting = false;
        this.authFailed = false;
        this.relayUrl = relayUrl.replace(/^http/, 'ws');
        this.appToken = appToken;
        this.timeout = timeout;
    }
    /**
     * Initialize the connection and wait for handshake.
     * Throws StvorError if API key is rejected.
     */
    async init() {
        if (this.authFailed) {
            throw new StvorError(Errors.INVALID_API_KEY, 'Relay rejected connection: invalid API key');
        }
        if (this.handshakeComplete)
            return;
        await this.connect();
    }
    getAuthHeaders() {
        return {
            Authorization: `Bearer ${this.appToken}`,
        };
    }
    connect() {
        if (this.connectPromise)
            return this.connectPromise;
        if (this.ws)
            return Promise.resolve();
        this.connectPromise = new Promise((resolve, reject) => {
            this.connectResolve = resolve;
            this.connectReject = reject;
            const WSClass = WS.default ?? WS;
            this.ws = new WSClass(this.relayUrl, { headers: this.getAuthHeaders() });
            // Timeout for handshake
            const handshakeTimeout = setTimeout(() => {
                if (!this.handshakeComplete) {
                    this.ws?.close();
                    reject(new StvorError(Errors.RELAY_UNAVAILABLE, 'Relay handshake timeout'));
                }
            }, this.timeout);
            this.ws.on('open', () => {
                this.connected = true;
                this.backoff = 1000;
                // Don't flush queue yet - wait for handshake
            });
            this.ws.on('message', (data) => {
                try {
                    const json = JSON.parse(data.toString());
                    // Handle handshake response
                    if (json.type === 'handshake') {
                        clearTimeout(handshakeTimeout);
                        if (json.status === 'ok') {
                            this.handshakeComplete = true;
                            // Now flush the queue
                            while (this.queue.length) {
                                const m = this.queue.shift();
                                this.doSend(m);
                            }
                            this.connectResolve?.();
                        }
                        else {
                            // Handshake rejected
                            this.authFailed = true;
                            this.ws?.close();
                            const err = new StvorError(Errors.INVALID_API_KEY, `Relay rejected connection: ${json.reason || 'invalid API key'}`);
                            this.connectReject?.(err);
                        }
                        return;
                    }
                    // Regular message
                    for (const h of this.handlers)
                        h(json);
                }
                catch (e) {
                    // ignore parse errors
                }
            });
            this.ws.on('close', (code) => {
                this.connected = false;
                this.handshakeComplete = false;
                this.ws = undefined;
                this.connectPromise = undefined;
                // If auth failed, don't reconnect
                if (this.authFailed) {
                    return;
                }
                // 401/403 close codes mean auth failure
                if (code === 4001 || code === 4003) {
                    this.authFailed = true;
                    this.connectReject?.(new StvorError(Errors.INVALID_API_KEY, 'Relay rejected connection: invalid API key'));
                    return;
                }
                this.scheduleReconnect();
            });
            this.ws.on('error', (err) => {
                this.connected = false;
                this.handshakeComplete = false;
                this.ws = undefined;
                this.connectPromise = undefined;
                if (this.authFailed) {
                    return;
                }
                this.scheduleReconnect();
            });
        });
        return this.connectPromise;
    }
    scheduleReconnect() {
        if (this.reconnecting)
            return;
        this.reconnecting = true;
        setTimeout(() => {
            this.reconnecting = false;
            this.connect();
            this.backoff = Math.min(this.backoff * 2, 30000);
        }, this.backoff);
    }
    doSend(obj) {
        const data = JSON.stringify(obj);
        if (this.connected && this.ws && this.handshakeComplete) {
            this.ws.send(data);
        }
        else {
            this.queue.push(obj);
        }
    }
    send(obj) {
        if (this.authFailed) {
            throw new StvorError(Errors.INVALID_API_KEY, 'Cannot send: relay rejected connection due to invalid API key');
        }
        this.doSend(obj);
    }
    onMessage(h) {
        this.handlers.push(h);
    }
    isConnected() {
        return this.connected && this.handshakeComplete;
    }
    isAuthenticated() {
        return this.handshakeComplete && !this.authFailed;
    }
}
