/**
 * STVOR DX Facade - Relay Client
 */
import { Errors } from './errors.js';
export class RelayClient {
    constructor(relayUrl, appToken, timeout = 10000) {
        this.connected = false;
        this.relayUrl = relayUrl;
        this.appToken = appToken;
        this.timeout = timeout;
    }
    getAppToken() {
        return this.appToken;
    }
    getBaseUrl() {
        return this.relayUrl;
    }
    getAuthHeaders() {
        return {
            'Authorization': `Bearer ${this.appToken}`,
            'Content-Type': 'application/json',
        };
    }
    async healthCheck() {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        try {
            const res = await fetch(`${this.relayUrl}/health`, {
                method: 'GET',
                signal: controller.signal,
            });
            if (!res.ok) {
                throw Errors.relayUnavailable();
            }
        }
        finally {
            clearTimeout(timeoutId);
        }
    }
    isConnected() {
        return this.connected;
    }
    async register(userId, publicKeys) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        try {
            const res = await fetch(`${this.relayUrl}/register`, {
                method: 'POST',
                headers: this.getAuthHeaders(),
                body: JSON.stringify({ user_id: userId, publicKeys }),
                signal: controller.signal,
            });
            if (!res.ok) {
                const error = await res.json().catch(() => ({}));
                if (error.code === 'AUTH_FAILED') {
                    throw Errors.authFailed();
                }
                throw Errors.relayUnavailable();
            }
            this.connected = true;
        }
        finally {
            clearTimeout(timeoutId);
        }
    }
    async getPublicKeys(userId) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        try {
            const res = await fetch(`${this.relayUrl}/public-key/${userId}`, {
                method: 'GET',
                headers: this.getAuthHeaders(),
                signal: controller.signal,
            });
            if (res.status === 404) {
                return null;
            }
            if (!res.ok) {
                throw Errors.relayUnavailable();
            }
            const data = await res.json();
            return data.publicKeys;
        }
        finally {
            clearTimeout(timeoutId);
        }
    }
    async send(message) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        try {
            const res = await fetch(`${this.relayUrl}/message`, {
                method: 'POST',
                headers: this.getAuthHeaders(),
                body: JSON.stringify({
                    to: message.to,
                    from: message.from,
                    ciphertext: message.ciphertext,
                    header: message.header,
                }),
                signal: controller.signal,
            });
            if (!res.ok) {
                throw Errors.deliveryFailed(message.to);
            }
        }
        finally {
            clearTimeout(timeoutId);
        }
    }
    async fetchMessages(userId) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        try {
            const res = await fetch(`${this.relayUrl}/messages/${userId}`, {
                method: 'GET',
                headers: this.getAuthHeaders(),
                signal: controller.signal,
            });
            if (!res.ok) {
                throw Errors.relayUnavailable();
            }
            const data = await res.json();
            return data.messages || [];
        }
        finally {
            clearTimeout(timeoutId);
        }
    }
    disconnect() {
        this.connected = false;
    }
}
