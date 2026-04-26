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
                    ...(message.pqcCt ? { pqcCt: message.pqcCt } : {}),
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
    async deleteMessage(messageId) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        try {
            const res = await fetch(`${this.relayUrl}/message/${messageId}`, {
                method: 'DELETE',
                headers: this.getAuthHeaders(),
                signal: controller.signal,
            });
            if (!res.ok && res.status !== 404) {
                // 404 is ok - message already deleted
                throw Errors.relayUnavailable();
            }
        }
        finally {
            clearTimeout(timeoutId);
        }
    }
    async deleteUser(userId) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        try {
            const res = await fetch(`${this.relayUrl}/user/${encodeURIComponent(userId)}`, {
                method: 'DELETE',
                headers: this.getAuthHeaders(),
                signal: controller.signal,
            });
            if (!res.ok)
                throw new Error('Failed to delete user data');
            return await res.json();
        }
        finally {
            clearTimeout(timeoutId);
        }
    }
    async exportUserData(userId) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        try {
            const res = await fetch(`${this.relayUrl}/user/${encodeURIComponent(userId)}/export`, {
                method: 'GET',
                headers: this.getAuthHeaders(),
                signal: controller.signal,
            });
            if (!res.ok)
                throw new Error('Failed to export user data');
            return await res.json();
        }
        finally {
            clearTimeout(timeoutId);
        }
    }
    async sendToGroup(message) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        try {
            const res = await fetch(`${this.relayUrl}/group/${message.groupId}/message`, {
                method: 'POST',
                headers: this.getAuthHeaders(),
                body: JSON.stringify({
                    from: message.from,
                    members: message.members,
                    ciphertext: message.ciphertext,
                    groupHeader: message.groupHeader,
                }),
                signal: controller.signal,
            });
            if (!res.ok)
                throw Errors.deliveryFailed(message.groupId);
        }
        finally {
            clearTimeout(timeoutId);
        }
    }
    async sendSenderKeyDistribution(payload, recipientId) {
        // Sender key distribution is sent as a special 1-to-1 message with a marker header
        // The recipient's stvor.ts will detect the __SKD__ prefix and install it
        await this.send({
            to: recipientId,
            from: payload.from,
            ciphertext: Buffer.from(JSON.stringify(payload)).toString('base64url'),
            header: Buffer.from('__SKD__').toString('base64url'),
        });
    }
    disconnect() {
        this.connected = false;
    }
}
