/**
 * STVOR DX Facade - Relay Client
 */

import { Errors } from './errors';
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
  // group fields (present only on group messages)
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

export class RelayClient {
  private relayUrl: string;
  private timeout: number;
  private appToken: string;
  private connected: boolean = false;

  constructor(relayUrl: string, appToken: string, timeout: number = 10000) {
    this.relayUrl = relayUrl;
    this.appToken = appToken;
    this.timeout = timeout;
  }

  getAppToken(): string {
    return this.appToken;
  }

  getBaseUrl(): string {
    return this.relayUrl;
  }

  private getAuthHeaders(): Record<string, string> {
    return {
      'Authorization': `Bearer ${this.appToken}`,
      'Content-Type': 'application/json',
    };
  }

  async healthCheck(): Promise<void> {
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
    } finally {
      clearTimeout(timeoutId);
    }
  }

  isConnected(): boolean {
    return this.connected;
  }

  async register(userId: string, publicKeys: SerializedPublicKeys): Promise<void> {
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
    } finally {
      clearTimeout(timeoutId);
    }
  }

  async getPublicKeys(userId: string): Promise<SerializedPublicKeys | null> {
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
      return data.publicKeys as SerializedPublicKeys;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  async send(message: OutgoingMessage): Promise<void> {
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
    } finally {
      clearTimeout(timeoutId);
    }
  }

  async fetchMessages(userId: string): Promise<IncomingMessage[]> {
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
    } finally {
      clearTimeout(timeoutId);
    }
  }

  async deleteMessage(messageId: string): Promise<void> {
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
    } finally {
      clearTimeout(timeoutId);
    }
  }

  async deleteUser(userId: string): Promise<{ deletedAt: string; messagesDeleted: number }> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);
    try {
      const res = await fetch(`${this.relayUrl}/user/${encodeURIComponent(userId)}`, {
        method: 'DELETE',
        headers: this.getAuthHeaders(),
        signal: controller.signal,
      });
      if (!res.ok) throw new Error('Failed to delete user data');
      return await res.json();
    } finally {
      clearTimeout(timeoutId);
    }
  }

  async exportUserData(userId: string): Promise<unknown> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);
    try {
      const res = await fetch(`${this.relayUrl}/user/${encodeURIComponent(userId)}/export`, {
        method: 'GET',
        headers: this.getAuthHeaders(),
        signal: controller.signal,
      });
      if (!res.ok) throw new Error('Failed to export user data');
      return await res.json();
    } finally {
      clearTimeout(timeoutId);
    }
  }

  async sendToGroup(message: OutgoingGroupMessage): Promise<void> {
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
      if (!res.ok) throw Errors.deliveryFailed(message.groupId);
    } finally {
      clearTimeout(timeoutId);
    }
  }

  async sendSenderKeyDistribution(payload: SenderKeyDistributionPayload, recipientId: string): Promise<void> {
    // Sender key distribution is sent as a special 1-to-1 message with a marker header
    // The recipient's stvor.ts will detect the __SKD__ prefix and install it
    await this.send({
      to: recipientId,
      from: payload.from,
      ciphertext: Buffer.from(JSON.stringify(payload)).toString('base64url'),
      header: Buffer.from('__SKD__').toString('base64url'),
    });
  }

  disconnect(): void {
    this.connected = false;
  }
}
