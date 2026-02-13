/**
 * STVOR DX Facade - Main Application Classes
 * 
 * Security Guarantees:
 * - X3DH + Double Ratchet (Signal Protocol)
 * - Forward Secrecy via automatic DH ratchet rotation
 * - Post-Compromise Security via forced ratchet steps
 * - TOFU (Trust On First Use) for identity verification
 * - Replay protection via nonce validation
 * - Cryptographically verified metrics (HMAC-SHA256)
 * - libsodium for all cryptographic operations
 */

import { StvorAppConfig, UserId, MessageContent } from './types';
import { DecryptedMessage } from './types';
import { Errors, StvorError, ErrorCode } from './errors';
export type { DecryptedMessage, SealedPayload, ErrorCode };
export { StvorError, Errors };
import { RelayClient } from './relay-client';
import { Counter, Gauge, register } from 'prom-client';
import { CryptoSessionManager } from './crypto-session';
import { verifyFingerprint } from './tofu-manager';
import { validateMessageWithNonce } from './replay-manager';
import { MetricsAttestationEngine, MetricsAttestation } from './metrics-attestation';
import sodium from 'libsodium-wrappers';

// Define Prometheus metrics
const messagesDeliveredTotal = new Counter({
  name: 'messages_delivered_total',
  help: 'Total number of messages successfully delivered',
});

const quotaExceededTotal = new Counter({
  name: 'quota_exceeded_total',
  help: 'Total number of quota exceeded events',
});

const rateLimitedTotal = new Counter({
  name: 'rate_limited_total',
  help: 'Total number of rate-limited events',
});

const activeTokens = new Gauge({
  name: 'active_tokens',
  help: 'Number of currently active tokens',
});

// Export metrics for use in the application
export { messagesDeliveredTotal, quotaExceededTotal, rateLimitedTotal, activeTokens, register };

export class StvorApp {
  private relay: RelayClient;
  private config: Required<StvorAppConfig>;
  private connectedClients: Map<UserId, StvorFacadeClient> = new Map();
  private metricsAttestation: MetricsAttestationEngine;
  private backendUrl: string;
  private appToken: string;

  constructor(config: Required<StvorAppConfig>) {
    this.config = config;
    this.relay = new RelayClient(config.relayUrl, config.appToken, config.timeout);
    this.metricsAttestation = new MetricsAttestationEngine(config.appToken);
    this.appToken = config.appToken;
    this.backendUrl = (config as any).backendUrl || 'http://localhost:3000';
  }

  isReady(): boolean {
    return this.relay.isConnected();
  }

  /**
   * Get attestation engine for recording metrics
   */
  getMetricsAttestationEngine(): MetricsAttestationEngine {
    return this.metricsAttestation;
  }

  /**
   * Periodically send metrics attestations to backend
   * Backend verifies and stores only valid attestations
   */
  async sendMetricsAttestation(): Promise<void> {
    const attestation = this.metricsAttestation.createAttestation();

    try {
      const response = await fetch(`${this.backendUrl}/api/metrics/attest`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          appToken: this.appToken,
          attestation,
        }),
      });

      if (!response.ok) {
        const error = await response.json();
        console.error('[STVOR] Metrics attestation rejected:', error.reason);
        return;
      }

      console.debug('[STVOR] Metrics attestation verified and stored');
    } catch (error) {
      console.error('[STVOR] Failed to send metrics attestation:', error);
    }
  }

  /**
   * Flush metrics to backend
   * Sends current metrics attestation (if there is any activity)
   * Called explicitly by user or on disconnect
   */
  async flushMetrics(): Promise<void> {
    await this.sendMetricsAttestation().catch(err =>
      console.debug('[STVOR] Metrics flush failed:', err)
    );
  }

  async connect(userId: UserId): Promise<StvorFacadeClient> {
    const existingClient = this.connectedClients.get(userId);
    if (existingClient) {
      console.warn(`[STVOR] Warning: User "${userId}" is already connected. Returning cached client.`);
      return existingClient;
    }

    const client = new StvorFacadeClient(userId, this.relay, this.metricsAttestation);
    await this.initClient(client);
    this.connectedClients.set(userId, client);
    return client;
  }

  async disconnect(userId?: UserId): Promise<void> {
    if (userId) {
      const client = this.connectedClients.get(userId);
      if (client) {
        await client.disconnect();
        this.connectedClients.delete(userId);
      }
    } else {
      for (const client of this.connectedClients.values()) {
        await client.disconnect();
      }
      this.connectedClients.clear();
      this.relay.disconnect();
      // Flush any pending metrics before disconnect
      await this.flushMetrics();
    }
  }

  private async initClient(client: StvorFacadeClient): Promise<void> {
    await client.internalInitialize();
  }
}

export class StvorFacadeClient {
  private userId: UserId;
  private relay: RelayClient;
  private metricsAttestation: MetricsAttestationEngine;
  private initialized: boolean = false;
  private cryptoSession: CryptoSessionManager;
  private messageHandlers: Map<string, (msg: DecryptedMessage) => void> = new Map();
  private messageQueue: any[] = [];
  private isReceiving: boolean = false;

  constructor(userId: UserId, relay: RelayClient, metricsAttestation: MetricsAttestationEngine) {
    this.userId = userId;
    this.relay = relay;
    this.metricsAttestation = metricsAttestation;
    this.cryptoSession = new CryptoSessionManager(userId);
  }

  async internalInitialize(): Promise<void> {
    await this.initialize();
  }

  private async initialize(): Promise<void> {
    if (this.initialized) return;

    // Initialize libsodium and generate identity keys
    await this.cryptoSession.initialize();

    // Get serialized public keys for relay registration
    const publicKeys = this.cryptoSession.getPublicKeys();

    // Register with relay server
    await this.relay.register(this.userId, publicKeys);

    this.initialized = true;
    this.startMessagePolling();
  }

  /**
   * Send an encrypted message to a recipient.
   *
   * By default, if the recipient is not yet registered, the method will
   * poll up to `options.timeout` ms for their keys to appear on the relay.
   * Set `options.waitForRecipient: false` to throw immediately instead.
   *
   * @param recipientId  - The recipient's user ID
   * @param content      - Message content (string or Uint8Array)
   * @param options      - Optional settings:
   *   - `timeout`           — Max wait time in ms (default: 10 000)
   *   - `waitForRecipient`  — Auto-wait for recipient keys (default: true)
   */
  async send(
    recipientId: UserId,
    content: MessageContent,
    options?: { timeout?: number; waitForRecipient?: boolean }
  ): Promise<void> {
    if (!this.initialized) {
      throw Errors.clientNotReady();
    }

    const { timeout = 10_000, waitForRecipient = true } = options ?? {};

    // Check quota for production tokens (skip for local dev tokens)
    const appToken = this.relay.getAppToken();
    if (!appToken.startsWith('stvor_local_') && !appToken.startsWith('stvor_dev_')) {
      const quota = await this.checkQuota();
      if (quota && quota.used >= quota.limit && quota.limit !== -1) {
        quotaExceededTotal.inc();
        throw Errors.quotaExceeded();
      }
    }

    const contentBytes: Uint8Array = typeof content === 'string' 
      ? new TextEncoder().encode(content) 
      : content;

    // Ensure session with recipient exists
    if (!this.cryptoSession.hasSession(recipientId)) {
      // Fetch recipient's public keys (with optional polling)
      let recipientPublicKeys = await this.relay.getPublicKeys(recipientId);

      // If not found and waitForRecipient is enabled, poll until timeout
      if (!recipientPublicKeys && waitForRecipient) {
        recipientPublicKeys = await this.waitForRecipientKeys(recipientId, timeout);
      }

      if (!recipientPublicKeys) {
        throw Errors.recipientNotFound(recipientId);
      }

      // TOFU: Verify fingerprint (throws on mismatch)
      const recipientIdentityKey = sodium.from_base64(recipientPublicKeys.identityKey);
      await verifyFingerprint(recipientId, recipientIdentityKey);

      // Establish X3DH session
      await this.cryptoSession.establishSessionWithPeer(recipientId, recipientPublicKeys);
    }

    // Encrypt using Double Ratchet
    const plaintext = new TextDecoder().decode(contentBytes);
    const { ciphertext, header } = await this.cryptoSession.encryptForPeer(recipientId, plaintext);

    // METRIC: Record successful encryption (AFTER AEAD completes)
    this.metricsAttestation.recordMessageEncrypted();

    try {
      await this.relay.send({
        to: recipientId,
        from: this.userId,
        ciphertext,
        header,
      });
      messagesDeliveredTotal.inc();
    } catch (e: any) {
      if (e.code === 'QUOTA_EXCEEDED') {
        quotaExceededTotal.inc();
        throw Errors.quotaExceeded();
      }
      throw e;
    }
  }

  /**
   * Check current quota usage from the relay server
   */
  private async checkQuota(): Promise<{ used: number; limit: number } | null> {
    try {
      const response = await fetch(`${this.relay.getBaseUrl()}/usage`, {
        headers: { 
          'Authorization': `Bearer ${this.relay.getAppToken()}` 
        },
      });
      if (!response.ok) return null;
      return await response.json();
    } catch {
      // If quota check fails, allow the request (fail open for availability)
      return null;
    }
  }

  /**
   * Wait for a specific recipient's public keys to become available on the relay.
   * Polls the relay at 500ms intervals until the keys appear or timeout expires.
   *
   * @param recipientId - The user ID of the recipient
   * @param timeoutMs   - Max time to wait in milliseconds (default: 10000)
   * @returns The recipient's serialized public keys, or null if timeout
   */
  async waitForUser(recipientId: UserId, timeoutMs: number = 10_000): Promise<boolean> {
    const keys = await this.waitForRecipientKeys(recipientId, timeoutMs);
    return keys !== null;
  }

  private async waitForRecipientKeys(
    recipientId: UserId,
    timeoutMs: number,
  ): Promise<import('./crypto-session').SerializedPublicKeys | null> {
    const start = Date.now();
    const pollInterval = 500;

    while (Date.now() - start < timeoutMs) {
      const keys = await this.relay.getPublicKeys(recipientId);
      if (keys) return keys;
      await new Promise(resolve => setTimeout(resolve, pollInterval));
    }

    return null;
  }

  // Note: blocking receive()/seal()/open() APIs are NOT part of SDK v0.1 facade.
  // Use onMessage() for incoming messages and send() to transmit messages.

  onMessage(handler: (msg: DecryptedMessage) => void): () => void {
    const id = crypto.randomUUID();
    this.messageHandlers.set(id, handler);
    return () => {
      this.messageHandlers.delete(id);
    };
  }

  getUserId(): UserId {
    returcryptoSession.destroy();
    this.messageQueue = [];
    this.isReceiving = false;
  }

  private async decryptMessage(msg: { 
    from: string; 
    ciphertext: number[]; 
    header: { publicKey: number[]; nonce: number[] }; 
    timestamp: string; 
    id?: string 
  }): Promise<DecryptedMessage> {
    // Ensure session with sender exists
    if (!this.cryptoSession.hasSession(msg.from)) {
      // Fetch sender's public keys
      const senderPublicKeys = await this.relay.getPublicKeys(msg.from);
      if (!senderPublicKeys) {
        throw Errors.recipientNotFound(msg.from);
      }

      // TOFU: Verify fingerprint (throws on mismatch)
      const senderIdentityKey = sodium.from_base64(senderPublicKeys.identityKey);
      await verifyFingerprint(msg.from, senderIdentityKey);

      // Establish X3DH session
      await this.cryptoSession.establishSessionWithPeer(msg.from, senderPublicKeys);
    }

    // Replay protection: Validate nonce
    const nonce = new Uint8Array(msg.header.nonce);
    const timestamp = Math.floor(new Date(msg.timestamp).getTime() / 1000);
    
    try {
      await validateMessageWithNonce(msg.from, nonce, timestamp);
    } catch (e) {
      // METRIC: Record replay attempt
      this.metricsAttestation.recordReplayAttempt();
      throw e; // Re-throw to prevent decryption
    }

    // Decrypt using Double Ratchet
    try {
      const ciphertext = new Uint8Array(msg.ciphertext);
      const header = {
        publicKey: new Uint8Array(msg.header.publicKey),
        nonce: new Uint8Array(msg.header.nonce),
      };

      const plaintext = await this.cryptoSession.decryptFromPeer(
        msg.from,
        ciphertext,
        header
      );

      // METRIC: Record successful decryption (AFTER AAD verification)
      this.metricsAttestation.recordMessageDecrypted();

      return {
        id: msg.id || crypto.randomUUID(),
        senderId: msg.from,
        content: plaintext,
        timestamp: new Date(msg.timestamp),
      };
    } catch (e) {
      // METRIC: Record failed decryption (auth failure)
      this.metricsAttestation.recordMessageRejected();
      
      // Decryption failed — surface as delivery failure
      throw Errors.deliveryFailed(msg.from);
    }
  }

  private startMessagePolling(): void {
    const poll = async () => {
      try {
        const messages = await this.relay.fetchMessages(this.userId);
        
        if (messages.length > 0) {
          const msg = await this.decryptMessage(messages[0]);
          
          for (const handler of this.messageHandlers.values()) {
            try {
              handler(msg);
            } catch {
              // Handler error does not break other handlers
            }
          }
        }
      } catch {
        // Silent error on poll
      }
      
      if (this.initialized) {
        setTimeout(poll, 1000);
      }
    };
    
    poll();
  }
}

export async function init(config: StvorAppConfig): Promise<StvorApp> {
  const relayUrl = config.relayUrl || 'https://relay.stvor.io';
  const timeout = config.timeout || 10000;

  if (!config.appToken || !config.appToken.startsWith('stvor_')) {
    throw Errors.invalidAppToken();
  }

  const appConfig: Required<StvorAppConfig> = {
    appToken: config.appToken,
    relayUrl,
    timeout,
  };

  const app = new StvorApp(appConfig);

  try {
    const relay = new RelayClient(relayUrl, config.appToken, timeout);
    await relay.healthCheck();
  } catch {
    throw Errors.relayUnavailable();
  }

  return app;
}

// Alias for createApp
export const createApp = init;

export const Stvor = {
  init,
  createApp,
};

async function processDelivery(messageId, appToken) {
  await db.query(`
    BEGIN;

    WITH inserted AS (
      INSERT INTO message_deliveries (message_id, app_token, delivered_at)
      VALUES ($1, $2, now())
      ON CONFLICT DO NOTHING
      RETURNING 1
    )
    UPDATE app_tokens
    SET used_messages = used_messages + 1
    WHERE app_token = $2
      AND plan != 'unlimited'
      AND used_messages < monthly_message_limit
      AND EXISTS (SELECT 1 FROM inserted);

    COMMIT;
  `, [messageId, appToken]);
}
