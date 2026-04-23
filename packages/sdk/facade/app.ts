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
 * - Node.js crypto for all cryptographic operations
 */

import { StvorAppConfig, UserId, MessageContent } from './types';
import { DecryptedMessage } from './types';
import { Errors, StvorError, ErrorCode } from './errors';
import { SealedPayload } from './types';
export type { DecryptedMessage, SealedPayload, ErrorCode };
export { StvorError, Errors };
import { RelayClient } from './relay-client';
import { CryptoSessionManager } from './crypto-session';
import { verifyFingerprint } from './tofu-manager';
import { validateMessageWithNonce } from './replay-manager';
import { MetricsAttestationEngine } from './metrics-attestation';

// Simple in-memory counters (no external dependencies)
const _counters = { delivered: 0, quotaExceeded: 0, rateLimited: 0 };
const messagesDeliveredTotal = { inc: () => _counters.delivered++ };
const quotaExceededTotal     = { inc: () => _counters.quotaExceeded++ };
const rateLimitedTotal       = { inc: () => _counters.rateLimited++ };
export { messagesDeliveredTotal, quotaExceededTotal, rateLimitedTotal };

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
    this.backendUrl = (config as any).backendUrl || '';
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
    // Non-critical: silently ignore all errors
    try {
      const attestation = this.metricsAttestation.createAttestation();
      const response = await fetch(`${this.backendUrl}/api/metrics/attest`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          appToken: this.appToken,
          attestation,
        }),
      });
      void response; // ignore response
    } catch {
      // Non-critical — swallow silently
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
      const recipientIdentityKey = Buffer.from(recipientPublicKeys.identityKey, 'base64url');
      await verifyFingerprint(recipientId, recipientIdentityKey);

      // Establish X3DH session
      await this.cryptoSession.establishSessionWithPeer(recipientId, recipientPublicKeys);
    }

    // Encrypt using Double Ratchet
    const plaintext = new TextDecoder().decode(contentBytes);
    const { ciphertext, header } = this.cryptoSession.encryptForPeer(recipientId, plaintext);

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
    return this.userId;
  }

  private async decryptMessage(msg: { 
    from: string; 
    ciphertext: string; 
    header: string; 
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
      const senderIdentityKey = Buffer.from(senderPublicKeys.identityKey, 'base64url');
      await verifyFingerprint(msg.from, senderIdentityKey);

      // Establish X3DH session
      await this.cryptoSession.establishSessionWithPeer(msg.from, senderPublicKeys);
    }

    // Replay protection: extract nonce from header (bytes 73-84)
    const headerBuf = Buffer.from(msg.header, 'base64url');
    const nonce = headerBuf.subarray(73, 85);
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
      const plaintext = this.cryptoSession.decryptFromPeer(
        msg.from,
        msg.ciphertext,
        msg.header,
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

        for (const raw of messages) {
          try {
            const msg = await this.decryptMessage(raw);
            for (const handler of this.messageHandlers.values()) {
              try {
                handler(msg);
              } catch (err) {
                console.error('[StvorApp] Handler error:', err);
              }
            }
          } catch (err) {
            console.error('[StvorApp] Failed to decrypt message from', raw.from, ':', err);
          }
        }
      } catch (err) {
        console.error('[StvorApp] Poll error:', err);
      }

      if (this.initialized) {
        setTimeout(poll, 1000);
      }
    };

    poll().catch(err => console.error('[StvorApp] Polling failed:', err));
  }

  /**
   * Disconnect the client from the relay server.
   */
  async disconnect(): Promise<void> {
    this.initialized = false;
    // Stop message polling
    // Note: The polling interval will naturally stop checking once initialized is false
  }
}

export async function init(config: StvorAppConfig): Promise<StvorApp> {
  const relayUrl = config.relayUrl || 'https://sdk-relay-production.up.railway.app';
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
  } catch (err) {
    console.error('[StvorApp] Relay health check failed:', err);
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
