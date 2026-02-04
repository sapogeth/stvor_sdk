/**
 * STVOR DX Facade - Type Definitions
 */

/**
 * AppToken from developer dashboard
 * Replaces "API key" terminology for better DX
 */
export type AppToken = string;

/**
 * Configuration for SDK initialization
 */
export interface StvorAppConfig {
  /** AppToken from STVOR developer dashboard */
  appToken: string;
  
  /** Relay server URL (optional, defaults to stvor.io) */
  relayUrl?: string;
  
  /** Connection timeout in ms (optional, default 10000) */
  timeout?: number;
}

/**
 * User identifier in your application
 * Can be email, username, or UUID
 */
export type UserId = string;

/**
 * Message content - text or binary data
 */
export type MessageContent = string | Uint8Array;

/**
 * Result of receiving a decrypted message
 */
export interface DecryptedMessage {
  /** Unique message identifier */
  id: string;
  
  /** Sender's user ID */
  senderId: UserId;
  
  /** Decrypted content */
  content: MessageContent;
  
  /** Timestamp when message was sent */
  timestamp: Date;
}

/**
 * Sealed payload for encrypting files/binary data
 */
export interface SealedPayload {
  /** Encrypted ciphertext */
  ciphertext: Uint8Array;
  
  /** Nonce used for encryption */
  nonce: Uint8Array;
}
