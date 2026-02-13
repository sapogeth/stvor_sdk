/**
 * STVOR DX Facade - Error Handling
 */

export const ErrorCode = {
  AUTH_FAILED: 'AUTH_FAILED',
  INVALID_APP_TOKEN: 'INVALID_APP_TOKEN',
  RELAY_UNAVAILABLE: 'RELAY_UNAVAILABLE',
  RECIPIENT_NOT_FOUND: 'RECIPIENT_NOT_FOUND',
  RECIPIENT_TIMEOUT: 'RECIPIENT_TIMEOUT',
  CLIENT_NOT_READY: 'CLIENT_NOT_READY',
  DELIVERY_FAILED: 'DELIVERY_FAILED',
  QUOTA_EXCEEDED: 'QUOTA_EXCEEDED',
  RATE_LIMITED: 'RATE_LIMITED',
} as const;

export type ErrorCode = typeof ErrorCode[keyof typeof ErrorCode];

export class StvorError extends Error {
  code: string;
  action?: string;
  retryable?: boolean;

  constructor(code: string, message: string, action?: string, retryable?: boolean) {
    super(message);
    this.name = 'StvorError';
    this.code = code;
    this.action = action;
    this.retryable = retryable;
  }
}

export const Errors = {
  authFailed(): StvorError {
    return new StvorError(
      ErrorCode.AUTH_FAILED,
      'The AppToken is invalid or has been revoked.',
      'Check your dashboard and regenerate a new AppToken.',
      false
    );
  },

  invalidAppToken(): StvorError {
    return new StvorError(
      ErrorCode.INVALID_APP_TOKEN,
      'Invalid AppToken format. AppToken must start with "stvor_".',
      'Get your AppToken from the developer dashboard.',
      false
    );
  },

  relayUnavailable(): StvorError {
    return new StvorError(
      ErrorCode.RELAY_UNAVAILABLE,
      'Cannot connect to STVOR relay server.',
      'Check your internet connection.',
      true
    );
  },

  recipientNotFound(userId: string): StvorError {
    return new StvorError(
      ErrorCode.RECIPIENT_NOT_FOUND,
      `User "${userId}" not found. They may not have registered with STVOR.`,
      'Ask the recipient to initialize STVOR first, or verify the userId is correct.',
      false
    );
  },

  messageIntegrityFailed(): StvorError {
    return new StvorError(
      ErrorCode.DELIVERY_FAILED,
      'Message integrity check failed or decryption failed.',
      'Request the message again from the sender.',
      false
    );
  },

  keystoreCorrupted(): StvorError {
    return new StvorError(
      ErrorCode.DELIVERY_FAILED,
      'Local keystore error (not supported in v0.1).',
      'Investigate local storage configuration.',
      false
    );
  },

  deviceCompromised(): StvorError {
    return new StvorError(
      ErrorCode.DELIVERY_FAILED,
      'Device compromise detected (placeholder).',
      'Investigate and revoke credentials.',
      false
    );
  },

  protocolMismatch(): StvorError {
    return new StvorError(
      ErrorCode.DELIVERY_FAILED,
      'Protocol version mismatch.',
      'Update the SDK to the latest version.',
      false
    );
  },

  recipientTimeout(userId: string, timeoutMs: number): StvorError {
    return new StvorError(
      ErrorCode.RECIPIENT_TIMEOUT,
      `Timed out waiting for user "${userId}" after ${timeoutMs}ms. ` +
      `The user may not have registered with STVOR yet.`,
      'Ensure the recipient has called connect() and is online, or increase the timeout.',
      true
    );
  },

  clientNotReady(): StvorError {
    return new StvorError(
      ErrorCode.CLIENT_NOT_READY,
      'Client is not ready. Call connect() first and await it.',
      'Make sure to await app.connect() before sending messages.',
      false
    );
  },

  deliveryFailed(recipientId: string): StvorError {
    return new StvorError(
      ErrorCode.DELIVERY_FAILED,
      `Failed to deliver message to ${recipientId}.`,
      'Check that the recipient exists and try again.',
      true
    );
  },

  quotaExceeded: () => new StvorError({
    code: 'QUOTA_EXCEEDED',
    message: 'Message quota exceeded for this AppToken.',
    action: 'UPGRADE_PLAN',
    retryable: false,
  }),

  rateLimited: () => new StvorError({
    code: 'RATE_LIMITED',
    message: 'Rate limit exceeded. Please try again later.',
    action: 'WAIT',
    retryable: true,
  }),
  // receive()/timeout APIs are not part of SDK v0.1 facade; use onMessage().
};
