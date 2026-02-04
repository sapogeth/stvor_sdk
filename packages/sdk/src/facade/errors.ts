

export const Errors = {
  INVALID_APP_TOKEN: 'INVALID_APP_TOKEN',
  INVALID_API_KEY: 'INVALID_API_KEY',
  RELAY_UNAVAILABLE: 'RELAY_UNAVAILABLE',
  DELIVERY_FAILED: 'DELIVERY_FAILED',
  RECIPIENT_NOT_FOUND: 'RECIPIENT_NOT_FOUND',
  RECIPIENT_TIMEOUT: 'RECIPIENT_TIMEOUT',
  MESSAGE_INTEGRITY_FAILED: 'MESSAGE_INTEGRITY_FAILED',
  RECEIVE_TIMEOUT: 'RECEIVE_TIMEOUT',
  RECEIVE_IN_PROGRESS: 'RECEIVE_IN_PROGRESS',
  NOT_CONNECTED: 'NOT_CONNECTED',
} as const;

export type ErrorCode = (typeof Errors)[keyof typeof Errors];

export class StvorError extends Error {
  constructor(
    public code: ErrorCode,
    message: string,
    public action?: string,
    public retryable?: boolean
  ) {
    super(message);
    this.name = 'StvorError';
  }
}

