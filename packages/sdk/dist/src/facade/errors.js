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
};
export class StvorError extends Error {
    constructor(code, message, action, retryable) {
        super(message);
        this.code = code;
        this.action = action;
        this.retryable = retryable;
        this.name = 'StvorError';
    }
}
