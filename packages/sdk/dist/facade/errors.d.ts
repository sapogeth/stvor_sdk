/**
 * STVOR DX Facade - Error Handling
 */
export declare const ErrorCode: {
    readonly AUTH_FAILED: "AUTH_FAILED";
    readonly INVALID_APP_TOKEN: "INVALID_APP_TOKEN";
    readonly RELAY_UNAVAILABLE: "RELAY_UNAVAILABLE";
    readonly RECIPIENT_NOT_FOUND: "RECIPIENT_NOT_FOUND";
    readonly RECIPIENT_TIMEOUT: "RECIPIENT_TIMEOUT";
    readonly CLIENT_NOT_READY: "CLIENT_NOT_READY";
    readonly DELIVERY_FAILED: "DELIVERY_FAILED";
    readonly QUOTA_EXCEEDED: "QUOTA_EXCEEDED";
    readonly RATE_LIMITED: "RATE_LIMITED";
};
export type ErrorCode = typeof ErrorCode[keyof typeof ErrorCode];
export declare class StvorError extends Error {
    code: string;
    action?: string;
    retryable?: boolean;
    constructor(code: string, message: string, action?: string, retryable?: boolean);
}
export declare const Errors: {
    authFailed(): StvorError;
    invalidAppToken(): StvorError;
    relayUnavailable(): StvorError;
    recipientNotFound(userId: string): StvorError;
    messageIntegrityFailed(): StvorError;
    keystoreCorrupted(): StvorError;
    deviceCompromised(): StvorError;
    protocolMismatch(): StvorError;
    recipientTimeout(userId: string, timeoutMs: number): StvorError;
    clientNotReady(): StvorError;
    deliveryFailed(recipientId: string): StvorError;
    quotaExceeded: () => StvorError;
    rateLimited: () => StvorError;
};
