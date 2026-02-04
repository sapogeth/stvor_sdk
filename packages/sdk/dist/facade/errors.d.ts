export declare const Errors: {
    readonly INVALID_APP_TOKEN: "INVALID_APP_TOKEN";
    readonly INVALID_API_KEY: "INVALID_API_KEY";
    readonly RELAY_UNAVAILABLE: "RELAY_UNAVAILABLE";
    readonly DELIVERY_FAILED: "DELIVERY_FAILED";
    readonly RECIPIENT_NOT_FOUND: "RECIPIENT_NOT_FOUND";
    readonly RECIPIENT_TIMEOUT: "RECIPIENT_TIMEOUT";
    readonly MESSAGE_INTEGRITY_FAILED: "MESSAGE_INTEGRITY_FAILED";
    readonly RECEIVE_TIMEOUT: "RECEIVE_TIMEOUT";
    readonly RECEIVE_IN_PROGRESS: "RECEIVE_IN_PROGRESS";
    readonly NOT_CONNECTED: "NOT_CONNECTED";
};
export type ErrorCode = (typeof Errors)[keyof typeof Errors];
export declare class StvorError extends Error {
    code: ErrorCode;
    action?: string | undefined;
    retryable?: boolean | undefined;
    constructor(code: ErrorCode, message: string, action?: string | undefined, retryable?: boolean | undefined);
}
