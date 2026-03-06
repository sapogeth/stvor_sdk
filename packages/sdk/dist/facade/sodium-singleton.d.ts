/**
 * STVOR libsodium Singleton
 * Ensures sodium.ready is called only ONCE globally
 * Prevents race conditions during concurrent initialization
 */
/**
 * Initialize libsodium ONCE globally
 * Safe to call multiple times - returns same promise
 *
 * @throws Never throws - libsodium.ready is infallible
 */
export declare function ensureSodiumReady(): Promise<void>;
/**
 * Check if libsodium is ready (synchronous)
 */
export declare function isSodiumReady(): boolean;
/**
 * Reset state (ONLY for testing)
 */
export declare function _resetSodiumState(): void;
