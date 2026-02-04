/**
 * STVOR libsodium Singleton
 * Ensures sodium.ready is called only ONCE globally
 * Prevents race conditions during concurrent initialization
 */

import sodium from 'libsodium-wrappers';

let sodiumInitialized = false;
let sodiumInitPromise: Promise<void> | null = null;

/**
 * Initialize libsodium ONCE globally
 * Safe to call multiple times - returns same promise
 * 
 * @throws Never throws - libsodium.ready is infallible
 */
export async function ensureSodiumReady(): Promise<void> {
  // Already initialized - return immediately
  if (sodiumInitialized) {
    return;
  }

  // Initialization in progress - return existing promise
  if (sodiumInitPromise) {
    return sodiumInitPromise;
  }

  // Start initialization
  sodiumInitPromise = (async () => {
    await sodium.ready;
    sodiumInitialized = true;
    console.log('[Crypto] libsodium initialized');
  })();

  return sodiumInitPromise;
}

/**
 * Check if libsodium is ready (synchronous)
 */
export function isSodiumReady(): boolean {
  return sodiumInitialized;
}

/**
 * Reset state (ONLY for testing)
 */
export function _resetSodiumState(): void {
  sodiumInitialized = false;
  sodiumInitPromise = null;
}
