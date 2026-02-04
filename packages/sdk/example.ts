/**
 * STVOR DX Facade - Quick Start Example
 * 
 * Copy-paste ready example for getting started.
 * 
 * IMPORTANT: This is a DX facade. The actual security guarantees
 * depend on the STVOR core implementation.
 */

import { Stvor, StvorError, DecryptedMessage } from './index.js';

/**
 * Basic messaging example with proper error handling
 */
async function main() {
  try {
    // 1. Initialize SDK with AppToken from environment
    const app = await Stvor.init({
      appToken: process.env.STVOR_APP_TOKEN || 'stvor_demo_abc123...'
    });
    console.log('SDK initialized');

    // 2. Connect as a user
    const alice = await app.connect('alice@example.com');
    console.log(`Connected as ${alice.getUserId()}`);

    // 3. Subscribe to incoming messages (recommended for production)
    const unsubscribe = alice.onMessage((msg: DecryptedMessage) => {
      console.log(`[Push] ${msg.senderId}: ${msg.content}`);
    });

    // 4. Send encrypted message
    await alice.send('bob@example.com', 'Hello Bob!');

    // 5. Cleanup
    await app.disconnect();
    unsubscribe();
    
  } catch (error: unknown) {
    if (error instanceof StvorError) {
      console.error(`[${error.code}] ${error.message}`);
      console.error(`Action: ${error.action}`);
      console.error(`Retryable: ${error.retryable}`);
    } else {
      console.error('Unknown error:', error);
    }
  }
}

/**
 * Note on security guarantees:
 * 
 * The facade provides a convenient API, but actual security
 * (E2EE, PFS, post-quantum resistance) depends on the STVOR core.
 * 
 * For production use, verify:
 * 1. Core implements Double Ratchet for PFS
 * 2. Core implements ML-KEM for post-quantum resistance  
 * 3. Keys are stored securely (not in plain memory)
 * 4. Relay is trusted or verified
 */

// Run example
main();
