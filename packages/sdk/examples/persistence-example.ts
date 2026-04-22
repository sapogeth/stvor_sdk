/**
 * Example: Using STVOR SDK with File-Based Persistent Storage
 * 
 * Perfect for:
 * - Server applications
 * - CLI tools  
 * - Desktop apps
 * 
 * Keys and sessions are encrypted and saved to disk,
 * so they survive app restarts.
 */

import { CryptoSessionManager, FileIdentityStore, FileSessionStore } from '@stvor/sdk';

// Setup encrypted file storage for keys and sessions
const keyStore = new FileIdentityStore({
  directory: './keys',
  masterPassword: process.env.MASTER_PASSWORD || 'your-secure-password',
});

const sessionStore = new FileSessionStore({
  directory: './sessions',
  masterPassword: process.env.MASTER_PASSWORD || 'your-secure-password',
});

// Create crypto manager with persistence
const crypto = new CryptoSessionManager(
  'alice@example.com',
  keyStore,      // Identity keys are persisted
  sessionStore   // Session states are persisted
);

// Initialize - loads from disk if exists, or generates new keys
await crypto.initialize();

// Keys now survive app restarts!
console.log('Identity keys loaded/created');

// Session Example 1: Create new session
const bobPublicKeys = {
  identityKey: 'bob-ik-base64url...',
  signedPreKey: 'bob-spk-base64url...',
  signedPreKeySignature: 'bob-sig-base64url...',
  oneTimePreKey: '',
};

await crypto.establishSession('bob@example.com', bobPublicKeys);
console.log('✓ Session with Bob established and persisted');

// Encrypt message
const { ciphertext, header } = crypto.encryptForPeer(
  'bob@example.com',
  'Hello Bob! This is encrypted.'
);

console.log('✓ Message encrypted');

// ============================================================
// Later, after app restart or new process:
// ============================================================

// Reinitialize - loads persisted keys and sessions from disk
const crypto2 = new CryptoSessionManager(
  'alice@example.com',
  keyStore,
  sessionStore
);

await crypto2.initialize();

// Identity keys are loaded from disk
const aliceKeys = crypto2.getPublicKeys();
console.log('✓ Keys loaded from persistent storage');

// Session with Bob is loaded from disk
if (crypto2.hasSession('bob@example.com')) {
  console.log('✓ Session with Bob loaded - can decrypt messages!');
  
  // Decrypt message (using loaded session state)
  const plaintext = crypto2.decryptFromPeer(
    'bob@example.com',
    ciphertext,
    header
  );
  console.log('✓ Decrypted:', plaintext);
}

// ============================================================
// Advanced: Easy API with persistence
// ============================================================

import { StvorEasyAPI } from '@stvor/sdk';

// Coming soon: StvorEasyAPI will support persistent stores
// const api = await StvorEasyAPI.init({
//   appToken: 'your-token',
//   userId: 'alice@example.com',
//   identityStore: keyStore,
//   sessionStore: sessionStore,
// });

console.log('\n✅ Persistence example complete!');
console.log('Check ./keys and ./sessions for encrypted files');
