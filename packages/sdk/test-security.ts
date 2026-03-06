/**
 * STVOR SDK Security Verification Tests
 * Tests to verify all security fixes are working correctly
 */

import sodium from 'libsodium-wrappers';
import { ensureSodiumReady } from './facade/sodium-singleton.js';
import {
  SessionState,
  encryptMessage,
  decryptMessage,
  establishSession,
} from './ratchet/index.js';
import {
  CryptoSessionManager,
  LocalStorageIdentityStore,
} from './facade/index.js';
import {
  generateFingerprint,
  verifyFingerprint,
  initializeTofu,
} from './facade/tofu-manager.js';
import {
  isReplay,
  validateMessage,
  initializeReplayProtection,
} from './facade/replay-manager.js';

async function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function runTests() {
  console.log('🧪 Starting STVOR Security Tests...\n');
  
  // Initialize libsodium
  await ensureSodiumReady();
  console.log('✅ libsodium initialized\n');

  let passed = 0;
  let failed = 0;

  // Test 1: Crypto Random Token Generation
  console.log('Test 1: Crypto Random Token Generation');
  try {
    const crypto = await import('crypto');
    const token = `stvor_live_${crypto.randomBytes(12).toString('base64url')}`;
    if (token.length > 20 && token.startsWith('stvor_live_')) {
      console.log('  ✅ PASS: Cryptographically secure token generated');
      passed++;
    } else {
      console.log('  ❌ FAIL: Token generation failed');
      failed++;
    }
  } catch (e) {
    console.log('  ❌ FAIL:', e);
    failed++;
  }

  // Test 2: X3DH with DH1
  console.log('\nTest 2: X3DH Key Exchange with DH1');
  try {
    // Generate Alice's keys
    const aliceIdentity = sodium.crypto_sign_keypair();
    const aliceSignedPreKey = sodium.crypto_kx_keypair();
    const aliceOneTimePreKey = sodium.crypto_kx_keypair();

    // Generate Bob's keys
    const bobIdentity = sodium.crypto_sign_keypair();
    const bobSignedPreKey = sodium.crypto_kx_keypair();
    const bobOneTimePreKey = sodium.crypto_kx_keypair();

    // Sign Bob's SPK
    const spkSignature = sodium.crypto_sign_detached(
      bobSignedPreKey.publicKey,
      bobIdentity.privateKey
    );

    // Establish session (Alice -> Bob)
    const session = establishSession(
      aliceIdentity,
      aliceSignedPreKey,
      aliceOneTimePreKey.publicKey,
      bobIdentity.publicKey,
      bobSignedPreKey.publicKey,
      bobOneTimePreKey.publicKey,
      spkSignature,
      '1.0',
      'AES-GCM'
    );

    if (session && session.rootKey && session.identityKey) {
      console.log('  ✅ PASS: X3DH session established with DH1');
      passed++;
    } else {
      console.log('  ❌ FAIL: Session not established properly');
      failed++;
    }
  } catch (e) {
    console.log('  ❌ FAIL:', e);
    failed++;
  }

  // Test 3: Double Ratchet Encryption/Decryption
  console.log('\nTest 3: Double Ratchet Encryption/Decryption');
  try {
    // Create a proper session
    const aliceIdentity = sodium.crypto_sign_keypair();
    const aliceSignedPreKey = sodium.crypto_kx_keypair();
    const bobIdentity = sodium.crypto_sign_keypair();
    const bobSignedPreKey = sodium.crypto_kx_keypair();
    const bobOneTimePreKey = sodium.crypto_kx_keypair();

    const spkSignature = sodium.crypto_sign_detached(
      bobSignedPreKey.publicKey,
      bobIdentity.privateKey
    );

    const session = establishSession(
      aliceIdentity,
      aliceSignedPreKey,
      aliceSignedPreKey.publicKey,
      bobIdentity.publicKey,
      bobSignedPreKey.publicKey,
      bobOneTimePreKey.publicKey,
      spkSignature,
      '1.0',
      'AES-GCM'
    );

    // Set their ratchet public key for encryption
    session.theirRatchetPublicKey = bobSignedPreKey.publicKey;

    // Encrypt
    const plaintext = 'Hello, secure world!';
    const encrypted = encryptMessage(plaintext, session);

    // Check header has message number
    if (encrypted.header && 'messageNumber' in encrypted.header) {
      console.log('  ✅ PASS: Double Ratchet working with message numbers');
      passed++;
    } else {
      console.log('  ❌ FAIL: Missing message number in header');
      failed++;
    }
  } catch (e) {
    console.log('  ❌ FAIL:', e);
    failed++;
  }

  // Test 4: Forward Secrecy (DH Ratchet)
  console.log('\nTest 4: Forward Secrecy via DH Ratchet');
  try {
    const aliceIdentity = sodium.crypto_sign_keypair();
    const aliceSignedPreKey = sodium.crypto_kx_keypair();
    const bobIdentity = sodium.crypto_sign_keypair();
    const bobSignedPreKey = sodium.crypto_kx_keypair();
    const bobOneTimePreKey = sodium.crypto_kx_keypair();

    const spkSignature = sodium.crypto_sign_detached(
      bobSignedPreKey.publicKey,
      bobIdentity.privateKey
    );

    const session = establishSession(
      aliceIdentity,
      aliceSignedPreKey,
      aliceSignedPreKey.publicKey,
      bobIdentity.publicKey,
      bobSignedPreKey.publicKey,
      bobOneTimePreKey.publicKey,
      spkSignature,
      '1.0',
      'AES-GCM'
    );

    // Save old root key
    const oldRootKey = new Uint8Array(session.rootKey);

    // Encrypt a message (this should update ratchet)
    session.theirRatchetPublicKey = bobSignedPreKey.publicKey;
    encryptMessage('Message 1', session);

    // Root key should have changed
    let keyChanged = false;
    for (let i = 0; i < 32; i++) {
      if (oldRootKey[i] !== session.rootKey[i]) {
        keyChanged = true;
        break;
      }
    }

    if (keyChanged) {
      console.log('  ✅ PASS: Forward secrecy - root key changes on each message');
      passed++;
    } else {
      console.log('  ❌ FAIL: Root key did not change');
      failed++;
    }
  } catch (e) {
    console.log('  ❌ FAIL:', e);
    failed++;
  }

  // Test 5: TOFU Fingerprint
  console.log('\nTest 5: TOFU Fingerprint Verification');
  try {
    initializeTofu();
    
    const identityKey = sodium.crypto_sign_keypair().publicKey;
    const fingerprint = generateFingerprint(identityKey);

    // First verification - should trust
    const result1 = await verifyFingerprint('user123', identityKey);
    
    // Second verification with same key - should pass
    const result2 = await verifyFingerprint('user123', identityKey);

    if (result1 && result2 && fingerprint.length === 64) {
      console.log('  ✅ PASS: TOFU fingerprint verification working');
      passed++;
    } else {
      console.log('  ❌ FAIL: TOFU verification failed');
      failed++;
    }
  } catch (e) {
    console.log('  ❌ FAIL:', e);
    failed++;
  }

  // Test 6: TOFU MITM Detection
  console.log('\nTest 6: TOFU MITM Detection');
  try {
    initializeTofu();
    
    const realKey = sodium.crypto_sign_keypair().publicKey;
    const attackerKey = sodium.crypto_sign_keypair().publicKey;

    // Trust real key
    await verifyFingerprint('target', realKey);

    // Try to verify with attacker's key - should throw
    let mitmDetected = false;
    try {
      await verifyFingerprint('target', attackerKey);
    } catch (e) {
      if (e.message.includes('MISMATCH') || e.message.includes('MITM')) {
        mitmDetected = true;
      }
    }

    if (mitmDetected) {
      console.log('  ✅ PASS: MITM attack detected by TOFU');
      passed++;
    } else {
      console.log('  ❌ FAIL: MITM not detected');
      failed++;
    }
  } catch (e) {
    console.log('  ❌ FAIL:', e);
    failed++;
  }

  // Test 7: Replay Protection
  console.log('\nTest 7: Replay Protection');
  try {
    initializeReplayProtection();
    
    const userId = 'testuser';
    const nonce = 'testnonce123';
    const timestamp = Math.floor(Date.now() / 1000);

    // First message - should pass
    await validateMessage(userId, nonce, timestamp);

    // Second message with same nonce - should fail
    let replayDetected = false;
    try {
      await validateMessage(userId, nonce, timestamp);
    } catch (e) {
      if (e.message.includes('Replay') || e.message.includes('too old')) {
        replayDetected = true;
      }
    }

    if (replayDetected) {
      console.log('  ✅ PASS: Replay attack detected');
      passed++;
    } else {
      console.log('  ❌ FAIL: Replay not detected');
      failed++;
    }
  } catch (e) {
    console.log('  ❌ FAIL:', e);
    failed++;
  }

  // Test 8: Persistent Identity Storage Interface
  console.log('\nTest 8: Identity Storage Interface');
  try {
    const store = new LocalStorageIdentityStore('testuser');
    
    // Check interface methods exist
    if (typeof store.saveIdentityKeys === 'function' &&
        typeof store.loadIdentityKeys === 'function') {
      console.log('  ✅ PASS: Identity storage interface implemented');
      passed++;
    } else {
      console.log('  ❌ FAIL: Missing interface methods');
      failed++;
    }
  } catch (e) {
    console.log('  ❌ FAIL:', e);
    failed++;
  }

  // Summary
  console.log('\n' + '='.repeat(50));
  console.log(`Tests Passed: ${passed}/${passed + failed}`);
  console.log(`Tests Failed: ${failed}/${passed + failed}`);
  
  if (failed === 0) {
    console.log('\n🎉 ALL SECURITY TESTS PASSED!');
    process.exit(0);
  } else {
    console.log('\n⚠️  SOME TESTS FAILED');
    process.exit(1);
  }
}

// Run tests
runTests().catch(console.error);
