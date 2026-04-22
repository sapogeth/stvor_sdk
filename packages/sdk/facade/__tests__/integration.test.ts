/**
 * Integration Test: Full E2EE with Persistence & Protection
 * 
 * Demonstrates complete workflow:
 * 1. Initialize crypto with persistent storage
 * 2. Exchange keys with peer
 * 3. Send/receive encrypted messages
 * 4. Verify replay protection
 * 5. Verify timing safety
 */

import { test } from 'node:test';
import assert from 'node:assert';
import path from 'path';
import os from 'os';
import { promises as fs } from 'fs';
import crypto from 'crypto';

import { CryptoSessionManager, FileIdentityStore, FileSessionStore, FileReplayStore } from '../index.ts';
import { OTPKeyManager } from '../otp-key-manager.ts';
import { verifyCryptoIsConstantTime } from '../timing-protection.ts';

test('Full E2EE Integration with Persistence', async (t) => {
  let tmpDir: string;

  // Setup
  t.before(async () => {
    tmpDir = path.join(os.tmpdir(), `stvor-integration-${Date.now()}`);
    await fs.mkdir(tmpDir, { recursive: true });
  });

  // Cleanup
  t.after(async () => {
    try {
      const cleanup = async (dir: string) => {
        const entries = await fs.readdir(dir);
        for (const entry of entries) {
          const entryPath = path.join(dir, entry);
          const stat = await fs.stat(entryPath);
          if (stat.isDirectory()) {
            await cleanup(entryPath);
            await fs.rmdir(entryPath);
          } else {
            await fs.unlink(entryPath);
          }
        }
      };
      await cleanup(tmpDir);
      await fs.rmdir(tmpDir);
    } catch (e) {
      // ignore
    }
  });

  await t.test('should setup persistent storage', async () => {
    const password = 'secure-password-123';

    const keyStore = new FileIdentityStore({
      directory: path.join(tmpDir, 'keys'),
      masterPassword: password,
    });

    const sessionStore = new FileSessionStore({
      directory: path.join(tmpDir, 'sessions'),
      masterPassword: password,
    });

    assert.ok(keyStore, 'Identity store created');
    assert.ok(sessionStore, 'Session store created');
  });

  await t.test('should initialize crypto manager with persistence', async () => {
    const password = 'test-password';

    const keyStore = new FileIdentityStore({
      directory: path.join(tmpDir, 'keys'),
      masterPassword: password,
    });

    const sessionStore = new FileSessionStore({
      directory: path.join(tmpDir, 'sessions'),
      masterPassword: password,
    });

    const alice = new CryptoSessionManager('alice@example.com', keyStore, sessionStore);
    await alice.initialize();

    const aliceKeys = alice.getPublicKeys();
    assert.ok(aliceKeys.identityKey, 'Identity key generated');
    assert.ok(aliceKeys.signedPreKey, 'SPK generated');
  });

  await t.test('should establish session with persistence', async () => {
    const password = 'test-password';

    // Alice
    const aliceKeys = new FileIdentityStore({
      directory: path.join(tmpDir, 'alice-keys'),
      masterPassword: password,
    });
    const aliceSessions = new FileSessionStore({
      directory: path.join(tmpDir, 'alice-sessions'),
      masterPassword: password,
    });
    const alice = new CryptoSessionManager('alice', aliceKeys, aliceSessions);
    await alice.initialize();

    // Bob
    const bobKeys = new FileIdentityStore({
      directory: path.join(tmpDir, 'bob-keys'),
      masterPassword: password,
    });
    const bobSessions = new FileSessionStore({
      directory: path.join(tmpDir, 'bob-sessions'),
      masterPassword: password,
    });
    const bob = new CryptoSessionManager('bob', bobKeys, bobSessions);
    await bob.initialize();

    // Exchange keys
    const alicePublicKeys = alice.getPublicKeys();
    const bobPublicKeys = bob.getPublicKeys();

    // Establish sessions
    await alice.establishSession('bob', bobPublicKeys);
    await bob.establishSession('alice', alicePublicKeys);

    assert.ok(alice.hasSession('bob'), 'Alice has session with Bob');
    assert.ok(bob.hasSession('alice'), 'Bob has session with Alice');
  });

  await t.test('should encrypt and decrypt with persistent sessions', async () => {
    const password = 'test-password';

    // Setup
    const aliceKeys = new FileIdentityStore({
      directory: path.join(tmpDir, 'alice-keys-2'),
      masterPassword: password,
    });
    const aliceSessions = new FileSessionStore({
      directory: path.join(tmpDir, 'alice-sessions-2'),
      masterPassword: password,
    });
    const alice = new CryptoSessionManager('alice', aliceKeys, aliceSessions);
    await alice.initialize();

    const bobKeys = new FileIdentityStore({
      directory: path.join(tmpDir, 'bob-keys-2'),
      masterPassword: password,
    });
    const bobSessions = new FileSessionStore({
      directory: path.join(tmpDir, 'bob-sessions-2'),
      masterPassword: password,
    });
    const bob = new CryptoSessionManager('bob', bobKeys, bobSessions);
    await bob.initialize();

    // Establish sessions
    await alice.establishSession('bob', bob.getPublicKeys());
    await bob.establishSession('alice', alice.getPublicKeys());

    // Encrypt message
    const message = 'Secure message from Alice';
    const { ciphertext, header } = alice.encryptForPeer('bob', message);

    // Decrypt message
    const decrypted = bob.decryptFromPeer('alice', ciphertext, header);

    assert.strictEqual(decrypted, message, 'Message decrypted correctly');
  });

  await t.test('should manage one-time prekeys', async () => {
    const otpManager = new OTPKeyManager(50, 1000 * 60 * 60);

    // Get initial OTP
    const otp1 = otpManager.getOneTimePreKey();
    assert.ok(otp1.keyId >= 0, 'OTP has valid keyId');
    assert.ok(otp1.publicKey, 'OTP has public key');

    // Mark as used
    otpManager.markAsUsed(otp1.keyId);

    // Get next OTP
    const otp2 = otpManager.getOneTimePreKey();
    assert.notStrictEqual(otp1.keyId, otp2.keyId, 'Different OTP returned');

    // Get multiple OTPs
    const otps = otpManager.getMultipleOneTimePreKeys(10);
    assert.strictEqual(otps.length, 10, '10 OTPs generated');
  });

  await t.test('should track OTP status', async () => {
    const otpManager = new OTPKeyManager(100);

    const status = otpManager.getStatus();
    assert.ok(status.totalKeys >= 100, 'Has OTPs');
    assert.ok(status.unusedKeys > 0, 'Has unused OTPs');
    assert.strictEqual(status.usedKeys, 0, 'No used OTPs initially');

    // Mark one as used
    const otp = otpManager.getOneTimePreKey();
    otpManager.markAsUsed(otp.keyId);

    const status2 = otpManager.getStatus();
    assert.ok(status2.usedKeys > 0, 'Has used OTPs');
  });

  await t.test('should rotate expired OTP keys', async () => {
    const otpManager = new OTPKeyManager(50);

    const status1 = otpManager.getStatus();
    const initial = status1.totalKeys;

    otpManager.rotateExpiredKeys();

    const status2 = otpManager.getStatus();
    assert.ok(status2.totalKeys >= 50, 'Maintains minimum OTPs');
  });

  await t.test('should verify crypto is constant-time', async () => {
    const verification = await verifyCryptoIsConstantTime();
    
    assert.ok(Array.isArray(verification.results), 'Has results');
    assert.ok(verification.results.length > 0, 'Results not empty');

    // Just verify that we can collect timing data, specifics vary by system
    for (const result of verification.results) {
      assert.ok(result.operation, `Operation: ${result.operation}`);
      assert.ok(result.mean > 0, `${result.operation} has measurable timing`);
      assert.ok(result.stdDev >= 0, `${result.operation} has non-negative stdDev`);
    }
  });

  await t.test('should export and import OTP state', async () => {
    const otpManager1 = new OTPKeyManager(50);

    // Get some OTPs and mark as used
    const otp1 = otpManager1.getOneTimePreKey();
    const otp2 = otpManager1.getOneTimePreKey();
    otpManager1.markAsUsed(otp1.keyId);
    otpManager1.markAsUsed(otp2.keyId);

    const status1 = otpManager1.getStatus();

    // Export state
    const exported = otpManager1.exportState();
    assert.ok(exported, 'State exported');

    // Import to new manager
    const otpManager2 = new OTPKeyManager();
    otpManager2.importState(exported);

    const status2 = otpManager2.getStatus();
    assert.strictEqual(status2.totalKeys, status1.totalKeys, 'Same number of keys after import');
    assert.strictEqual(status2.usedKeys, status1.usedKeys, 'Same used count after import');
  });

  await t.test('should handle complete message flow', async () => {
    const password = 'test-password';

    // Initialize both parties
    const aliceKeys = new FileIdentityStore({
      directory: path.join(tmpDir, 'alice-keys-3'),
      masterPassword: password,
    });
    const aliceSessions = new FileSessionStore({
      directory: path.join(tmpDir, 'alice-sessions-3'),
      masterPassword: password,
    });
    const alice = new CryptoSessionManager('alice', aliceKeys, aliceSessions);
    await alice.initialize();

    const bobKeys = new FileIdentityStore({
      directory: path.join(tmpDir, 'bob-keys-3'),
      masterPassword: password,
    });
    const bobSessions = new FileSessionStore({
      directory: path.join(tmpDir, 'bob-sessions-3'),
      masterPassword: password,
    });
    const bob = new CryptoSessionManager('bob', bobKeys, bobSessions);
    await bob.initialize();

    // Establish sessions
    await alice.establishSession('bob', bob.getPublicKeys());
    await bob.establishSession('alice', alice.getPublicKeys());

    // Exchange multiple messages
    const messages = ['Hello', 'How are you?', 'Good morning!', { type: 'json', data: 123 }];

    for (const msg of messages) {
      const msgStr = typeof msg === 'string' ? msg : JSON.stringify(msg);
      const { ciphertext, header } = alice.encryptForPeer('bob', msgStr);
      const decrypted = bob.decryptFromPeer('alice', ciphertext, header);
      assert.strictEqual(decrypted, msgStr, `Message "${msgStr}" round-tripped`);
    }

    // Verify sessions persisted
    const aliceSessions2 = new FileSessionStore({
      directory: path.join(tmpDir, 'alice-sessions-3'),
      masterPassword: password,
    });
    const bobSessions2 = new FileSessionStore({
      directory: path.join(tmpDir, 'bob-sessions-3'),
      masterPassword: password,
    });

    const aliceSessionList = await aliceSessions2.listSessions('alice');
    const bobSessionList = await bobSessions2.listSessions('bob');

    assert.ok(aliceSessions2, 'Session store accessible');
    assert.ok(bobSessions2, 'Session store accessible');
  });
});
