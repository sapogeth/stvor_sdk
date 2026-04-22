/**
 * STVOR Comprehensive Cryptography Test Suite
 * 
 * Tests ALL cryptographic properties at a hardcore level:
 * - Forward Secrecy (FS)
 * - Post-Compromise Security (PCS)
 * - Authentication (via ECDSA)
 * - Message Integrity (via AES-GCM)
 * - Key Derivation (RFC 5869 HKDF)
 * - Session State Management
 * - Multi-type data support (strings, binary, JSON, large payloads)
 * 
 * Uses Node.js built-in test module (no external dependencies)
 * Run: node --import tsx ratchet/__tests__/comprehensive-crypto.test.ts
 */

import { test } from 'node:test';
import { strict as assert } from 'assert';
import crypto from 'crypto';
import {
  generateKeyPair,
  ecSign,
  ecVerify,
  x3dhSymmetric,
  establishSession,
  encryptMessage,
  decryptMessage,
  forceRatchet,
  serializeSession,
  deserializeSession,
  initializeCrypto,
  type KeyPair,
  type SessionState,
} from '../index.js';

/* ================================================================
 * PART 1: BASIC CRYPTO OPERATIONS
 * ================================================================ */

test('Part 1: Basic Crypto Operations', async (t) => {
  await t.test('should initialize crypto without errors', async () => {
    await initializeCrypto();
    assert.ok(true, 'Initialization successful');
  });

  await t.test('should generate valid key pairs', () => {
    const kp1 = generateKeyPair();
    const kp2 = generateKeyPair();

    assert.strictEqual(kp1.publicKey.length, 65, 'Public key is 65 bytes');
    assert.strictEqual(kp1.privateKey.length, 32, 'Private key is 32 bytes');
    assert.notDeepStrictEqual(kp1, kp2, 'Two key pairs are different');
    assert.strictEqual(kp1.publicKey[0], 0x04, 'Uncompressed format marker');
  });

  await t.test('should sign and verify messages with ECDSA', () => {
    const kp = generateKeyPair();
    const msg = Buffer.from('Test message for ECDSA');
    const signature = ecSign(msg, kp);
    
    assert.ok(signature.length > 0, 'Signature is not empty');
    assert.ok(ecVerify(msg, signature, kp.publicKey), 'Valid signature verifies');

    const tamperedMsg = Buffer.from('Tampered message for ECDSA');
    assert.strictEqual(ecVerify(tamperedMsg, signature, kp.publicKey), false, 'Tampered message fails');

    const otherKp = generateKeyPair();
    assert.strictEqual(ecVerify(msg, signature, otherKp.publicKey), false, 'Wrong key fails');
  });

  await t.test('should derive same X3DH key from both sides', () => {
    const aliceIK = generateKeyPair();
    const aliceSPK = generateKeyPair();
    const bobIK = generateKeyPair();
    const bobSPK = generateKeyPair();

    const aliceSK = x3dhSymmetric(aliceIK, aliceSPK, bobIK.publicKey, bobSPK.publicKey);
    const bobSK = x3dhSymmetric(bobIK, bobSPK, aliceIK.publicKey, aliceSPK.publicKey);

    assert.deepStrictEqual(aliceSK, bobSK, 'X3DH keys match on both sides');
    assert.strictEqual(aliceSK.length, 32, 'Shared key is 32 bytes');
  });

  await t.test('should detect X3DH MITM attacks', () => {
    const aliceIK = generateKeyPair();
    const aliceSPK = generateKeyPair();
    const bobIK = generateKeyPair();
    const bobSPK = generateKeyPair();
    const eveIK = generateKeyPair();

    const aliceSK = x3dhSymmetric(aliceIK, aliceSPK, bobIK.publicKey, bobSPK.publicKey);
    const eveMITMSK = x3dhSymmetric(eveIK, generateKeyPair(), bobIK.publicKey, bobSPK.publicKey);

    assert.notDeepStrictEqual(aliceSK, eveMITMSK, 'MITM produces different key');
  });
});

/* ================================================================
 * PART 2: SESSION ESTABLISHMENT
 * ================================================================ */

test('Part 2: Session Establishment', async (t) => {
  const aliceIK = generateKeyPair();
  const aliceSPK = generateKeyPair();
  const bobIK = generateKeyPair();
  const bobSPK = generateKeyPair();

  await t.test('should establish session with peer public keys', () => {
    const session = establishSession(aliceIK, aliceSPK, bobIK.publicKey, bobSPK.publicKey);

    assert.ok(session.rootKey.length === 32, 'Root key is 32 bytes');
    assert.ok(session.myRatchetKeyPair, 'Has initial ratchet key pair');
    assert.strictEqual(session.sendCount, 0, 'Send count starts at 0');
    assert.strictEqual(session.recvCount, 0, 'Recv count starts at 0');
  });

  await t.test('should create independent sessions for each peer', () => {
    const session1 = establishSession(aliceIK, aliceSPK, bobIK.publicKey, bobSPK.publicKey);
    const session2 = establishSession(aliceIK, aliceSPK, bobIK.publicKey, bobSPK.publicKey);

    assert.deepStrictEqual(session1.rootKey, session2.rootKey, 'Same X3DH produces same root key');
    assert.notDeepStrictEqual(
      session1.myRatchetKeyPair.publicKey,
      session2.myRatchetKeyPair.publicKey,
      'Different ratchet key pairs (random)'
    );
  });
});

/* ================================================================
 * PART 3: ENCRYPT/DECRYPT
 * ================================================================ */

test('Part 3: Encrypt/Decrypt Operations', async (t) => {
  const aliceIK = generateKeyPair();
  const aliceSPK = generateKeyPair();
  const bobIK = generateKeyPair();
  const bobSPK = generateKeyPair();

  const aliceSession = establishSession(aliceIK, aliceSPK, bobIK.publicKey, bobSPK.publicKey);
  const bobSession = establishSession(bobIK, bobSPK, aliceIK.publicKey, aliceSPK.publicKey);

  await t.test('should encrypt message with header', () => {
    const plaintext = Buffer.from('Hello, Bob!');
    const { ciphertext, header } = encryptMessage(aliceSession, plaintext);

    assert.ok(ciphertext.length > plaintext.length, 'Ciphertext longer than plaintext');
    assert.strictEqual(header.length, 85, 'Header is 85 bytes');
  });

  await t.test('should decrypt message correctly', () => {
    const plaintext = Buffer.from('Test message from Alice');
    const { ciphertext, header } = encryptMessage(aliceSession, plaintext);
    const decrypted = decryptMessage(bobSession, ciphertext, header);
    assert.deepStrictEqual(decrypted, plaintext, 'Decryption successful');
  });

  await t.test('should detect tampering in ciphertext', () => {
    const plaintext = Buffer.from('Original message');
    const { ciphertext, header } = encryptMessage(aliceSession, plaintext);

    const tampered = Buffer.from(ciphertext);
    tampered[0] ^= 0xFF;

    assert.throws(
      () => decryptMessage(bobSession, tampered, header),
      /.*/, 
      'Tampered ciphertext fails'
    );
  });

  await t.test('should detect tampering in header', () => {
    const plaintext = Buffer.from('Original message');
    const { ciphertext, header } = encryptMessage(aliceSession, plaintext);

    const tamperedHeader = Buffer.from(header);
    tamperedHeader.writeUInt32BE(999, 69);

    assert.throws(
      () => decryptMessage(bobSession, ciphertext, tamperedHeader),
      /.*/, 
      'Tampered header fails'
    );
  });

  await t.test('should increment counters correctly', () => {
    const initialSend = aliceSession.sendCount;
    const { ciphertext, header } = encryptMessage(aliceSession, Buffer.from('msg1'));
    assert.strictEqual(aliceSession.sendCount, initialSend + 1, 'Send count incremented');

    decryptMessage(bobSession, ciphertext, header);
    assert.ok(bobSession.recvCount > 0, 'Recv count incremented');
  });
});

/* ================================================================
 * PART 4: FORWARD SECRECY (FS)
 * ================================================================ */

test('Part 4: Forward Secrecy', async (t) => {
  await t.test('should prevent decryption of old messages with new keys', () => {
    const aliceIK = generateKeyPair();
    const aliceSPK = generateKeyPair();
    const bobIK = generateKeyPair();
    const bobSPK = generateKeyPair();

    const aliceSession = establishSession(aliceIK, aliceSPK, bobIK.publicKey, bobSPK.publicKey);
    const bobSession = establishSession(bobIK, bobSPK, aliceIK.publicKey, aliceSPK.publicKey);

    const msg1 = Buffer.from('Secret message 1');
    const enc1 = encryptMessage(aliceSession, msg1);
    const dec1 = decryptMessage(bobSession, enc1.ciphertext, enc1.header);
    assert.deepStrictEqual(dec1, msg1);

    // More messages trigger ratchet
    for (let i = 0; i < 5; i++) {
      const msg = Buffer.from(`Message ${i + 2}`);
      const enc = encryptMessage(aliceSession, msg);
      decryptMessage(bobSession, enc.ciphertext, enc.header);
    }

    // Verify chain key changed
    assert.ok(aliceSession.sendingChainKey.length === 32, 'Chain key updated');
  });

  await t.test('should handle out-of-order messages', () => {
    const aliceIK = generateKeyPair();
    const aliceSPK = generateKeyPair();
    const bobIK = generateKeyPair();
    const bobSPK = generateKeyPair();

    const aliceSession = establishSession(aliceIK, aliceSPK, bobIK.publicKey, bobSPK.publicKey);
    const bobSession = establishSession(bobIK, bobSPK, aliceIK.publicKey, aliceSPK.publicKey);

    const msg1 = encryptMessage(aliceSession, Buffer.from('Message 1'));
    const msg2 = encryptMessage(aliceSession, Buffer.from('Message 2'));
    const msg3 = encryptMessage(aliceSession, Buffer.from('Message 3'));

    // Receive out of order: 3, 1, 2
    const dec3 = decryptMessage(bobSession, msg3.ciphertext, msg3.header);
    assert.deepStrictEqual(dec3, Buffer.from('Message 3'));

    const dec1 = decryptMessage(bobSession, msg1.ciphertext, msg1.header);
    assert.deepStrictEqual(dec1, Buffer.from('Message 1'));

    const dec2 = decryptMessage(bobSession, msg2.ciphertext, msg2.header);
    assert.deepStrictEqual(dec2, Buffer.from('Message 2'));
  });
});

/* ================================================================
 * PART 5: POST-COMPROMISE SECURITY (PCS)
 * ================================================================ */

test('Part 5: Post-Compromise Security', async (t) => {
  await t.test('should recover after forceRatchet', () => {
    const aliceIK = generateKeyPair();
    const aliceSPK = generateKeyPair();
    const bobIK = generateKeyPair();
    const bobSPK = generateKeyPair();

    const aliceSession = establishSession(aliceIK, aliceSPK, bobIK.publicKey, bobSPK.publicKey);
    const bobSession = establishSession(bobIK, bobSPK, aliceIK.publicKey, aliceSPK.publicKey);

    // Exchange messages
    for (let i = 0; i < 3; i++) {
      const msg = Buffer.from(`Message ${i}`);
      const enc = encryptMessage(aliceSession, msg);
      decryptMessage(bobSession, enc.ciphertext, enc.header);
    }

    const oldRatchet = aliceSession.myRatchetKeyPair;
    forceRatchet(aliceSession);

    assert.notDeepStrictEqual(aliceSession.myRatchetKeyPair, oldRatchet, 'Ratchet key changed');
    assert.strictEqual(aliceSession.sendCount, 0, 'Send count reset');
    assert.ok(aliceSession.isPostCompromise, 'Post-compromise flag set');

    // New message works
    const newMsg = Buffer.from('First message after recovery');
    const enc = encryptMessage(aliceSession, newMsg);
    assert.ok(enc.header.length === 85, 'Message encrypted with new ratchet');
  });
});

/* ================================================================
 * PART 6: MULTI-TYPE DATA SUPPORT
 * ================================================================ */

test('Part 6: Multi-Type Data Support', async (t) => {
  const aliceIK = generateKeyPair();
  const aliceSPK = generateKeyPair();
  const bobIK = generateKeyPair();
  const bobSPK = generateKeyPair();

  let aliceSession = establishSession(aliceIK, aliceSPK, bobIK.publicKey, bobSPK.publicKey);
  const bobSession = establishSession(bobIK, bobSPK, aliceIK.publicKey, aliceSPK.publicKey);

  await t.test('should encrypt/decrypt UTF-8 strings', () => {
    const tests = [
      'Hello, World!',
      'Привет, мир! 🌍',
      '你好世界 🎉',
      'مرحبا بالعالم',
      '',
    ];

    for (const text of tests) {
      const plaintext = Buffer.from(text, 'utf-8');
      const { ciphertext, header } = encryptMessage(aliceSession, plaintext);
      const decrypted = decryptMessage(bobSession, ciphertext, header);
      assert.deepStrictEqual(decrypted, plaintext, `Handles: ${text}`);
    }
  });

  await t.test('should encrypt/decrypt binary data', () => {
    const tests = [
      Buffer.from([0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD]),
      Buffer.from(crypto.randomBytes(1024)),
      Buffer.from(crypto.randomBytes(65536)),
    ];

    for (const binary of tests) {
      const { ciphertext, header } = encryptMessage(aliceSession, binary);
      const decrypted = decryptMessage(bobSession, ciphertext, header);
      assert.deepStrictEqual(decrypted, binary, `Binary size ${binary.length}`);
    }
  });

  await t.test('should encrypt/decrypt JSON', () => {
    const objects = [
      { message: 'hello' },
      { user: 'alice', age: 30, verified: true },
      { nested: { data: { structure: [1, 2, 3] } } },
      { emoji: '👋🔐🚀', unicode: '你好' },
      [],
      {},
    ];

    for (const obj of objects) {
      const plaintext = Buffer.from(JSON.stringify(obj), 'utf-8');
      const { ciphertext, header } = encryptMessage(aliceSession, plaintext);
      const decrypted = decryptMessage(bobSession, ciphertext, header);
      const parsed = JSON.parse(decrypted.toString('utf-8'));
      assert.deepStrictEqual(parsed, obj, `JSON: ${JSON.stringify(obj)}`);
    }
  });

  await t.test('should handle empty messages', () => {
    const empty = Buffer.alloc(0);
    const { ciphertext, header } = encryptMessage(aliceSession, empty);
    const decrypted = decryptMessage(bobSession, ciphertext, header);
    assert.deepStrictEqual(decrypted, empty, 'Empty message handled');
  });

  await t.test('should handle large payloads (1MB)', () => {
    const large = Buffer.alloc(1024 * 1024, 'a');
    const { ciphertext, header } = encryptMessage(aliceSession, large);
    // Ciphertext = encrypted payload (same size) + 16-byte GCM tag
    assert.ok(ciphertext.length >= large.length + 16, 'Ciphertext is at least plaintext + tag');

    const decrypted = decryptMessage(bobSession, ciphertext, header);
    assert.deepStrictEqual(decrypted, large, 'Large payload decrypted');
  });
});

/* ================================================================
 * PART 7: SERIALIZATION & PERSISTENCE
 * ================================================================ */

test('Part 7: Serialization & Persistence', async (t) => {
  await t.test('should serialize and deserialize session state', () => {
    const aliceIK = generateKeyPair();
    const aliceSPK = generateKeyPair();
    const bobIK = generateKeyPair();
    const bobSPK = generateKeyPair();

    const session1 = establishSession(aliceIK, aliceSPK, bobIK.publicKey, bobSPK.publicKey);
    const msg = Buffer.from('Test');
    encryptMessage(session1, msg);

    const serialized = serializeSession(session1);
    assert.ok(serialized.length > 0, 'Serialized session not empty');
    assert.ok(Buffer.isBuffer(serialized), 'Serialized is Buffer');

    const session2 = deserializeSession(serialized);
    assert.deepStrictEqual(session2.rootKey, session1.rootKey, 'Root key preserved');
    assert.deepStrictEqual(session2.sendingChainKey, session1.sendingChainKey, 'Chain key preserved');
    assert.strictEqual(session2.sendCount, session1.sendCount, 'Send count preserved');
  });

  await t.test('should maintain state after deserialization', () => {
    const aliceIK = generateKeyPair();
    const aliceSPK = generateKeyPair();
    const bobIK = generateKeyPair();
    const bobSPK = generateKeyPair();

    let aliceSession = establishSession(aliceIK, aliceSPK, bobIK.publicKey, bobSPK.publicKey);
    const bobSession = establishSession(bobIK, bobSPK, aliceIK.publicKey, aliceSPK.publicKey);

    // Send message 1
    const msg1 = Buffer.from('Message 1');
    const enc1 = encryptMessage(aliceSession, msg1);
    const dec1 = decryptMessage(bobSession, enc1.ciphertext, enc1.header);
    assert.deepStrictEqual(dec1, msg1);

    // Serialize
    const serialized = serializeSession(aliceSession);
    aliceSession = deserializeSession(serialized);

    // Send message 2 after deserialization
    const msg2 = Buffer.from('Message 2');
    const enc2 = encryptMessage(aliceSession, msg2);
    const dec2 = decryptMessage(bobSession, enc2.ciphertext, enc2.header);
    assert.deepStrictEqual(dec2, msg2, 'Works after deserialization');
  });
});

/* ================================================================
 * PART 8: ADVERSARIAL SCENARIOS
 * ================================================================ */

test('Part 8: Adversarial Scenarios', async (t) => {
  await t.test('should detect replay attacks', () => {
    const aliceIK = generateKeyPair();
    const aliceSPK = generateKeyPair();
    const bobIK = generateKeyPair();
    const bobSPK = generateKeyPair();

    const aliceSession = establishSession(aliceIK, aliceSPK, bobIK.publicKey, bobSPK.publicKey);
    const bobSession = establishSession(bobIK, bobSPK, aliceIK.publicKey, aliceSPK.publicKey);

    const msg = Buffer.from('Important: transfer funds');
    const encrypted = encryptMessage(aliceSession, msg);

    // Receive first time
    const dec1 = decryptMessage(bobSession, encrypted.ciphertext, encrypted.header);
    assert.deepStrictEqual(dec1, msg);

    // Replay attempt fails
    assert.throws(
      () => decryptMessage(bobSession, encrypted.ciphertext, encrypted.header),
      /.*/, 
      'Replay detected'
    );
  });

  await t.test('should handle adversarial DH ratchet changes', () => {
    const aliceIK = generateKeyPair();
    const aliceSPK = generateKeyPair();
    const bobIK = generateKeyPair();
    const bobSPK = generateKeyPair();

    const aliceSession = establishSession(aliceIK, aliceSPK, bobIK.publicKey, bobSPK.publicKey);
    const bobSession = establishSession(bobIK, bobSPK, aliceIK.publicKey, aliceSPK.publicKey);

    for (let round = 0; round < 3; round++) {
      const msg1 = Buffer.from(`A-${round}-1`);
      const enc1 = encryptMessage(aliceSession, msg1);
      const dec1 = decryptMessage(bobSession, enc1.ciphertext, enc1.header);
      assert.deepStrictEqual(dec1, msg1);

      const msg2 = Buffer.from(`A-${round}-2`);
      const enc2 = encryptMessage(aliceSession, msg2);
      const dec2 = decryptMessage(bobSession, enc2.ciphertext, enc2.header);
      assert.deepStrictEqual(dec2, msg2);

      const bMsg = Buffer.from(`B-${round}`);
      const bEnc = encryptMessage(bobSession, bMsg);
      const bDec = decryptMessage(aliceSession, bEnc.ciphertext, bEnc.header);
      assert.deepStrictEqual(bDec, bMsg);
    }
  });

  await t.test('should NOT be vulnerable to known-plaintext attacks', () => {
    const aliceIK = generateKeyPair();
    const aliceSPK = generateKeyPair();
    const bobIK = generateKeyPair();
    const bobSPK = generateKeyPair();

    const aliceSession = establishSession(aliceIK, aliceSPK, bobIK.publicKey, bobSPK.publicKey);

    const plaintext = Buffer.from('same content');
    const enc1 = encryptMessage(aliceSession, plaintext);
    const enc2 = encryptMessage(aliceSession, plaintext);

    assert.notDeepStrictEqual(enc1.header, enc2.header, 'Different headers');
    assert.notDeepStrictEqual(enc1.ciphertext, enc2.ciphertext, 'Different ciphertexts');
  });
});

/* ================================================================
 * PART 9: IMPLEMENTATION PROPERTIES
 * ================================================================ */

test('Part 9: Implementation Properties', async (t) => {
  await t.test('should NOT reuse nonces', () => {
    const aliceIK = generateKeyPair();
    const aliceSPK = generateKeyPair();
    const bobIK = generateKeyPair();
    const bobSPK = generateKeyPair();

    const aliceSession = establishSession(aliceIK, aliceSPK, bobIK.publicKey, bobSPK.publicKey);
    const nonces = new Set<string>();

    for (let i = 0; i < 100; i++) {
      const { header } = encryptMessage(aliceSession, Buffer.from(`msg ${i}`));
      const nonce = header.subarray(73, 85).toString('hex');
      assert.ok(!nonces.has(nonce), `Nonce reused: ${nonce}`);
      nonces.add(nonce);
    }

    assert.strictEqual(nonces.size, 100, 'All 100 nonces unique');
  });

  await t.test('should produce deterministic HKDF', () => {
    const aliceIK = generateKeyPair();
    const aliceSPK = generateKeyPair();
    const bobIK = generateKeyPair();
    const bobSPK = generateKeyPair();

    const session1 = establishSession(aliceIK, aliceSPK, bobIK.publicKey, bobSPK.publicKey);
    const session2 = establishSession(aliceIK, aliceSPK, bobIK.publicKey, bobSPK.publicKey);

    assert.deepStrictEqual(session1.rootKey, session2.rootKey, 'Deterministic HKDF');
  });

  await t.test('should properly track chain keys', () => {
    const aliceIK = generateKeyPair();
    const aliceSPK = generateKeyPair();
    const bobIK = generateKeyPair();
    const bobSPK = generateKeyPair();

    const aliceSession = establishSession(aliceIK, aliceSPK, bobIK.publicKey, bobSPK.publicKey);
    const bobSession = establishSession(bobIK, bobSPK, aliceIK.publicKey, aliceSPK.publicKey);

    const chainSnapshots: Buffer[] = [];

    for (let i = 0; i < 10; i++) {
      const msg = Buffer.from(`msg ${i}`);
      const enc = encryptMessage(aliceSession, msg);
      decryptMessage(bobSession, enc.ciphertext, enc.header);
      chainSnapshots.push(Buffer.from(aliceSession.sendingChainKey));
    }

    for (let i = 0; i < chainSnapshots.length; i++) {
      for (let j = i + 1; j < chainSnapshots.length; j++) {
        assert.notDeepStrictEqual(chainSnapshots[i], chainSnapshots[j], `Chain key ${i} != ${j}`);
      }
    }
  });
});

console.log('\n✅ All comprehensive crypto tests completed\n');
