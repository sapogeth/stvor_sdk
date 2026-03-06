/**
 * STVOR E2EE Integration Test
 * Verifies the full encrypt/decrypt cycle between two parties
 * using ONLY Node.js built-in crypto — zero external dependencies.
 *
 * Run: node --loader ts-node/esm test-e2ee.ts
 *   or: npx tsx test-e2ee.ts
 */

import {
  generateKeyPair,
  establishSession,
  encryptMessage,
  decryptMessage,
  ecSign,
  ecVerify,
  x3dhSymmetric,
  serializeSession,
  deserializeSession,
} from './ratchet/index.js';

import { CryptoSessionManager } from './facade/crypto-session.js';

let passed = 0;
let failed = 0;

function assert(condition: boolean, label: string): void {
  if (condition) {
    console.log(`  ✅ ${label}`);
    passed++;
  } else {
    console.error(`  ❌ ${label}`);
    failed++;
  }
}

/* ================================================================
 * Test 1: ECDSA sign / verify
 * ================================================================ */
console.log('\n🔐 Test 1: ECDSA P-256 Sign / Verify');
{
  const kp = generateKeyPair();
  const data = Buffer.from('Hello ECDSA');
  const sig = ecSign(data, kp);
  assert(sig.length > 0, 'Signature is non-empty');
  assert(ecVerify(data, sig, kp.publicKey), 'Signature verifies correctly');
  assert(!ecVerify(Buffer.from('tampered'), sig, kp.publicKey), 'Tampered data fails verification');

  const otherKP = generateKeyPair();
  assert(!ecVerify(data, sig, otherKP.publicKey), 'Wrong public key fails verification');
}

/* ================================================================
 * Test 2: X3DH — both sides derive the same shared secret
 * ================================================================ */
console.log('\n🔑 Test 2: X3DH Symmetric Key Agreement');
{
  const aliceIK = generateKeyPair();
  const aliceSPK = generateKeyPair();
  const bobIK = generateKeyPair();
  const bobSPK = generateKeyPair();

  const aliceSecret = x3dhSymmetric(aliceIK, aliceSPK, bobIK.publicKey, bobSPK.publicKey);
  const bobSecret = x3dhSymmetric(bobIK, bobSPK, aliceIK.publicKey, aliceSPK.publicKey);

  assert(aliceSecret.length === 32, 'Shared secret is 32 bytes');
  assert(Buffer.compare(aliceSecret, bobSecret) === 0, 'Both sides derive identical shared secret');
}

/* ================================================================
 * Test 3: Full Double Ratchet encrypt/decrypt cycle
 * ================================================================ */
console.log('\n📨 Test 3: Double Ratchet Encrypt / Decrypt (raw)');
{
  const aliceIK = generateKeyPair();
  const aliceSPK = generateKeyPair();
  const bobIK = generateKeyPair();
  const bobSPK = generateKeyPair();

  const aliceSession = establishSession(aliceIK, aliceSPK, bobIK.publicKey, bobSPK.publicKey);
  const bobSession = establishSession(bobIK, bobSPK, aliceIK.publicKey, aliceSPK.publicKey);

  // Alice → Bob
  const msg1 = Buffer.from('Привет, Bob! Это зашифрованное сообщение.');
  const { ciphertext: ct1, header: h1 } = encryptMessage(aliceSession, msg1);
  const pt1 = decryptMessage(bobSession, ct1, h1);
  assert(Buffer.compare(pt1, msg1) === 0, 'Alice→Bob: message decrypted correctly');

  // Bob → Alice
  const msg2 = Buffer.from('Привет, Alice! Ответ зашифрован.');
  const { ciphertext: ct2, header: h2 } = encryptMessage(bobSession, msg2);
  const pt2 = decryptMessage(aliceSession, ct2, h2);
  assert(Buffer.compare(pt2, msg2) === 0, 'Bob→Alice: message decrypted correctly');

  // Alice → Bob (second message — same chain)
  const msg3 = Buffer.from('Second message from Alice');
  const { ciphertext: ct3, header: h3 } = encryptMessage(aliceSession, msg3);
  const pt3 = decryptMessage(bobSession, ct3, h3);
  assert(Buffer.compare(pt3, msg3) === 0, 'Alice→Bob: second message decrypted correctly');

  // Test tampering detection
  let tamperDetected = false;
  try {
    const tamperedCt = Buffer.from(ct1);
    tamperedCt[0] ^= 0xff; // flip a byte
    decryptMessage(bobSession, tamperedCt, h1);
  } catch (e) {
    tamperDetected = true;
  }
  assert(tamperDetected, 'Tampered ciphertext is rejected');
}

/* ================================================================
 * Test 4: Multiple messages in both directions (ratchet rotation)
 * ================================================================ */
console.log('\n🔄 Test 4: Multi-message ratchet rotation');
{
  const aliceIK = generateKeyPair();
  const aliceSPK = generateKeyPair();
  const bobIK = generateKeyPair();
  const bobSPK = generateKeyPair();

  const alice = establishSession(aliceIK, aliceSPK, bobIK.publicKey, bobSPK.publicKey);
  const bob = establishSession(bobIK, bobSPK, aliceIK.publicKey, aliceSPK.publicKey);

  const messages = [
    { from: 'alice', text: 'Message 1 from Alice' },
    { from: 'alice', text: 'Message 2 from Alice' },
    { from: 'bob', text: 'Reply 1 from Bob' },
    { from: 'alice', text: 'Message 3 from Alice' },
    { from: 'bob', text: 'Reply 2 from Bob' },
    { from: 'bob', text: 'Reply 3 from Bob' },
  ];

  let allOK = true;
  for (const m of messages) {
    const pt = Buffer.from(m.text);
    if (m.from === 'alice') {
      const { ciphertext, header } = encryptMessage(alice, pt);
      const dec = decryptMessage(bob, ciphertext, header);
      if (Buffer.compare(dec, pt) !== 0) allOK = false;
    } else {
      const { ciphertext, header } = encryptMessage(bob, pt);
      const dec = decryptMessage(alice, ciphertext, header);
      if (Buffer.compare(dec, pt) !== 0) allOK = false;
    }
  }
  assert(allOK, 'All 6 messages across 3 ratchet rotations decrypted correctly');
}

/* ================================================================
 * Test 5: Session serialisation / deserialisation
 * ================================================================ */
console.log('\n💾 Test 5: Session Serialisation');
{
  const aliceIK = generateKeyPair();
  const aliceSPK = generateKeyPair();
  const bobIK = generateKeyPair();
  const bobSPK = generateKeyPair();

  const session = establishSession(aliceIK, aliceSPK, bobIK.publicKey, bobSPK.publicKey);
  const serialized = serializeSession(session);
  const restored = deserializeSession(serialized);

  assert(Buffer.compare(restored.rootKey, session.rootKey) === 0, 'Restored rootKey matches');
  assert(
    Buffer.compare(restored.sendingChainKey, session.sendingChainKey) === 0,
    'Restored sendingChainKey matches',
  );
  assert(restored.sendCount === session.sendCount, 'Restored sendCount matches');
}

/* ================================================================
 * Test 6: CryptoSessionManager (high-level facade)
 * ================================================================ */
console.log('\n🏗️  Test 6: CryptoSessionManager façade');
{
  const alice = new CryptoSessionManager('alice');
  const bob = new CryptoSessionManager('bob');

  await alice.initialize();
  await bob.initialize();

  const aliceKeys = alice.getPublicKeys();
  const bobKeys = bob.getPublicKeys();

  assert(aliceKeys.identityKey.length > 0, 'Alice has identity key');
  assert(bobKeys.signedPreKeySignature.length > 0, 'Bob has SPK signature');

  // Establish sessions
  await alice.establishSession('bob', bobKeys);
  await bob.establishSession('alice', aliceKeys);

  assert(alice.hasSession('bob'), 'Alice has session with Bob');
  assert(bob.hasSession('alice'), 'Bob has session with Alice');

  // Encrypt / Decrypt
  const { ciphertext, header } = alice.encryptForPeer('bob', 'Hello from the SDK façade!');
  assert(typeof ciphertext === 'string', 'Ciphertext is base64url string');

  const plaintext = bob.decryptFromPeer('alice', ciphertext, header);
  assert(plaintext === 'Hello from the SDK façade!', 'Façade decrypt returns original plaintext');

  // Bob replies
  const reply = bob.encryptForPeer('alice', 'Reply from Bob via façade');
  const replyPT = alice.decryptFromPeer('bob', reply.ciphertext, reply.header);
  assert(replyPT === 'Reply from Bob via façade', 'Bidirectional façade communication works');
}

/* ================================================================
 * Test 7: Forward secrecy — old keys can't decrypt new messages
 * ================================================================ */
console.log('\n🛡️  Test 7: Forward Secrecy');
{
  const aliceIK = generateKeyPair();
  const aliceSPK = generateKeyPair();
  const bobIK = generateKeyPair();
  const bobSPK = generateKeyPair();

  const alice = establishSession(aliceIK, aliceSPK, bobIK.publicKey, bobSPK.publicKey);
  const bob = establishSession(bobIK, bobSPK, aliceIK.publicKey, aliceSPK.publicKey);

  // Save root key before any messages
  const initialRootKey = Buffer.from(alice.rootKey);

  // Exchange first pair of messages (triggers DH ratchet on each side)
  const { ciphertext: c1, header: h1 } = encryptMessage(alice, Buffer.from('msg1'));
  decryptMessage(bob, c1, h1);

  const { ciphertext: c2, header: h2 } = encryptMessage(bob, Buffer.from('reply1'));
  decryptMessage(alice, c2, h2);

  // Root key changed after the DH ratchets
  assert(
    Buffer.compare(alice.rootKey, initialRootKey) !== 0,
    'Root key rotated after first exchange — forward secrecy active',
  );

  // Save root key after first exchange
  const afterFirstExchange = Buffer.from(alice.rootKey);

  // Exchange second pair of messages (triggers more DH ratchets)
  const { ciphertext: c3, header: h3 } = encryptMessage(alice, Buffer.from('msg2'));
  decryptMessage(bob, c3, h3);

  const { ciphertext: c4, header: h4 } = encryptMessage(bob, Buffer.from('reply2'));
  decryptMessage(alice, c4, h4);

  assert(
    Buffer.compare(alice.rootKey, afterFirstExchange) !== 0,
    'Root key rotated again after second exchange — ongoing forward secrecy',
  );
}

/* ================================================================
 * Summary
 * ================================================================ */
console.log('\n' + '='.repeat(50));
console.log(`Results: ${passed} passed, ${failed} failed`);
console.log('='.repeat(50));

if (failed > 0) {
  process.exit(1);
}
