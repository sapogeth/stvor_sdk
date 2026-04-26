/**
 * One-time prekey (OPK) tests
 * Verifies DH4 is included in X3DH when OPK is present
 */

import { CryptoSessionManager } from '../crypto-session.js';

async function test(name: string, fn: () => Promise<void>) {
  try { await fn(); console.log(`  ✓ ${name}`); }
  catch (e: any) { console.error(`  ✗ ${name}: ${e.message}`); process.exit(1); }
}

function assert(cond: boolean, msg: string) {
  if (!cond) throw new Error(msg);
}

console.log('\nOne-Time Prekey (OPK) Tests\n');

await test('getPublicKeys includes a non-empty oneTimePreKey', async () => {
  const alice = new CryptoSessionManager('alice');
  await alice.initialize();
  const keys = alice.getPublicKeys();
  assert(keys.oneTimePreKey.length > 0, 'oneTimePreKey should be non-empty');
});

await test('Each getPublicKeys call returns a different OPK', async () => {
  const alice = new CryptoSessionManager('alice');
  await alice.initialize();
  const k1 = alice.getPublicKeys();
  const k2 = alice.getPublicKeys();
  assert(k1.oneTimePreKey !== k2.oneTimePreKey, 'Each call should return a different OPK');
});

await test('Session with OPK produces different root key than without', async () => {
  const a1 = new CryptoSessionManager('alice');
  const b1 = new CryptoSessionManager('bob');
  await a1.initialize(); await b1.initialize();

  // Get bob's keys WITH OPK
  const bobKeysWithOpk = b1.getPublicKeys();
  assert(bobKeysWithOpk.oneTimePreKey.length > 0, 'bob must have OPK');

  // Get bob's keys WITHOUT OPK (simulate exhausted pool)
  const bobKeysNoOpk = { ...bobKeysWithOpk, oneTimePreKey: '' };

  // Establish two sessions: one with OPK, one without
  const a2 = new CryptoSessionManager('alice');
  await a2.initialize();

  await a1.establishSessionWithPeer('bob', bobKeysWithOpk);
  await a2.establishSessionWithPeer('bob', bobKeysNoOpk);

  // Encrypt with both — ciphertexts must differ (different root keys)
  const { ciphertext: c1 } = a1.encryptForPeer('bob', 'test');
  const { ciphertext: c2 } = a2.encryptForPeer('bob', 'test');
  assert(c1 !== c2, 'OPK and no-OPK sessions should produce different ciphertexts');
});

await test('Full session with OPK: encrypt/decrypt works end-to-end', async () => {
  const alice = new CryptoSessionManager('alice');
  const bob   = new CryptoSessionManager('bob');
  await alice.initialize();
  await bob.initialize();

  const aliceKeys = alice.getPublicKeys();
  const bobKeys   = bob.getPublicKeys();
  assert(bobKeys.oneTimePreKey.length > 0, 'bob must have OPK');

  // Alice (initiator) uses Bob's OPK in X3DH — DH4 = ECDH(alice_SPK.priv, bob_OPK.pub)
  await alice.establishSessionWithPeer('bob', bobKeys);

  // Bob (responder) learns which OPK Alice used from Alice's initial message.
  // He passes aliceKeys with oneTimePreKey = the OPK Alice consumed (his own pub key).
  // crypto-session.ts detects it's his own key, looks up the private key, computes DH4 = ECDH(bob_OPK.priv, alice_SPK.pub)
  const aliceKeysForBob = { ...aliceKeys, oneTimePreKey: bobKeys.oneTimePreKey };
  await bob.establishSessionWithPeer('alice', aliceKeysForBob);

  const { ciphertext, header } = alice.encryptForPeer('bob', 'hello with opk');
  const plaintext = bob.decryptFromPeer('alice', ciphertext, header);
  assert(plaintext === 'hello with opk', `Got: ${plaintext}`);
});

await test('OPK pool refills automatically', async () => {
  const alice = new CryptoSessionManager('alice');
  await alice.initialize();
  // Drain most of the pool
  for (let i = 0; i < 8; i++) alice.getPublicKeys();
  // Should still have OPKs (pool refills at low water mark)
  const keys = alice.getPublicKeys();
  assert(keys.oneTimePreKey.length > 0, 'Pool should have refilled');
});

console.log('\nAll OPK tests passed.\n');
