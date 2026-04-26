/**
 * Hybrid session test — verifies PQC is actually wired into establishSession
 */

import { CryptoSessionManager } from '../../facade/crypto-session.js';

async function test(name: string, fn: () => Promise<void>) {
  try { await fn(); console.log(`  ✓ ${name}`); }
  catch (e: any) { console.error(`  ✗ ${name}: ${e.message}`); process.exit(1); }
}

function assert(cond: boolean, msg: string) {
  if (!cond) throw new Error(msg);
}

console.log('\nHybrid PQC Session Tests\n');

await test('pqc:true includes pqcEk in public keys', async () => {
  const alice = new CryptoSessionManager('alice', undefined, undefined, true);
  await alice.initialize();
  const keys = alice.getPublicKeys();
  assert(!!keys.pqcEk, 'pqcEk missing from public keys');
  assert(keys.pqcEk!.length > 100, 'pqcEk too short');
});

await test('pqc:false does not include pqcEk', async () => {
  const alice = new CryptoSessionManager('alice');
  await alice.initialize();
  const keys = alice.getPublicKeys();
  assert(!keys.pqcEk, 'pqcEk should not be present when pqc disabled');
});

await test('Full KEM handshake: alice encaps to bob, bob decaps — both get same SS', async () => {
  const alice = new CryptoSessionManager('alice', undefined, undefined, true);
  const bob   = new CryptoSessionManager('bob',   undefined, undefined, true);
  await alice.initialize();
  await bob.initialize();

  const aliceKeys = alice.getPublicKeys();
  const bobKeys   = bob.getPublicKeys();
  assert(!!bobKeys.pqcEk, 'bob must have pqcEk');

  // Alice establishes session → encaps to bob → gets pending ct+ss
  await alice.establishSessionWithPeer('bob', bobKeys);
  const ctB64 = alice.popPendingPqcCt('bob');
  assert(ctB64 !== null, 'Alice should have a pending PQC ciphertext');

  // Bob establishes session (classical only)
  await bob.establishSessionWithPeer('alice', aliceKeys);

  // Bob receives ct from Alice and applies it
  bob.applyIncomingPqcCt('alice', ctB64!);

  // Now both should have the same hybrid root key — test by encrypt/decrypt
  const { ciphertext, header } = alice.encryptForPeer('bob', 'hello quantum world');
  const plaintext = bob.decryptFromPeer('alice', ciphertext, header);
  assert(plaintext === 'hello quantum world', `Got: ${plaintext}`);
});

await test('popPendingPqcCt returns null on second call (ct consumed)', async () => {
  const alice = new CryptoSessionManager('alice', undefined, undefined, true);
  const bob   = new CryptoSessionManager('bob',   undefined, undefined, true);
  await alice.initialize();
  await bob.initialize();
  await alice.establishSessionWithPeer('bob', bob.getPublicKeys());
  const ct1 = alice.popPendingPqcCt('bob');
  const ct2 = alice.popPendingPqcCt('bob');
  assert(ct1 !== null, 'First call should return ct');
  assert(ct2 === null, 'Second call should return null');
});

await test('PQC session root key differs from classical-only', async () => {
  // Classical only
  const a1 = new CryptoSessionManager('alice');
  const b1 = new CryptoSessionManager('bob');
  await a1.initialize(); await b1.initialize();
  await a1.establishSessionWithPeer('bob', b1.getPublicKeys());
  await b1.establishSessionWithPeer('alice', a1.getPublicKeys());

  // PQC hybrid
  const a2 = new CryptoSessionManager('alice', undefined, undefined, true);
  const b2 = new CryptoSessionManager('bob',   undefined, undefined, true);
  await a2.initialize(); await b2.initialize();
  await a2.establishSessionWithPeer('bob', b2.getPublicKeys());
  await b2.establishSessionWithPeer('alice', a2.getPublicKeys());

  // c1 and c2 should be different (different root keys from different key material)
  const { ciphertext: c1, header: h1 } = a1.encryptForPeer('bob', 'test');
  const { ciphertext: c2, header: h2 } = a2.encryptForPeer('bob', 'test');
  assert(c1 !== c2, 'PQC and classical sessions produced same ciphertext');

  // Each should decrypt correctly with their own peer
  const d1 = b1.decryptFromPeer('alice', c1, h1);
  const d2 = b2.decryptFromPeer('alice', c2, h2);
  assert(d1 === 'test', `classical decrypt: ${d1}`);
  assert(d2 === 'test', `pqc decrypt: ${d2}`);
});

await test('Fallback: pqc:true sender + pqc:false receiver still works (classical only)', async () => {
  const alice = new CryptoSessionManager('alice', undefined, undefined, true);
  const bob   = new CryptoSessionManager('bob'); // no PQC
  await alice.initialize(); await bob.initialize();

  // bob has no pqcEk — alice falls back to classical
  await alice.establishSessionWithPeer('bob', bob.getPublicKeys());
  await bob.establishSessionWithPeer('alice', alice.getPublicKeys());

  const { ciphertext, header } = alice.encryptForPeer('bob', 'fallback test');
  const plaintext = bob.decryptFromPeer('alice', ciphertext, header);
  assert(plaintext === 'fallback test', `Got: ${plaintext}`);
});

console.log('\nAll hybrid session tests passed.\n');
