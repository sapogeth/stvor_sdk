/**
 * ML-KEM-768 tests
 * Verifies correctness of keygen, encaps, decaps, and hybrid KDF
 */

import { pqcKeyGen, pqcEncaps, pqcDecaps, hybridKDF, EK_SIZE, DK_SIZE, CT_SIZE, SS_SIZE } from '../index.js';
import nodeCrypto from 'node:crypto';

async function test(name: string, fn: () => void | Promise<void>) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
  } catch (e: any) {
    console.error(`  ✗ ${name}: ${e.message}`);
    process.exit(1);
  }
}

function assert(cond: boolean, msg: string) {
  if (!cond) throw new Error(msg);
}

function bufEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

console.log('\nML-KEM-768 (Post-Quantum KEM) Tests\n');

await test('Key sizes are correct', () => {
  const { ek, dk } = pqcKeyGen();
  assert(ek.length === EK_SIZE, `ek size: expected ${EK_SIZE}, got ${ek.length}`);
  assert(dk.length === DK_SIZE, `dk size: expected ${DK_SIZE}, got ${dk.length}`);
});

await test('Encaps produces correct sizes', () => {
  const { ek } = pqcKeyGen();
  const { ciphertext, sharedSecret } = pqcEncaps(ek);
  assert(ciphertext.length === CT_SIZE, `ct size: expected ${CT_SIZE}, got ${ciphertext.length}`);
  assert(sharedSecret.length === SS_SIZE, `ss size: expected ${SS_SIZE}, got ${sharedSecret.length}`);
});

await test('Encaps/Decaps shared secrets match', () => {
  const { ek, dk } = pqcKeyGen();
  const { ciphertext, sharedSecret: ss1 } = pqcEncaps(ek);
  const ss2 = pqcDecaps(ciphertext, dk);
  assert(bufEqual(ss1, ss2), 'Shared secrets do not match');
});

await test('Different keypairs produce different shared secrets', () => {
  const kp1 = pqcKeyGen();
  const kp2 = pqcKeyGen();
  const { ciphertext, sharedSecret: ss1 } = pqcEncaps(kp1.ek);
  const ss2 = pqcDecaps(ciphertext, kp2.dk); // wrong key
  assert(!bufEqual(ss1, ss2), 'Wrong key produced same shared secret');
});

await test('Each encaps produces unique ciphertext', () => {
  const { ek } = pqcKeyGen();
  const { ciphertext: ct1 } = pqcEncaps(ek);
  const { ciphertext: ct2 } = pqcEncaps(ek);
  assert(!bufEqual(ct1, ct2), 'Two encaps produced identical ciphertext');
});

await test('Each encaps produces unique shared secret', () => {
  const { ek } = pqcKeyGen();
  const { sharedSecret: ss1 } = pqcEncaps(ek);
  const { sharedSecret: ss2 } = pqcEncaps(ek);
  assert(!bufEqual(ss1, ss2), 'Two encaps produced identical shared secret');
});

await test('Tampered ciphertext causes implicit rejection (different SS)', () => {
  const { ek, dk } = pqcKeyGen();
  const { ciphertext, sharedSecret: ss1 } = pqcEncaps(ek);
  const tampered = new Uint8Array(ciphertext);
  tampered[42] ^= 0xff;
  const ss2 = pqcDecaps(tampered, dk);
  // ML-KEM uses implicit rejection — returns random-looking SS, not throwing
  assert(!bufEqual(ss1, ss2), 'Tampered ciphertext produced same shared secret');
});

await test('Shared secret is not all zeros', () => {
  const { ek, dk } = pqcKeyGen();
  const { ciphertext, sharedSecret } = pqcEncaps(ek);
  const ss = pqcDecaps(ciphertext, dk);
  const allZero = ss.every(b => b === 0);
  assert(!allZero, 'Shared secret is all zeros');
});

await test('hybridKDF combines classical and PQC secrets', () => {
  const classical = nodeCrypto.randomBytes(32);
  const pqc       = nodeCrypto.randomBytes(32);
  const hybrid    = hybridKDF(classical, pqc);
  assert(hybrid.length === 32, `hybrid length: ${hybrid.length}`);
  // Must differ from either input alone
  assert(!bufEqual(hybrid, classical), 'Hybrid == classical input');
  assert(!bufEqual(hybrid, pqc),       'Hybrid == pqc input');
});

await test('hybridKDF is deterministic', () => {
  const classical = nodeCrypto.randomBytes(32);
  const pqc       = nodeCrypto.randomBytes(32);
  const h1 = hybridKDF(classical, pqc);
  const h2 = hybridKDF(classical, pqc);
  assert(bufEqual(h1, h2), 'hybridKDF is not deterministic');
});

await test('hybridKDF with different inputs produces different outputs', () => {
  const c1 = nodeCrypto.randomBytes(32);
  const c2 = nodeCrypto.randomBytes(32);
  const p  = nodeCrypto.randomBytes(32);
  const h1 = hybridKDF(c1, p);
  const h2 = hybridKDF(c2, p);
  assert(!bufEqual(h1, h2), 'Different classical inputs produced same hybrid');
});

await test('Full hybrid flow: keygen → encaps → decaps → hybridKDF', () => {
  const { ek, dk } = pqcKeyGen();

  // Sender side
  const classicalSS_sender = nodeCrypto.randomBytes(32); // simulated X3DH output
  const { ciphertext, sharedSecret: pqcSS_sender } = pqcEncaps(ek);
  const hybridSS_sender = hybridKDF(classicalSS_sender, pqcSS_sender);

  // Recipient side
  const classicalSS_recip = new Uint8Array(classicalSS_sender); // same X3DH output
  const pqcSS_recip       = pqcDecaps(ciphertext, dk);
  const hybridSS_recip    = hybridKDF(classicalSS_recip, pqcSS_recip);

  assert(bufEqual(hybridSS_sender, hybridSS_recip), 'Hybrid session keys do not match');
});

console.log('\nAll ML-KEM-768 tests passed.\n');
