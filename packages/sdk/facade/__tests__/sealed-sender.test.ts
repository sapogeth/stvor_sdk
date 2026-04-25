/**
 * Sealed Sender tests
 * Verifies that the relay cannot learn sender identity from the envelope
 */

import { sealEnvelope, unsealEnvelope } from '../sealed-sender.js';
import nodeCrypto from 'node:crypto';

async function test(name: string, fn: () => Promise<void> | void) {
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

function genIdentityKey(): { pub: Buffer; priv: Buffer } {
  const ecdh = nodeCrypto.createECDH('prime256v1');
  ecdh.generateKeys();
  return { pub: Buffer.from(ecdh.getPublicKey()), priv: Buffer.from(ecdh.getPrivateKey()) };
}

console.log('\nSealed Sender Tests\n');

await test('Seal and unseal recovers original payload', async () => {
  const recipient = genIdentityKey();
  const input = { from: 'alice', ciphertext: 'abc123', header: 'hdr456' };

  const sealed = sealEnvelope(input, recipient.pub);
  const output = unsealEnvelope(sealed, recipient.priv);

  assert(output.from === input.from,           `from: ${output.from}`);
  assert(output.ciphertext === input.ciphertext, `ct: ${output.ciphertext}`);
  assert(output.header === input.header,         `hdr: ${output.header}`);
});

await test('Sealed envelope does not contain plaintext sender', async () => {
  const recipient = genIdentityKey();
  const input = { from: 'alice-secret-identity', ciphertext: 'ct', header: 'hdr' };

  const sealed = sealEnvelope(input, recipient.pub);
  const raw = Buffer.from(sealed, 'base64url').toString('utf-8');

  assert(!raw.includes('alice-secret-identity'), 'Sender identity found in envelope — not sealed!');
});

await test('Each seal produces a different envelope (fresh ephemeral key)', async () => {
  const recipient = genIdentityKey();
  const input = { from: 'alice', ciphertext: 'same', header: 'same' };

  const s1 = sealEnvelope(input, recipient.pub);
  const s2 = sealEnvelope(input, recipient.pub);

  assert(s1 !== s2, 'Envelopes are identical — ephemeral key not fresh!');
});

await test('Wrong private key cannot unseal', async () => {
  const recipient = genIdentityKey();
  const attacker  = genIdentityKey();
  const input = { from: 'alice', ciphertext: 'ct', header: 'hdr' };

  const sealed = sealEnvelope(input, recipient.pub);

  let threw = false;
  try { unsealEnvelope(sealed, attacker.priv); }
  catch { threw = true; }

  assert(threw, 'Attacker should not be able to unseal');
});

await test('Tampered envelope is rejected (AEAD auth)', async () => {
  const recipient = genIdentityKey();
  const input = { from: 'alice', ciphertext: 'ct', header: 'hdr' };

  const sealed = sealEnvelope(input, recipient.pub);
  const buf = Buffer.from(sealed, 'base64url');
  // Flip a byte in the ciphertext region
  buf[buf.length - 1] ^= 0xff;
  const tampered = buf.toString('base64url');

  let threw = false;
  try { unsealEnvelope(tampered, recipient.priv); }
  catch { threw = true; }

  assert(threw, 'Tampered envelope should be rejected');
});

await test('Large payload seals and unseals correctly', async () => {
  const recipient = genIdentityKey();
  const bigCt = nodeCrypto.randomBytes(4096).toString('base64url');
  const input = { from: 'alice', ciphertext: bigCt, header: 'hdr' };

  const sealed  = sealEnvelope(input, recipient.pub);
  const output  = unsealEnvelope(sealed, recipient.priv);

  assert(output.ciphertext === bigCt, 'Large payload mismatch');
});

console.log('\nAll sealed sender tests passed.\n');
