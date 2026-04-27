/**
 * NIST ACVTS test vectors for ML-KEM-768 (FIPS 203)
 *
 * Vectors from:
 *   https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
 *
 * Tests:
 *   1. KeyGen: given (d, z) → verify (ek, dk) match expected
 *   2. Encap:  given (ek, m) → verify (ct, ss) match expected
 *   3. Decap:  given (dk, ct) → verify ss matches expected
 */

import { readFileSync } from 'node:fs';
import { mlkemKeyGenFrom, mlkemEncapsFrom, mlkemDecaps } from '../mlkem.js';

function hex(buf: Uint8Array): string {
  return Buffer.from(buf).toString('hex').toUpperCase();
}

function fromHex(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'hex'));
}

function assert(cond: boolean, msg: string) {
  if (!cond) throw new Error(msg);
}

async function test(name: string, fn: () => void) {
  try { fn(); console.log(`  ✓ ${name}`); }
  catch (e: any) { console.error(`  ✗ ${name}: ${e.message}`); process.exit(1); }
}

console.log('\nNIST ACVTS ML-KEM-768 Test Vectors\n');

// ── Load vectors ──────────────────────────────────────────────────────────────

const keygenVectors: { d: string; z: string; ek: string; dk: string }[] =
  JSON.parse(readFileSync('/tmp/mlkem768_keygen.json', 'utf-8'));

const encapVectors: { ek: string; dk: string; m: string; k: string; c: string }[] =
  JSON.parse(readFileSync('/tmp/mlkem768_encap.json', 'utf-8'));

console.log(`Loaded ${keygenVectors.length} keygen vectors, ${encapVectors.length} encap vectors\n`);

// ── KeyGen tests ──────────────────────────────────────────────────────────────

let keygenPass = 0, keygenFail = 0;

for (let i = 0; i < keygenVectors.length; i++) {
  const v = keygenVectors[i];
  const d = fromHex(v.d);
  const z = fromHex(v.z);
  const { ek, dk } = mlkemKeyGenFrom(d, z);

  const ekMatch = hex(ek) === v.ek.toUpperCase();
  const dkMatch = hex(dk) === v.dk.toUpperCase();

  if (ekMatch && dkMatch) {
    keygenPass++;
  } else {
    keygenFail++;
    if (keygenFail <= 2) {
      console.error(`  ✗ KeyGen vector ${i + 1}:`);
      if (!ekMatch) {
        console.error(`    ek expected: ${v.ek.slice(0, 32)}...`);
        console.error(`    ek got:      ${hex(ek).slice(0, 32).toLowerCase()}...`);
      }
      if (!dkMatch) {
        console.error(`    dk expected: ${v.dk.slice(0, 32)}...`);
        console.error(`    dk got:      ${hex(dk).slice(0, 32).toLowerCase()}...`);
      }
    }
  }
}

if (keygenFail === 0) {
  console.log(`  ✓ KeyGen: all ${keygenPass} vectors match`);
} else {
  console.error(`  ✗ KeyGen: ${keygenPass} pass, ${keygenFail} FAIL`);
  process.exit(1);
}

// ── Encap + Decap tests ───────────────────────────────────────────────────────

let encapPass = 0, encapFail = 0;
let decapPass = 0, decapFail = 0;

for (let i = 0; i < encapVectors.length; i++) {
  const v = encapVectors[i];
  const ek = fromHex(v.ek);
  const dk = fromHex(v.dk);
  const m  = fromHex(v.m);

  // Encap
  const { ciphertext, sharedSecret: ss_enc } = mlkemEncapsFrom(ek, m);
  const ctMatch = hex(ciphertext) === v.c.toUpperCase();
  const ssEncMatch = hex(ss_enc) === v.k.toUpperCase();

  if (ctMatch && ssEncMatch) {
    encapPass++;
  } else {
    encapFail++;
    if (encapFail <= 2) {
      console.error(`  ✗ Encap vector ${i + 1}:`);
      if (!ctMatch) {
        console.error(`    ct expected: ${v.c.slice(0, 32)}...`);
        console.error(`    ct got:      ${hex(ciphertext).slice(0, 32).toLowerCase()}...`);
      }
      if (!ssEncMatch) {
        console.error(`    ss expected: ${v.k.slice(0, 32)}...`);
        console.error(`    ss got:      ${hex(ss_enc).slice(0, 32).toLowerCase()}...`);
      }
    }
  }

  // Decap
  const ss_dec = mlkemDecaps(ciphertext, dk);
  const ssDecMatch = hex(ss_dec) === v.k.toUpperCase();

  if (ssDecMatch) {
    decapPass++;
  } else {
    decapFail++;
    if (decapFail <= 2) {
      console.error(`  ✗ Decap vector ${i + 1}:`);
      console.error(`    ss expected: ${v.k.slice(0, 32)}...`);
      console.error(`    ss got:      ${hex(ss_dec).slice(0, 32).toLowerCase()}...`);
    }
  }
}

if (encapFail === 0) {
  console.log(`  ✓ Encap: all ${encapPass} vectors match`);
} else {
  console.error(`  ✗ Encap: ${encapPass} pass, ${encapFail} FAIL`);
  process.exit(1);
}

if (decapFail === 0) {
  console.log(`  ✓ Decap: all ${decapPass} vectors match`);
} else {
  console.error(`  ✗ Decap: ${decapPass} pass, ${decapFail} FAIL`);
  process.exit(1);
}

console.log('\nAll NIST ACVTS vectors passed.\n');
