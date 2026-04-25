/**
 * Sealed Sender — metadata protection
 *
 * Hides the sender's identity from the relay server.
 * The relay sees only: { to, sealedEnvelope } — it cannot learn who sent the message.
 *
 * Protocol:
 *   1. Sender generates an ephemeral ECDH key pair (epk)
 *   2. Computes shared secret: ECDH(epk_priv, recipient_identity_pub)
 *   3. Derives AES key + nonce via HKDF
 *   4. Encrypts { from, ciphertext, header } with AES-256-GCM
 *   5. Sends { to, sealedEnvelope: epk_pub ‖ nonce ‖ tag ‖ ciphertext }
 *
 * On receive:
 *   1. Recipient computes shared secret: ECDH(identity_priv, epk_pub)
 *   2. Derives same AES key + nonce
 *   3. Decrypts → recovers { from, ciphertext, header }
 *   4. Proceeds with normal Double Ratchet decryption
 *
 * Security properties:
 *   - Relay never sees `from` in plaintext
 *   - Each envelope uses a fresh ephemeral key → no linkability
 *   - AEAD prevents tampering with the envelope
 *   - Does NOT hide `to` (relay needs it for routing) — that requires mix networks
 */

import nodeCrypto from 'node:crypto';

const CURVE   = 'prime256v1';
const PUB_LEN = 65;  // uncompressed P-256

// Envelope layout:
//   [0..64]    ephemeral public key  (65 B)
//   [65..76]   nonce                 (12 B)
//   [77..92]   GCM auth tag          (16 B)
//   [93..]     ciphertext            (variable)
const EPK_OFFSET   = 0;
const NONCE_OFFSET = PUB_LEN;
const TAG_OFFSET   = PUB_LEN + 12;
const CT_OFFSET    = PUB_LEN + 12 + 16;

export interface SealedEnvelopeInput {
  from: string;
  ciphertext: string;  // base64url
  header: string;      // base64url
}

export interface SealedEnvelopeOutput {
  from: string;
  ciphertext: string;
  header: string;
}

function ecdhSecret(privKey: Buffer, pubKey: Buffer): Buffer {
  const ecdh = nodeCrypto.createECDH(CURVE);
  ecdh.setPrivateKey(privKey);
  return Buffer.from(ecdh.computeSecret(pubKey));
}

function deriveKey(sharedSecret: Buffer, epkPub: Buffer): { aesKey: Buffer; nonce: Buffer } {
  const ikm  = Buffer.concat([sharedSecret, epkPub]);
  const salt = Buffer.from('stvor-sealed-sender-v1');
  const key  = Buffer.from(nodeCrypto.hkdfSync('sha256', ikm, salt, 'aes-key', 32));
  const nonce = Buffer.from(nodeCrypto.hkdfSync('sha256', ikm, salt, 'aes-nonce', 12));
  return { aesKey: key, nonce };
}

/**
 * Seal a message envelope so the relay cannot see the sender.
 *
 * @param input         { from, ciphertext, header } — the inner message
 * @param recipientIK   Recipient's identity public key (65-byte uncompressed P-256)
 * @returns             base64url-encoded sealed envelope
 */
export function sealEnvelope(input: SealedEnvelopeInput, recipientIK: Buffer): string {
  // 1. Generate ephemeral key pair
  const ecdh = nodeCrypto.createECDH(CURVE);
  ecdh.generateKeys();
  const epkPub  = Buffer.from(ecdh.getPublicKey());
  const epkPriv = Buffer.from(ecdh.getPrivateKey());

  // 2. ECDH with recipient's identity key
  const sharedSecret = ecdhSecret(epkPriv, recipientIK);
  const { aesKey, nonce } = deriveKey(sharedSecret, epkPub);

  // 3. Encrypt inner payload
  const plaintext = Buffer.from(JSON.stringify(input), 'utf-8');
  const cipher = nodeCrypto.createCipheriv('aes-256-gcm', aesKey, nonce);
  const ct  = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  // 4. Assemble envelope: epkPub ‖ nonce ‖ tag ‖ ct
  const envelope = Buffer.concat([epkPub, nonce, tag, ct]);
  return envelope.toString('base64url');
}

/**
 * Unseal a message envelope.
 *
 * @param sealedEnvelope  base64url-encoded sealed envelope
 * @param myIKPriv        Recipient's identity private key (32 bytes)
 * @returns               Decrypted { from, ciphertext, header }
 */
export function unsealEnvelope(sealedEnvelope: string, myIKPriv: Buffer): SealedEnvelopeOutput {
  const buf = Buffer.from(sealedEnvelope, 'base64url');

  if (buf.length < CT_OFFSET + 1) {
    throw new Error('Sealed envelope too short');
  }

  const epkPub = buf.subarray(EPK_OFFSET, NONCE_OFFSET);
  const nonce  = buf.subarray(NONCE_OFFSET, TAG_OFFSET);
  const tag    = buf.subarray(TAG_OFFSET, CT_OFFSET);
  const ct     = buf.subarray(CT_OFFSET);

  // 1. ECDH with ephemeral public key
  const sharedSecret = ecdhSecret(myIKPriv, epkPub);
  const { aesKey } = deriveKey(sharedSecret, epkPub);

  // 2. Decrypt
  const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', aesKey, nonce);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ct), decipher.final()]);

  return JSON.parse(plaintext.toString('utf-8')) as SealedEnvelopeOutput;
}
