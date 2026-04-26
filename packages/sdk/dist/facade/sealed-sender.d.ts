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
export interface SealedEnvelopeInput {
    from: string;
    ciphertext: string;
    header: string;
}
export interface SealedEnvelopeOutput {
    from: string;
    ciphertext: string;
    header: string;
}
/**
 * Seal a message envelope so the relay cannot see the sender.
 *
 * @param input         { from, ciphertext, header } — the inner message
 * @param recipientIK   Recipient's identity public key (65-byte uncompressed P-256)
 * @returns             base64url-encoded sealed envelope
 */
export declare function sealEnvelope(input: SealedEnvelopeInput, recipientIK: Buffer): string;
/**
 * Unseal a message envelope.
 *
 * @param sealedEnvelope  base64url-encoded sealed envelope
 * @param myIKPriv        Recipient's identity private key (32 bytes)
 * @returns               Decrypted { from, ciphertext, header }
 */
export declare function unsealEnvelope(sealedEnvelope: string, myIKPriv: Buffer): SealedEnvelopeOutput;
