/**
 * Type declarations for libsodium-wrappers
 */

declare module 'libsodium-wrappers' {
  const sodium: {
    randombytes_buf(length: number): Uint8Array;
    crypto_kx_keypair(): { publicKey: Uint8Array; privateKey: Uint8Array };
    crypto_kx_client_session_keys(
      clientPublicKey: Uint8Array,
      clientPrivateKey: Uint8Array,
      serverPublicKey: Uint8Array
    ): { sharedTx: Uint8Array; sharedRx: Uint8Array };
    crypto_scalarmult(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
    crypto_generichash(
      length: number,
      key: Uint8Array,
      message?: Uint8Array,
      context?: Uint8Array
    ): Uint8Array;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
      message: Uint8Array,
      additionalData: Uint8Array | null,
      nonce: Uint8Array | null,
      key: Uint8Array
    ): Uint8Array;
    crypto_aead_xchacha20poly1305_ietf_decrypt(
      additionalData: Uint8Array | null,
      ciphertext: Uint8Array,
      nonce: Uint8Array | null,
      key: Uint8Array
    ): Uint8Array;
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES: number;
    crypto_sign_keypair(): { publicKey: Uint8Array; privateKey: Uint8Array };
    crypto_sign_detached(message: Uint8Array, privateKey: Uint8Array): Uint8Array;
    crypto_sign_verify_detached(
      signature: Uint8Array,
      message: Uint8Array,
      publicKey: Uint8Array
    ): boolean;
    from_string(str: string): Uint8Array;
    to_string(bytes: Uint8Array): string;
    to_hex(bytes: Uint8Array): string;
    from_hex(hex: string): Uint8Array;
    to_base64(bytes: Uint8Array): string;
    from_base64(base64: string): Uint8Array;
    ready: Promise<void>;
  };
  export default sodium;
}
