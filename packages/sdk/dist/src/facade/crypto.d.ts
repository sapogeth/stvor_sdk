import crypto from 'crypto';
export type EncryptedMessage = {
    version: number;
    senderPub: string;
    nonce: string;
    ciphertext: string;
    tag: string;
};
export declare class CryptoSession {
    privateKey: crypto.KeyObject;
    publicKey: crypto.KeyObject;
    readonly publicKeyBase64: string;
    constructor();
    exportPublic(): string;
    private deriveShared;
    encrypt(plaintext: Uint8Array, remotePubBase64: string): EncryptedMessage;
    decrypt(msg: EncryptedMessage, remotePubBase64: string): Uint8Array;
}
export default CryptoSession;
