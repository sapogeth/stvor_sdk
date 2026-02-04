/**
 * X3DH + Double Ratchet Implementation
 * This module handles session establishment and message encryption/decryption.
 */
export interface SessionState {
    identityKey: Uint8Array;
    signedPreKey: Uint8Array;
    oneTimePreKey: Uint8Array;
    rootKey: Uint8Array;
    sendingChainKey: Uint8Array;
    receivingChainKey: Uint8Array;
    skippedMessageKeys: Map<string, Uint8Array>;
    isPostCompromise: boolean;
}
export declare function initializeCrypto(): Promise<void>;
/**
 * X3DH Session Establishment
 * @param identityKeyPair - The user's identity key pair
 * @param signedPreKeyPair - The user's signed pre-key pair
 * @param oneTimePreKey - A one-time pre-key
 * @param recipientIdentityKey - The recipient's identity key
 * @param recipientSignedPreKey - The recipient's signed pre-key
 * @param recipientOneTimePreKey - The recipient's one-time pre-key
 * @param recipientSPKSignature - Signature of SPK by recipient's identity key
 * @param protocolVersion - The protocol version
 * @param cipherSuite - The cipher suite
 * @returns SessionState
 */
export declare function establishSession(identityKeyPair: {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}, signedPreKeyPair: {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}, oneTimePreKey: Uint8Array, recipientIdentityKey: Uint8Array, recipientSignedPreKey: Uint8Array, recipientOneTimePreKey: Uint8Array, recipientSPKSignature: Uint8Array, protocolVersion: string, cipherSuite: string): SessionState;
/**
 * Double Ratchet Encryption
 * @param plaintext - The message to encrypt
 * @param session - The current session state
 * @returns { ciphertext: Uint8Array; header: { publicKey: Uint8Array; nonce: Uint8Array } }
 */
export declare function encryptMessage(plaintext: string, session: SessionState): {
    ciphertext: any;
    header: {
        publicKey: any;
        nonce: any;
    };
};
/**
 * Double Ratchet Decryption
 * @param ciphertext - The encrypted message
 * @param header - The message header containing the sender's public key and nonce
 * @param session - The current session state
 * @returns The decrypted plaintext
 */
export declare function decryptMessage(ciphertext: Uint8Array, header: {
    publicKey: Uint8Array;
    nonce: Uint8Array;
}, session: SessionState): string;
export declare function addSkippedKey(session: SessionState, header: {
    publicKey: Uint8Array;
    nonce: Uint8Array;
}, messageKey: Uint8Array): void;
export declare function removeSkippedKey(session: SessionState, header: {
    publicKey: Uint8Array;
    nonce: Uint8Array;
}): void;
export declare function processSkippedKeys(session: SessionState): void;
export declare function handleSimultaneousSend(session: SessionState, isInitiator: boolean): void;
export declare function generateOPKPool(): void;
export declare function consumeOPKAtomically(userId: string): Uint8Array;
export declare function enforceDHRatchetPolicy(session: SessionState, remotePublicKey: Uint8Array, suspectedCompromise?: boolean): void;
/**
 * Increment message counter and enforce policy.
 */
export declare function incrementMessageCounter(session: SessionState, remotePublicKey: Uint8Array): void;
/**
 * Force a DH ratchet step to enable PCS.
 * @param session - The current session state.
 * @param remotePublicKey - The remote party's ephemeral public key.
 */
export declare function forceDHRatchet(session: SessionState, remotePublicKey: Uint8Array): void;
/**
 * Trigger PCS recovery only after receiving a new DH public key.
 * @param session - The current session state.
 * @param remotePublicKey - The new DH public key from the remote party.
 */
export declare function receiveNewDHPublicKey(session: SessionState, remotePublicKey: Uint8Array): void;
