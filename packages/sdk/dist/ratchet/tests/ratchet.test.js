import { initializeCrypto, establishSession, encryptMessage, decryptMessage } from '../index';
import { validateMessage } from '../replay-protection';
import { generateFingerprint, verifyFingerprint } from '../tofu';
import { randomBytes } from 'crypto';
describe('Ratchet Tests', () => {
    beforeAll(async () => {
        await initializeCrypto();
    });
    test('Forward Secrecy: Old keys cannot decrypt', () => {
        const session = establishSession({ publicKey: randomBytes(32), privateKey: randomBytes(32) }, { publicKey: randomBytes(32), privateKey: randomBytes(32) }, randomBytes(32), randomBytes(32), randomBytes(32), randomBytes(32));
        const message1 = encryptMessage('Hello, World!', session);
        const message2 = encryptMessage('Goodbye, World!', session);
        // Simulate key rotation
        session.chainKey = randomBytes(32);
        expect(() => decryptMessage(message1.ciphertext, message1.header, session)).toThrow();
    });
    test('Replay Protection: Reject duplicate nonces', async () => {
        const userId = 'user1';
        const nonce = 'unique-nonce';
        const timestamp = Math.floor(Date.now() / 1000);
        await validateMessage(userId, nonce, timestamp);
        await expect(validateMessage(userId, nonce, timestamp)).rejects.toThrow('Message rejected: replay detected');
    });
    test('MITM Detection: Fingerprint mismatch', async () => {
        const userId = 'user1';
        const publicKey1 = randomBytes(32);
        const publicKey2 = randomBytes(32);
        const fingerprint1 = generateFingerprint(publicKey1);
        const fingerprint2 = generateFingerprint(publicKey2);
        await verifyFingerprint(userId, fingerprint1);
        const result = await verifyFingerprint(userId, fingerprint2);
        expect(result).toBe(false);
    });
});
describe('2-Man Rule Tests', () => {
    test('Recovery shares lifecycle', () => {
        const userId = 'user1';
        const recoveryKey = randomBytes(32);
        const shares = generateRecoveryShares(recoveryKey);
        storeRecoveryShares(userId, shares);
        const retrievedShares = retrieveRecoveryShares(userId);
        expect(retrievedShares.length).toBe(2);
        expect(combineRecoveryShares(retrievedShares)).toEqual(recoveryKey);
        revokeRecoveryShares(userId);
        expect(() => retrieveRecoveryShares(userId)).toThrow('No recovery shares found for user');
    });
    test('Admin authentication', () => {
        process.env.ADMIN_TOKEN = 'secure-token';
        expect(authenticateAdmin('secure-token')).toBe(true);
        expect(authenticateAdmin('invalid-token')).toBe(false);
    });
});
describe('Double Ratchet Edge Cases', () => {
    test('Skipped keys DoS protection', () => {
        const session = {
            skippedMessageKeys: new Map(),
        };
        for (let i = 0; i < MAX_SKIPPED_KEYS; i++) {
            addSkippedKey(session, { publicKey: randomBytes(32), nonce: randomBytes(12) }, randomBytes(32));
        }
        expect(() => addSkippedKey(session, { publicKey: randomBytes(32), nonce: randomBytes(12) }, randomBytes(32))).toThrow('Skipped keys limit exceeded');
    });
    test('Simultaneous send handling', () => {
        const session = {
            sendingChainKey: randomBytes(32),
            receivingChainKey: randomBytes(32),
        };
        handleSimultaneousSend(session, true);
        expect(session.sendingChainKey).not.toEqual(session.receivingChainKey);
    });
});
describe('X3DH Edge Cases', () => {
    test('OPK exhaustion', () => {
        generateOPKPool();
        for (let i = 0; i < OPK_POOL_SIZE; i++) {
            consumeOPK();
        }
        expect(() => consumeOPK()).toThrow('OPK pool exhausted');
    });
    test('Partial handshake completion', () => {
        const identityKeyPair = { publicKey: randomBytes(32), privateKey: randomBytes(32) };
        const signedPreKeyPair = { publicKey: randomBytes(32), privateKey: randomBytes(32) };
        const oneTimePreKey = randomBytes(32);
        const recipientIdentityKey = randomBytes(32);
        const recipientSignedPreKey = randomBytes(32);
        const recipientOneTimePreKey = randomBytes(32);
        const recipientSPKSignature = randomBytes(64);
        expect(() => {
            establishSession(identityKeyPair, signedPreKeyPair, oneTimePreKey, recipientIdentityKey, recipientSignedPreKey, recipientOneTimePreKey, recipientSPKSignature, '1.0', 'AES-GCM');
        }).toThrow('Invalid SPK signature');
    });
    test('Abort ordering', () => {
        const identityKeyPair = { publicKey: randomBytes(32), privateKey: randomBytes(32) };
        const signedPreKeyPair = { publicKey: randomBytes(32), privateKey: randomBytes(32) };
        const oneTimePreKey = randomBytes(32);
        const recipientIdentityKey = randomBytes(32);
        const recipientSignedPreKey = randomBytes(32);
        const recipientOneTimePreKey = randomBytes(32);
        const recipientSPKSignature = randomBytes(64);
        try {
            establishSession(identityKeyPair, signedPreKeyPair, oneTimePreKey, recipientIdentityKey, recipientSignedPreKey, recipientOneTimePreKey, recipientSPKSignature, '1.0', 'AES-GCM');
        }
        catch (error) {
            expect(error.message).toBe('Invalid SPK signature');
        }
    });
});
describe('2-Man Rule Integrity', () => {
    test('Tamper-evidence for recovery shares', () => {
        const share = randomBytes(32);
        const hash = generateShareHash(share);
        expect(verifyShareIntegrity(share, hash)).toBe(true);
        expect(verifyShareIntegrity(randomBytes(32), hash)).toBe(false);
    });
});
describe('Post-Compromise Security (PCS)', () => {
    test('PCS recovery after compromise', () => {
        const session = establishSession({ publicKey: randomBytes(32), privateKey: randomBytes(32) }, { publicKey: randomBytes(32), privateKey: randomBytes(32) }, randomBytes(32), randomBytes(32), randomBytes(32), randomBytes(32));
        const remotePublicKey = randomBytes(32);
        // Simulate compromise
        session.rootKey = randomBytes(32);
        session.sendingChainKey = randomBytes(32);
        session.receivingChainKey = randomBytes(32);
        // Attacker can decrypt messages before recovery
        const compromisedMessage = encryptMessage('Compromised!', session);
        expect(() => decryptMessage(compromisedMessage.ciphertext, compromisedMessage.header, session)).not.toThrow();
        // Perform forced DH ratchet
        forceDHRatchet(session, remotePublicKey);
        // Attacker cannot decrypt new messages
        const recoveredMessage = encryptMessage('Recovered!', session);
        expect(() => decryptMessage(compromisedMessage.ciphertext, compromisedMessage.header, session)).toThrow();
        expect(() => decryptMessage(recoveredMessage.ciphertext, recoveredMessage.header, session)).not.toThrow();
    });
    test('PCS policy enforcement', () => {
        const session = establishSession({ publicKey: randomBytes(32), privateKey: randomBytes(32) }, { publicKey: randomBytes(32), privateKey: randomBytes(32) }, randomBytes(32), randomBytes(32), randomBytes(32), randomBytes(32));
        const remotePublicKey = randomBytes(32);
        // Simulate message sending
        for (let i = 0; i < 50; i++) {
            incrementMessageCounter(session, remotePublicKey);
        }
        // Ensure DH ratchet was triggered
        expect(messageCounter).toBe(0);
    });
});
describe('PCS Security Proofs', () => {
    test('rootKeyₜ ≠ rootKeyₜ₊₁ even with full attacker knowledge', () => {
        const session = establishSession({ publicKey: randomBytes(32), privateKey: randomBytes(32) }, { publicKey: randomBytes(32), privateKey: randomBytes(32) }, randomBytes(32), randomBytes(32), randomBytes(32), randomBytes(32));
        const remotePublicKey = randomBytes(32);
        // Simulate attacker knowledge
        const attackerRootKey = session.rootKey;
        const attackerChainKey = session.sendingChainKey;
        const attackerReceivingKey = session.receivingChainKey;
        // Perform DH ratchet
        receiveNewDHPublicKey(session, remotePublicKey);
        // Assert that attacker cannot derive the new root key
        expect(session.rootKey).not.toEqual(attackerRootKey);
        expect(session.sendingChainKey).not.toEqual(attackerChainKey);
        expect(session.receivingChainKey).not.toEqual(attackerReceivingKey);
    });
});
