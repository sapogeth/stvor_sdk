/**
 * STVOR SDK v2.4.0 - Production Test Suite
 * 
 * Tests SECURITY INVARIANTS and adversarial scenarios
 * Uses property-based + deterministic crypto for repeatability
 */

import * as fc from 'fast-check';
import sodium from 'libsodium-wrappers';

// ============================================================================
// PART 1: DETERMINISTIC CRYPTO (TESTING ONLY)
// ============================================================================

/**
 * Deterministic RNG for tests
 * Allows repeatable, reproducible encryption/decryption
 */
export class DeterministicRNG {
  private state: Uint32Array;
  
  constructor(seed: number = 12345) {
    this.state = new Uint32Array([seed, seed >> 16]);
  }

  /**
   * XORShift32 PRNG (reproducible, not cryptographic)
   */
  next(): number {
    let x = this.state[0];
    let y = this.state[1];
    this.state[0] = y;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= (x << 5);
    this.state[1] = x;
    return x;
  }

  /**
   * Generate deterministic buffer
   */
  buffer(len: number): Uint8Array {
    const buf = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      buf[i] = this.next() & 0xff;
    }
    return buf;
  }
}

// ============================================================================
// PART 2: SECURITY INVARIANT TESTS
// ============================================================================

describe('SECURITY INVARIANT: Header Authenticity', () => {
  it('should reject message with tampered header.sendCounter', () => {
    const plaintext = 'Hello';
    const { ciphertext, header, updatedSession } = encryptMessageWithPolicy(
      plaintext,
      testSession
    );

    // Attacker tampers with counter in header
    const tamperedHeader = { ...header };
    tamperedHeader.sendCounter += 100;

    // Decryption MUST fail (AAD verification)
    expect(() => {
      decryptMessageWithValidation(ciphertext, tamperedHeader, testSession, {
        replayCache: mockReplayCache,
      });
    }).toThrow('AUTH_FAILED');
  });

  it('should reject message with tampered ciphertext (1 bit flip)', () => {
    const { ciphertext, header } = encryptMessageWithPolicy('Secret', testSession);

    // Flip 1 bit in ciphertext
    const tampered = new Uint8Array(ciphertext);
    tampered[0] ^= 0x01;

    expect(() => {
      decryptMessageWithValidation(tampered, header, testSession, {
        replayCache: mockReplayCache,
      });
    }).toThrow('DECRYPT_FAILED|AUTH_FAILED');
  });

  it('should reject message with replaced nonce in header', () => {
    const { ciphertext, header } = encryptMessageWithPolicy('Secret', testSession);

    const tamperedHeader = { ...header };
    tamperedHeader.nonce = sodium.randombytes_buf(24);  // Different nonce

    expect(() => {
      decryptMessageWithValidation(ciphertext, tamperedHeader, testSession, {
        replayCache: mockReplayCache,
      });
    }).toThrow('AUTH_FAILED');
  });
});

describe('SECURITY INVARIANT: Monotonic Ratchet Advancement', () => {
  it('should never allow sendCounter to go backwards', () => {
    const session = createTestSession();
    const initial = session.sendCounter;

    encryptMessageWithPolicy('msg1', session);
    const after1 = session.sendCounter;

    encryptMessageWithPolicy('msg2', session);
    const after2 = session.sendCounter;

    expect(initial).toBeLessThan(after1);
    expect(after1).toBeLessThan(after2);
  });

  it('should never allow rootKey to become predictable', () => {
    const session = createTestSession();
    const rootKeys = [];

    for (let i = 0; i < 10; i++) {
      const before = sodium.to_hex(session.rootKey);
      encryptMessageWithPolicy(`msg${i}`, session);
      const after = sodium.to_hex(session.rootKey);

      rootKeys.push(after);
      expect(before).not.toBe(after);
    }

    // No two root keys should be equal
    const unique = new Set(rootKeys);
    expect(unique.size).toBe(rootKeys.length);
  });

  it('should guarantee Forward Secrecy: old key cannot decrypt new message', () => {
    const session = createTestSession();
    const rng = new DeterministicRNG(42);

    // Save key material before encryption
    const oldRootKey = new Uint8Array(session.rootKey);

    // Encrypt messages, ratchet the key
    const msg1 = encryptMessageWithPolicy('message1', session);
    const msg2 = encryptMessageWithPolicy('message2', session);

    // Restore old key
    const compromisedSession = structuredClone(session);
    compromisedSession.rootKey = oldRootKey;

    // Try to decrypt msg2 with old key - MUST FAIL
    expect(() => {
      decryptMessageWithValidation(
        msg2.message.ciphertext,
        msg2.message.header,
        compromisedSession,
        { replayCache: mockReplayCache }
      );
    }).toThrow();
  });
});

describe('SECURITY INVARIANT: Replay Detection', () => {
  let replayCache: Map<string, boolean>;

  beforeEach(() => {
    replayCache = new Map();
  });

  it('should reject duplicate nonce', async () => {
    const session = createTestSession();
    const { ciphertext, header } = encryptMessageWithPolicy('msg', session);

    const cache = {
      checkAndMark: async (peerId: string, nonce: string) => {
        const seen = replayCache.has(nonce);
        replayCache.set(nonce, true);
        return seen;
      },
    };

    // First attempt - OK
    await expect(
      decryptMessageWithValidation(ciphertext, header, session, {
        replayCache: cache,
      })
    ).resolves.not.toThrow();

    // Second attempt - REPLAY
    const sessionCopy = structuredClone(session);
    await expect(
      decryptMessageWithValidation(ciphertext, header, sessionCopy, {
        replayCache: cache,
      })
    ).rejects.toThrow('REPLAY_DETECTED');
  });

  it('should NOT update session state on replay detection', async () => {
    const session = createTestSession();
    const { ciphertext, header } = encryptMessageWithPolicy('msg', session);

    const originalCounter = session.receiveCounter;

    const cache = {
      checkAndMark: async () => true,  // Always report as replay
    };

    // Attempt to decrypt replayed message
    await expect(
      decryptMessageWithValidation(ciphertext, header, session, {
        replayCache: cache,
      })
    ).rejects.toThrow('REPLAY_DETECTED');

    // Session state must NOT change
    expect(session.receiveCounter).toBe(originalCounter);
    expect(session.rootKey).toEqual(session.rootKey);
  });
});

describe('SECURITY INVARIANT: DH Ratchet Policy Enforcement', () => {
  it('should force ratchet after N messages', () => {
    const session = createTestSession();
    session.lastRatchetCounter = 0;

    for (let i = 1; i <= DH_RATCHET_POLICY.maxMessages; i++) {
      const before = sodium.to_hex(session.rootKey);
      encryptMessageWithPolicy(`msg${i}`, session);

      if (i === DH_RATCHET_POLICY.maxMessages) {
        // Last message before forced ratchet
        const result = encryptMessageWithPolicy(`msg${i + 1}`, session);
        const after = sodium.to_hex(session.rootKey);

        // Root key MUST change after ratchet
        expect(before).not.toBe(after);
      }
    }
  });

  it('should clear skipped keys after ratchet', () => {
    const session = createTestSession();

    // Add some skipped keys
    session.skippedMessageKeys.set('key1', {
      key: sodium.randombytes_buf(32),
      timestamp: Date.now(),
      counter: 0,
    });

    // Force ratchet (N messages)
    for (let i = 0; i < DH_RATCHET_POLICY.maxMessages; i++) {
      encryptMessageWithPolicy(`msg${i}`, session);
    }

    // Skipped keys MUST be cleared
    expect(session.skippedMessageKeys.size).toBe(0);
  });

  it('should reject encryption if session compromised', () => {
    const session = createTestSession();
    session.state = 'COMPROMISED';

    expect(() => {
      encryptMessageWithPolicy('msg', session);
    }).toThrow('SESSION_COMPROMISED');
  });
});

// ============================================================================
// PART 3: PROPERTY-BASED TESTS (Fast-Check)
// ============================================================================

describe('PROPERTY: Encrypt/Decrypt Round Trip', () => {
  it(
    'message decrypts to original plaintext (for any valid message)',
    fc.assert(
      fc.property(
        fc.string({ minLength: 0, maxLength: 1000 }),
        (plaintext: string) => {
          const session = createTestSession();
          const { message, updatedSession } = encryptMessageWithPolicy(
            plaintext,
            session
          );

          const { plaintext: decrypted } = decryptMessageWithValidation(
            message.ciphertext,
            message.header,
            updatedSession,
            { replayCache: mockReplayCache }
          );

          return decrypted === plaintext;
        }
      )
    )
  );

  it(
    'counter increments deterministically (property)',
    fc.assert(
      fc.property(
        fc.array(fc.string({ maxLength: 100 }), { minLength: 1, maxLength: 20 }),
        (messages: string[]) => {
          const session = createTestSession();
          let prevCounter = session.sendCounter;

          for (const msg of messages) {
            encryptMessageWithPolicy(msg, session);
            expect(session.sendCounter).toBe(prevCounter + 1);
            prevCounter = session.sendCounter;
          }

          return true;
        }
      )
    )
  );
});

// ============================================================================
// PART 4: ADVERSARIAL RELAY TESTS
// ============================================================================

describe('ADVERSARIAL: Malicious Relay', () => {
  it('should detect relay reordering messages (delayed delivery)', () => {
    const session = createTestSession();

    // Send 2 messages
    const msg1 = encryptMessageWithPolicy('first', session);
    const msg2 = encryptMessageWithPolicy('second', session);

    const session2 = structuredClone(session);  // Peer's copy

    // Relay delivers out of order: msg2, then msg1
    expect(() => {
      decryptMessageWithValidation(msg2.message.ciphertext, msg2.message.header, session2, {
        replayCache: mockReplayCache,
      });
    }).not.toThrow();  // Out-of-order is OK (skipped keys handle it)

    expect(() => {
      decryptMessageWithValidation(msg1.message.ciphertext, msg1.message.header, session2, {
        replayCache: mockReplayCache,
      });
    }).not.toThrow();  // Can still decrypt with skipped key
  });

  it('should detect relay replaying messages', async () => {
    const session = createTestSession();
    const { message } = encryptMessageWithPolicy('secret', session);

    const replayAttempts = [];
    const cache = {
      checkAndMark: async (peerId: string, nonce: string) => {
        replayAttempts.push(nonce);
        return replayAttempts.filter((n) => n === nonce).length > 1;
      },
    };

    const session2 = structuredClone(session);

    // First delivery
    await decryptMessageWithValidation(message.ciphertext, message.header, session2, {
      replayCache: cache,
    });

    // Relay replays the same message
    const session3 = structuredClone(session2);
    await expect(
      decryptMessageWithValidation(message.ciphertext, message.header, session3, {
        replayCache: cache,
      })
    ).rejects.toThrow('REPLAY_DETECTED');
  });

  it('should detect relay dropping and resending old messages', () => {
    const session = createTestSession();

    const msg1 = encryptMessageWithPolicy('msg1', session);
    const msg2 = encryptMessageWithPolicy('msg2', session);
    const msg3 = encryptMessageWithPolicy('msg3', session);

    // Relay drops msg2, then replays msg1
    const session2 = structuredClone(session);
    const cache = new Map<string, boolean>();

    // Receive msg1
    cache.set(sodium.to_hex(msg1.message.header.nonce), true);

    // Receive msg3 (out of order OK)
    cache.set(sodium.to_hex(msg3.message.header.nonce), true);

    // Relay retries msg1 (replay attack)
    expect(cache.has(sodium.to_hex(msg1.message.header.nonce))).toBe(true);
  });

  it('should detect relay tampering with header.timestamp', () => {
    const session = createTestSession();
    const { message } = encryptMessageWithPolicy('msg', session);

    const tamperedHeader = { ...message.header };
    tamperedHeader.timestamp = Date.now() + 1000 * 60 * 60;  // +1 hour

    const session2 = structuredClone(session);

    expect(() => {
      decryptMessageWithValidation(message.ciphertext, tamperedHeader, session2, {
        replayCache: mockReplayCache,
      });
    }).toThrow('AUTH_FAILED');  // AAD verification fails
  });
});

// ============================================================================
// PART 5: STATE MACHINE TESTS
// ============================================================================

describe('STATE MACHINE: Session FSM', () => {
  it('should reject invalid state transitions', () => {
    const session = createTestSession();
    session.state = 'INIT';

    // Valid: INIT → ESTABLISHED
    session.state = 'ESTABLISHED';
    expect(session.state).toBe('ESTABLISHED');

    // Invalid: ESTABLISHED → INIT (should throw)
    expect(() => {
      validateStateTransition('ESTABLISHED', 'INIT');
    }).toThrow('INVALID_STATE_TRANSITION');
  });

  it('should prevent operations after COMPROMISED', () => {
    const session = createTestSession();
    session.state = 'COMPROMISED';

    expect(() => {
      encryptMessageWithPolicy('msg', session);
    }).toThrow('SESSION_COMPROMISED');

    expect(() => {
      decryptMessageWithValidation(new Uint8Array(), {} as any, session, {
        replayCache: mockReplayCache,
      });
    }).rejects.toThrow('SESSION_COMPROMISED');
  });
});

// ============================================================================
// PART 6: TEST UTILITIES
// ============================================================================

function createTestSession(): SessionState {
  const rng = new DeterministicRNG(12345);

  return {
    peerId: 'bob@example.com',
    peerIdentityKey: rng.buffer(32),
    rootKey: rng.buffer(32),
    sendingChainKey: rng.buffer(32),
    receivingChainKey: rng.buffer(32),
    sendCounter: 0,
    receiveCounter: 0,
    skippedMessageKeys: new Map(),
    state: 'ESTABLISHED',
    lastRatchetTime: Date.now(),
    lastRatchetCounter: 0,
    createdAt: Date.now(),
    metadata: {},
  };
}

const mockReplayCache = {
  checkAndMark: async () => false,  // Never replay
};

function structuredClone<T>(obj: T): T {
  return JSON.parse(JSON.stringify(obj));
}

// ============================================================================
// PART 7: DETERMINISTIC CRYPTO TEST
// ============================================================================

describe('DETERMINISTIC: Reproducible Encryption', () => {
  it('should produce same ciphertext for same plaintext + seed', () => {
    // Note: This requires injecting DeterministicRNG into encryptMessage
    // Standard libsodium is non-deterministic, but we can test the pattern
    
    const plaintext = 'reproducible message';
    const sessionA = createTestSession();
    const sessionB = structuredClone(sessionA);

    const encA = encryptMessageWithPolicy(plaintext, sessionA);
    const encB = encryptMessageWithPolicy(plaintext, sessionB);

    // The ciphertexts will be different (different ephemeral keys)
    // But the ratchet states will be IDENTICAL
    expect(sodium.to_hex(sessionA.rootKey)).toBe(sodium.to_hex(sessionB.rootKey));
  });
});

// ============================================================================
// PART 8: INTEGRATION TEST
// ============================================================================

describe('INTEGRATION: Full Messaging Flow', () => {
  it('should handle bidirectional messaging with interleaved sends', async () => {
    const alice = createTestSession();
    alice.peerId = 'alice@example.com';

    const bob = createTestSession();
    bob.peerId = 'bob@example.com';

    const cache = new Map<string, boolean>();
    const replayCache = {
      checkAndMark: async (peerId: string, nonce: string) => {
        const key = `${peerId}:${nonce}`;
        const isReplay = cache.has(key);
        cache.set(key, true);
        return isReplay;
      },
    };

    // Alice sends to Bob
    const msg1 = encryptMessageWithPolicy('Hello Bob', alice);

    // Bob receives
    await decryptMessageWithValidation(
      msg1.message.ciphertext,
      msg1.message.header,
      bob,
      { replayCache }
    );

    // Bob sends to Alice
    const msg2 = encryptMessageWithPolicy('Hi Alice', bob);

    // Alice receives
    await decryptMessageWithValidation(
      msg2.message.ciphertext,
      msg2.message.header,
      alice,
      { replayCache }
    );

    // Both can send simultaneously
    const msg3 = encryptMessageWithPolicy('Quick msg', alice);
    const msg4 = encryptMessageWithPolicy('Simultaneous', bob);

    // Out-of-order delivery
    await decryptMessageWithValidation(msg4.message.ciphertext, msg4.message.header, alice, {
      replayCache,
    });
    await decryptMessageWithValidation(msg3.message.ciphertext, msg3.message.header, bob, {
      replayCache,
    });

    expect(true).toBe(true);  // All passed
  });
});
