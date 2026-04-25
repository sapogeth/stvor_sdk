/**
 * Group chat E2EE test
 * Tests Sender Keys: createGroup, sendToGroup, onGroupMessage, add/removeGroupMember
 */

import { CryptoSessionManager } from '../crypto-session.js';

async function test(name: string, fn: () => Promise<void>) {
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

console.log('\nGroup Chat E2EE Tests\n');

// ── Test 1: Alice creates group, sends to Bob ─────────────────────────────────
await test('Alice encrypts group message, Bob decrypts with installed sender key', async () => {
  const alice = new CryptoSessionManager('alice');
  const bob   = new CryptoSessionManager('bob');
  await alice.initialize();
  await bob.initialize();

  // Alice creates group
  alice.createGroupSession('room-1', ['bob']);
  const dist = alice.getSenderKeyDistribution('room-1');

  // Bob installs Alice's sender key
  bob.installSenderKey('room-1', 'alice', dist.chainKey, dist.generation);

  // Alice encrypts
  const plaintext = 'Hello group!';
  const { ciphertext, groupHeader } = alice.encryptForGroup('room-1', plaintext);

  // Bob decrypts
  const decrypted = bob.decryptFromGroup('room-1', 'alice', ciphertext, groupHeader);
  assert(decrypted === plaintext, `Expected "${plaintext}", got "${decrypted}"`);
});

// ── Test 2: Multiple messages, chain advances correctly ───────────────────────
await test('Chain ratchets correctly across multiple messages', async () => {
  const alice = new CryptoSessionManager('alice');
  const bob   = new CryptoSessionManager('bob');
  await alice.initialize();
  await bob.initialize();

  alice.createGroupSession('room-2', ['bob']);
  const dist = alice.getSenderKeyDistribution('room-2');
  bob.installSenderKey('room-2', 'alice', dist.chainKey, dist.generation);

  const messages = ['msg1', 'msg2', 'msg3', 'msg4', 'msg5'];
  for (const m of messages) {
    const { ciphertext, groupHeader } = alice.encryptForGroup('room-2', m);
    const decrypted = bob.decryptFromGroup('room-2', 'alice', ciphertext, groupHeader);
    assert(decrypted === m, `Expected "${m}", got "${decrypted}"`);
  }
});

// ── Test 3: Out-of-order messages ────────────────────────────────────────────
await test('Out-of-order group messages decrypted via skipped key cache', async () => {
  const alice = new CryptoSessionManager('alice');
  const bob   = new CryptoSessionManager('bob');
  await alice.initialize();
  await bob.initialize();

  alice.createGroupSession('room-3', ['bob']);
  const dist = alice.getSenderKeyDistribution('room-3');
  bob.installSenderKey('room-3', 'alice', dist.chainKey, dist.generation);

  // Encrypt 3 messages
  const enc1 = alice.encryptForGroup('room-3', 'first');
  const enc2 = alice.encryptForGroup('room-3', 'second');
  const enc3 = alice.encryptForGroup('room-3', 'third');

  // Deliver out of order: 1, 3, 2
  const d1 = bob.decryptFromGroup('room-3', 'alice', enc1.ciphertext, enc1.groupHeader);
  const d3 = bob.decryptFromGroup('room-3', 'alice', enc3.ciphertext, enc3.groupHeader);
  const d2 = bob.decryptFromGroup('room-3', 'alice', enc2.ciphertext, enc2.groupHeader);

  assert(d1 === 'first',  `msg1: ${d1}`);
  assert(d2 === 'second', `msg2: ${d2}`);
  assert(d3 === 'third',  `msg3: ${d3}`);
});

// ── Test 4: Two senders in same group ────────────────────────────────────────
await test('Both Alice and Bob can send in same group', async () => {
  const alice   = new CryptoSessionManager('alice');
  const bob     = new CryptoSessionManager('bob');
  const charlie = new CryptoSessionManager('charlie');
  await alice.initialize();
  await bob.initialize();
  await charlie.initialize();

  // Both Alice and Bob create their own sender key chains
  alice.createGroupSession('room-4', ['bob', 'charlie']);
  bob.createGroupSession('room-4', ['alice', 'charlie']);

  const aliceDist = alice.getSenderKeyDistribution('room-4');
  const bobDist   = bob.getSenderKeyDistribution('room-4');

  // Charlie installs both
  charlie.installSenderKey('room-4', 'alice', aliceDist.chainKey, aliceDist.generation);
  charlie.installSenderKey('room-4', 'bob',   bobDist.chainKey,   bobDist.generation);

  const { ciphertext: ac, groupHeader: ah } = alice.encryptForGroup('room-4', 'from alice');
  const { ciphertext: bc, groupHeader: bh } = bob.encryptForGroup('room-4', 'from bob');

  const da = charlie.decryptFromGroup('room-4', 'alice', ac, ah);
  const db = charlie.decryptFromGroup('room-4', 'bob',   bc, bh);

  assert(da === 'from alice', `alice msg: ${da}`);
  assert(db === 'from bob',   `bob msg: ${db}`);
});

// ── Test 5: removeGroupMember ratchets sender key ────────────────────────────
await test('After removeGroupMember, old sender key cannot decrypt new messages', async () => {
  const alice = new CryptoSessionManager('alice');
  const bob   = new CryptoSessionManager('bob');
  await alice.initialize();
  await bob.initialize();

  alice.createGroupSession('room-5', ['bob']);
  const dist = alice.getSenderKeyDistribution('room-5');
  bob.installSenderKey('room-5', 'alice', dist.chainKey, dist.generation);

  // Bob can decrypt before removal
  const { ciphertext: c1, groupHeader: h1 } = alice.encryptForGroup('room-5', 'before removal');
  const d1 = bob.decryptFromGroup('room-5', 'alice', c1, h1);
  assert(d1 === 'before removal', `pre-removal: ${d1}`);

  // Alice removes Bob and ratchets
  alice.removeGroupMember('room-5', 'bob');

  // Alice sends new message with new generation
  const { ciphertext: c2, groupHeader: h2 } = alice.encryptForGroup('room-5', 'after removal');

  // Bob tries to decrypt — should fail (generation mismatch)
  let threw = false;
  try {
    bob.decryptFromGroup('room-5', 'alice', c2, h2);
  } catch {
    threw = true;
  }
  assert(threw, 'Expected decryption to fail after member removal');
});

// ── Test 6: getGroupMembers ───────────────────────────────────────────────────
await test('getGroupMembers returns correct member list', async () => {
  const alice = new CryptoSessionManager('alice');
  await alice.initialize();

  alice.createGroupSession('room-6', ['bob', 'charlie', 'dave']);
  const members = alice.getGroupMembers('room-6');
  assert(members.includes('bob'),     'bob missing');
  assert(members.includes('charlie'), 'charlie missing');
  assert(members.includes('dave'),    'dave missing');
  assert(members.length === 3, `expected 3 members, got ${members.length}`);
});

console.log('\nAll group chat tests passed.\n');
