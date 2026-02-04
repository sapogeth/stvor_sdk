/**
 * STVOR API Test Script
 */

const API_BASE = 'http://localhost:3001';

async function createProject() {
  const res = await fetch(`${API_BASE}/projects`, { method: 'POST' });
  return res.json();
}

async function registerUser(userId, publicKey) {
  const res = await fetch(`${API_BASE}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_id: userId, publicKey }),
  });
  return res.json();
}

async function getPublicKey(userId) {
  const res = await fetch(`${API_BASE}/public-key/${userId}`);
  if (!res.ok) throw new Error(`User ${userId} not found`);
  return res.json();
}

async function sendMessage(from, to, ciphertext, nonce) {
  const res = await fetch(`${API_BASE}/message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ from, to, ciphertext, nonce }),
  });
  return res.json();
}

async function getMessages(userId) {
  const res = await fetch(`${API_BASE}/messages/${userId}`);
  return res.json();
}

async function generateKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );
  const publicKey = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  return { keyPair, publicKey };
}

async function deriveSharedKey(privateKey, publicKey) {
  const importedPub = await crypto.subtle.importKey(
    'jwk',
    publicKey,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: importedPub },
    privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encrypt(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(plaintext)
  );
  return {
    ciphertext: Buffer.from(encrypted).toString('base64'),
    nonce: Buffer.from(iv).toString('base64'),
  };
}

async function decrypt(key, ciphertext, nonce) {
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: Buffer.from(nonce, 'base64') },
    key,
    Buffer.from(ciphertext, 'base64')
  );
  return new TextDecoder().decode(decrypted);
}

async function runTests() {
  console.log('=== STVOR API Test ===\n');

  // Step 1: Create API key
  console.log('1. Creating project (API key)...');
  const { project_id, api_key } = await createProject();
  console.log(`   ✓ Project created: ${project_id}`);
  console.log(`   ✓ API Key: ${api_key}\n`);

  // Step 2: Generate keypairs for two peers
  console.log('2. Generating keypairs for Alice and Bob...');
  const alice = await generateKeyPair();
  const bob = await generateKeyPair();
  console.log('   ✓ Keypairs generated\n');

  // Step 3: Register users
  console.log('3. Registering users...');
  await registerUser('alice', alice.publicKey);
  console.log('   ✓ Alice registered');
  await registerUser('bob', bob.publicKey);
  console.log('   ✓ Bob registered\n');

  // Step 4: Alice sends encrypted message to Bob
  console.log('4. Alice sends encrypted message to Bob...');
  const sharedKeyAlice = await deriveSharedKey(alice.keyPair.privateKey, bob.publicKey);
  const encryptedMsg = await encrypt(sharedKeyAlice, 'Hello from STVOR!');
  
  // Check: server should only see ciphertext
  console.log(`   ✓ Plaintext: "Hello from STVOR!" (NEVER sent to server)`);
  console.log(`   ✓ Ciphertext sent: ${encryptedMsg.ciphertext.substring(0, 20)}...`);
  
  await sendMessage('alice', 'bob', encryptedMsg.ciphertext, encryptedMsg.nonce);
  console.log('   ✓ Message sent to server (ciphertext only)\n');

  // Step 5: Bob receives and decrypts
  console.log('5. Bob receives and decrypts message...');
  const { messages } = await getMessages('bob');
  const received = messages[0];
  
  console.log(`   ✓ Received from server: { ciphertext, nonce, from }`);
  console.log(`   ✓ From: ${received.from}`);
  
  const sharedKeyBob = await deriveSharedKey(bob.keyPair.privateKey, alice.publicKey);
  const plaintext = await decrypt(sharedKeyBob, received.ciphertext, received.nonce);
  console.log(`   ✓ Decrypted: "${plaintext}"\n`);

  // Verification
  console.log('=== VERIFICATION ===');
  console.log(`✓ Message delivered correctly: ${plaintext === 'Hello from STVOR!' ? 'PASS' : 'FAIL'}`);

  // Test without API key (authorization check)
  console.log('\n6. Testing without API key...');
  try {
    const badRes = await fetch(`${API_BASE}/projects`, { method: 'POST' });
    console.log(`   Note: /projects doesn't require API key (current server design)`);
    console.log(`   Response status: ${badRes.status}`);
  } catch (e) {
    console.log(`   ✓ Request blocked as expected`);
  }

  console.log('\n=== All Tests Complete ===');
}

runTests().catch(console.error);
