/**
 * STVOR SDK Live Test (standalone)
 * Uses provided API key from environment
 */

const API_BASE = 'http://localhost:3001';

async function generateKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );
  return {
    publicKey: await crypto.subtle.exportKey('jwk', keyPair.publicKey),
    privateKey: keyPair.privateKey
  };
}

async function deriveSharedKey(privateKey, peerPublicKey) {
  const importedPub = await crypto.subtle.importKey(
    'jwk', peerPublicKey,
    { name: 'ECDH', namedCurve: 'P-256' },
    false, []
  );
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: importedPub },
    privateKey,
    { name: 'AES-GCM', length: 256 },
    false, ['encrypt', 'decrypt']
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
    nonce: Buffer.from(iv).toString('base64')
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

async function register(userId, publicKey, apiKey) {
  const res = await fetch(`${API_BASE}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
    body: JSON.stringify({ user_id: userId, publicKey })
  });
  if (!res.ok) throw new Error(`Register ${userId} failed`);
}

async function getPublicKey(userId, apiKey) {
  const res = await fetch(`${API_BASE}/public-key/${userId}`, {
    headers: { 'Authorization': `Bearer ${apiKey}` }
  });
  if (!res.ok) throw new Error(`Get pubkey ${userId} failed`);
  const data = await res.json();
  return data.publicKey;
}

async function sendMessage(from, to, ciphertext, nonce, apiKey) {
  const res = await fetch(`${API_BASE}/message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
    body: JSON.stringify({ from, to, ciphertext, nonce })
  });
  if (!res.ok) throw new Error('Send failed');
}

async function getMessages(userId, apiKey) {
  const res = await fetch(`${API_BASE}/messages/${userId}`, {
    headers: { 'Authorization': `Bearer ${apiKey}` }
  });
  if (!res.ok) throw new Error('Get messages failed');
  const data = await res.json();
  return data.messages;
}

async function main() {
  const apiKey = process.env.STVOR_API_KEY;
  if (!apiKey) {
    console.log('FAIL: STVOR_API_KEY not set');
    process.exit(1);
  }

  // Create Alice and Bob
  const alice = await generateKeyPair();
  const bob = await generateKeyPair();

  await register('alice', alice.publicKey, apiKey);
  console.log('✓ Alice created');

  await register('bob', bob.publicKey, apiKey);
  console.log('✓ Bob created');

  // Alice sends to Bob
  const sharedKey = await deriveSharedKey(alice.privateKey, bob.publicKey);
  const { ciphertext, nonce } = await encrypt(sharedKey, 'Hello from STVOR!');
  await sendMessage('alice', 'bob', ciphertext, nonce, apiKey);
  console.log('✓ Encrypted message sent');

  // Bob receives and decrypts
  const messages = await getMessages('bob', apiKey);
  if (messages.length === 0) throw new Error('No messages received');
  
  // Bob derives shared key with Alice and decrypts
  const bobSharedKey = await deriveSharedKey(bob.privateKey, alice.publicKey);
  const decrypted = await decrypt(bobSharedKey, messages[0].ciphertext, messages[0].nonce);
  console.log('✓ Decrypted:', decrypted);

  if (decrypted === 'Hello from STVOR!') {
    console.log('\n✓✓✓ PASS ✓✓✓');
  } else {
    console.log('\n✗ FAIL');
    process.exit(1);
  }
}

main().catch(e => {
  console.log('FAIL:', e.message);
  process.exit(1);
});
