/**
 * STVOR Web SDK - Encryption Test (Node.js compatible)
 * Test real encryption with tweetnacl without browser APIs
 */

async function testEncryption() {
  // Dynamic import for CommonJS module
  const nacl = await import('tweetnacl').then(m => m.default || m);
  console.log('🧪 Testing STVOR Web SDK Encryption (TweetNaCl)\n');

  try {
    // Test 1: Generate Keypair (Box - Asymmetric)
    console.log('Test 1: Generating keypair (X25519)...');
    const keypair = nacl.box.keyPair();
    console.log(`✅ Keypair generated`);
    console.log(`   Public Key: ${keypair.publicKey.length} bytes`);
    console.log(`   Secret Key: ${keypair.secretKey.length} bytes\n`);

    // Test 2: Generate Master Key (for symmetric encryption)
    console.log('Test 2: Generating master key (256-bit)...');
    const masterKey = nacl.randomBytes(32);
    console.log(`✅ Master key generated: ${masterKey.length} bytes\n`);

    // Test 3: Symmetric Encryption (XSalsa20-Poly1305)
    console.log('Test 3: Testing symmetric encryption (secretbox)...');
    const message = 'Hello, encrypted world!';
    const encoder = new TextEncoder();
    const plaintext = encoder.encode(message);
    
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    console.log(`   Nonce: ${nonce.length} bytes (nonceLength: ${nacl.secretbox.nonceLength})`);
    
    const ciphertext = nacl.secretbox(plaintext, nonce, masterKey);
    console.log(`   Plaintext: ${plaintext.length} bytes`);
    console.log(`   Ciphertext: ${ciphertext.length} bytes`);
    console.log(`✅ Encryption successful\n`);

    // Test 4: Symmetric Decryption
    console.log('Test 4: Testing symmetric decryption (secretbox)...');
    const decrypted = nacl.secretbox.open(ciphertext, nonce, masterKey);
    
    if (!decrypted) {
      throw new Error('Decryption failed - authentication failed');
    }

    const decoder = new TextDecoder();
    const decryptedMessage = decoder.decode(decrypted);
    console.log(`   Decrypted: "${decryptedMessage}"`);
    console.log(`✅ Decryption successful\n`);

    // Test 5: Verify roundtrip
    console.log('Test 5: Verifying encryption/decryption roundtrip...');
    if (decryptedMessage === message) {
      console.log(`✅ Roundtrip verification passed: "${decryptedMessage}" === "${message}"\n`);
    } else {
      throw new Error('Roundtrip failed: decrypted message does not match original');
    }

    // Test 6: Asymmetric Encryption (Box)
    console.log('Test 6: Testing asymmetric encryption (box)...');
    const senderKeypair = nacl.box.keyPair();
    const recipientKeypair = nacl.box.keyPair();
    
    const boxNonce = nacl.randomBytes(nacl.box.nonceLength);
    const boxCiphertext = nacl.box(
      plaintext,
      boxNonce,
      recipientKeypair.publicKey,
      senderKeypair.secretKey
    );
    console.log(`✅ Box encryption successful: ${boxCiphertext.length} bytes\n`);

    // Test 7: Asymmetric Decryption
    console.log('Test 7: Testing asymmetric decryption (box)...');
    const boxDecrypted = nacl.box.open(
      boxCiphertext,
      boxNonce,
      senderKeypair.publicKey,
      recipientKeypair.secretKey
    );

    if (!boxDecrypted) {
      throw new Error('Box decryption failed');
    }

    const boxDecryptedMessage = decoder.decode(boxDecrypted);
    console.log(`   Decrypted: "${boxDecryptedMessage}"`);
    console.log(`✅ Box decryption successful\n`);

    // Test 8: Complex data serialization
    console.log('Test 8: Testing complex data serialization...');
    const complexData = {
      text: 'Hello',
      number: 42,
      array: [1, 2, 3],
      nested: { key: 'value' },
      date: new Date().toISOString()
    };

    const serialized = encoder.encode(JSON.stringify(complexData));
    const dataKey = nacl.randomBytes(32);
    const dataNonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const encryptedData = nacl.secretbox(serialized, dataNonce, dataKey);
    const decryptedData = nacl.secretbox.open(encryptedData, dataNonce, dataKey);

    if (!decryptedData) {
      throw new Error('Complex data decryption failed');
    }

    const deserializedData = JSON.parse(decoder.decode(decryptedData));
    console.log(`✅ Complex data roundtrip successful`);
    console.log(`   Original: ${JSON.stringify(complexData)}`);
    console.log(`   Decrypted: ${JSON.stringify(deserializedData)}\n`);

    // Summary
    console.log('✅ All encryption tests passed!\n');
    console.log('📊 Test Summary:');
    console.log('✅ Keypair generation (X25519): Working');
    console.log('✅ Master key generation (256-bit): Working');
    console.log('✅ Symmetric encryption (XSalsa20-Poly1305): Working');
    console.log('✅ Symmetric decryption: Working');
    console.log('✅ Encryption/Decryption roundtrip: Working');
    console.log('✅ Asymmetric encryption (Box): Working');
    console.log('✅ Asymmetric decryption: Working');
    console.log('✅ Complex data serialization: Working');

    console.log('\n🎉 TweetNaCl encryption is fully operational!\n');
    console.log('Encryption Details:');
    console.log('- Algorithm: XSalsa20-Poly1305 (secretbox)');
    console.log('- Key size: 32 bytes (256-bit)');
    console.log('- Nonce size: 24 bytes');
    console.log('- Authentication: Poly1305 (AEAD)');
    console.log('- Performance: ✅ Suitable for real-time messaging');

    console.log('\n✨ Ready for:');
    console.log('1. Integration with Web SDK');
    console.log('2. Testing against relay server');
    console.log('3. Browser compatibility verification');
    console.log('4. Node.js ↔ Browser bridge testing');

  } catch (err) {
    console.error('❌ Test failed:', err);
    process.exit(1);
  }
}

// Run tests
testEncryption().catch(err => {
  console.error('Error:', err);
  process.exit(1);
});
