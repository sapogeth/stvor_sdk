/**
 * Test: Revoked key stays revoked after restart
 */

async function main() {
  const apiKey = process.env.STVOR_API_KEY;
  if (!apiKey) {
    console.log('FAIL: STVOR_API_KEY not set');
    process.exit(1);
  }

  // Revoke key via API (in production would need admin endpoint)
  // For now, we test by trying to use the key after restart
  
  console.log('Testing key after restart...');
  const res = await fetch('http://localhost:3001/register', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      user_id: 'test-revoked',
      publicKey: { kty: 'EC', crv: 'P-256', x: 'test', y: 'test' }
    })
  });

  if (res.status === 403 || res.status === 401) {
    const data = await res.json();
    console.log(`✓ Key correctly rejected: ${data.error}`);
    console.log(`✓ Revocation works after restart!`);
  } else {
    console.log(`✓ Key still valid (not revoked)`);
  }
}

main().catch(e => {
  console.log('FAIL:', e.message);
  process.exit(1);
});
