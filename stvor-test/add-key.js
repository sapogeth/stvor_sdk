/**
 * Add API key to server storage via special request
 */

async function main() {
  const apiKey = process.env.STVOR_API_KEY;
  if (!apiKey) {
    console.log('FAIL: STVOR_API_KEY not set');
    process.exit(1);
  }

  const res = await fetch('http://localhost:3001/bootstrap', { method: 'POST' });
  const { project_id, api_key } = await res.json();
  
  console.log('New key created:', api_key);
  console.log('Project:', project_id);
}

main();
