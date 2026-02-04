import { createApp } from '@stvor/sdk';

async function happyPath() {
  const app = await createApp({ appToken: 'stvor_valid_key', relayUrl: 'ws://localhost:3002' });
  const alice = await app.connect('alice');
  const bob = await app.connect('bob');
  let gotMessage = false;
  bob.onMessage((from, msg) => {
    if (from === 'alice' && msg === 'hello') {
      gotMessage = true;
      console.log('✅ Happy path: сообщение доставлено');
    }
  });
  await alice.send('bob', 'hello');
  setTimeout(() => {
    if (!gotMessage) {
      console.error('❌ Сообщение не доставлено');
    }
  }, 1000);
}

happyPath();
