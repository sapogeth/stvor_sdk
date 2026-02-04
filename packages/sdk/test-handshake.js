import { createApp } from '@stvor/sdk';

async function testInvalidKey() {
  try {
    const app = await createApp({ appToken: 'wrong_key', relayUrl: 'ws://localhost:3002' });
    await app.connect('alice');
    console.error('❌ ОШИБКА: connect() не выбросил StvorError для неверного ключа');
  } catch (e) {
    if (e.code === 'INVALID_API_KEY') {
      console.log('✅ INVALID_API_KEY: ошибка корректно проброшена');
    } else {
      console.error('❌ Неожиданная ошибка:', e);
    }
  }
}

async function testValidKey() {
  try {
    const app = await createApp({ appToken: 'stvor_valid', relayUrl: 'ws://localhost:3002' });
    const alice = await app.connect('alice');
    if (alice.relay.isAuthenticated && alice.relay.isAuthenticated()) {
      console.log('✅ Валидный ключ: handshake ok, isAuthenticated() === true');
    } else {
      console.error('❌ isAuthenticated() !== true');
    }
  } catch (e) {
    console.error('❌ Ошибка при валидном ключе:', e);
  }
}

async function testRelayUnavailable() {
  try {
    const app = await createApp({ appToken: 'stvor_valid', relayUrl: 'ws://localhost:3999' });
    await app.connect('alice');
    console.error('❌ ОШИБКА: connect() не выбросил ошибку при недоступном relay');
  } catch (e) {
    if (e.code === 'RELAY_UNAVAILABLE') {
      console.log('✅ RELAY_UNAVAILABLE: ошибка корректно проброшена');
    } else {
      console.error('❌ Неожиданная ошибка:', e);
    }
  }
}

async function testHappyPath() {
  const app = await createApp({ appToken: 'stvor_valid', relayUrl: 'ws://localhost:3002' });
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

(async () => {
  await testInvalidKey();
  await testValidKey();
  await testRelayUnavailable();
  await testHappyPath();
})();
