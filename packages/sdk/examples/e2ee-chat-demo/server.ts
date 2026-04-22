/**
 * ✅ ИСТИННОЕ E2EE: Socket.io + STVOR SDK
 * 
 * Архитектура:
 * Браузер Alice → encryptMessage() → {ciphertext} → Сервер → Браузер Bob → decryptMessage()
 * 
 * Важно:
 * - Сервер ТОЛЬКО маршрутизирует зашифрованные данные
 * - Сервер не видит plaintext или ключи
 * - Браузеры шифруют/расшифровывают locально
 * - Это НАСТОЯЩЕЕ E2EE
 * 
 * Отличие от неправильного подхода:
 * ❌ Неправильно: Браузер → plaintext → Сервер (SDK) → encrypt/decrypt → plaintext → Браузер
 * ✅ Правильно: Браузер (SDK) → ciphertext → Сервер (слеп) → ciphertext → Браузер (SDK)
 */

import express from 'express';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import path from 'path';

const app = express();
const httpServer = createServer(app);
const io = new SocketIOServer(httpServer, {
  cors: { origin: '*' },
});

// Serve static HTML for browser clients
app.use(express.static('public'));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// In-memory storage for users and undelivered messages
interface User {
  id: string;
  socket: any;
  publicKey: string; // Сервер ХРАНИТ ключи, но не использует их!
}

interface StoredMessage {
  from: string;
  to: string;
  encrypted: {
    version: number;
    senderPub: string;
    nonce: string;
    ciphertext: string;
    tag: string;
  };
  timestamp: string;
  id: string;
}

const users = new Map<string, User>();
const undeliveredMessages = new Map<string, StoredMessage[]>();

// --- SOCKET.IO EVENTS ---

io.on('connection', (socket) => {
  console.log(`🔗 Socket connected: ${socket.id}`);

  /**
   * Событие: Пользователь регистрируется
   * Передаёт: userId, publicKey (для других пользователей)
   * Сервер НЕ использует publicKey для decrypt!
   */
  socket.on('register', (data) => {
    const { userId, publicKey } = data;

    if (!userId || !publicKey) {
      socket.emit('error', { message: 'Missing userId or publicKey' });
      return;
    }

    // Удалить старое соединение того же пользователя
    const existing = users.get(userId);
    if (existing) {
      existing.socket.emit('kicked', { reason: 'New connection from same user' });
      existing.socket.disconnect();
    }

    // Зарегистрировать пользователя
    users.set(userId, { id: userId, socket, publicKey });
    console.log(`👤 User registered: ${userId}`);

    // Уведомить других, что пользователь online
    socket.broadcast.emit('user_online', { userId, publicKey });

    // Отправить список уже online пользователей
    const onlineUsers = Array.from(users.values()).map((u) => ({
      userId: u.id,
      publicKey: u.publicKey,
    }));
    socket.emit('online_users', { users: onlineUsers });

    // Отправить любые сообщения, которые ждали этого пользователя
    const pending = undeliveredMessages.get(userId) || [];
    if (pending.length > 0) {
      console.log(`📬 Delivering ${pending.length} pending messages to ${userId}`);
      for (const msg of pending) {
        socket.emit('message', msg);
      }
      undeliveredMessages.delete(userId);
    }
  });

  /**
   * Событие: Отправка зашифрованного сообщения
   * Передаёт: to, from, encrypted (зашифровано браузером Alice!)
   * 
   * Сервер:
   * 1. Проверяет, что 'to' существует или offline
   * 2. Отправляет зашифрованное сообщение как есть
   * 3. НЕ расшифровывает, НЕ смотрит plaintext
   */
  socket.on('message', (data) => {
    const { to, from, encrypted } = data;

    if (!to || !from || !encrypted) {
      socket.emit('error', { message: 'Missing to, from, or encrypted' });
      return;
    }

    // Валидация: шифрованное сообщение должно иметь правильную структуру
    if (
      !encrypted.version ||
      !encrypted.senderPub ||
      !encrypted.nonce ||
      !encrypted.ciphertext ||
      !encrypted.tag
    ) {
      socket.emit('error', { message: 'Invalid encrypted message structure' });
      return;
    }

    const messageId = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const storedMsg: StoredMessage = {
      from,
      to,
      encrypted,
      timestamp: new Date().toISOString(),
      id: messageId,
    };

    // Попытка доставить сообщение
    const recipient = users.get(to);
    if (recipient) {
      // Пользователь online - отправить сразу
      recipient.socket.emit('message', storedMsg);
      console.log(`✉️ Message ${from} → ${to}: ${messageId}`);
    } else {
      // Пользователь offline - сохранить для позже
      if (!undeliveredMessages.has(to)) {
        undeliveredMessages.set(to, []);
      }
      undeliveredMessages.get(to)!.push(storedMsg);
      console.log(`📮 Message stored for ${to} (offline)`);
    }

    // Отправить подтверждение отправителю
    socket.emit('message_sent', { messageId, to });
  });

  /**
   * Событие: Подтверждение получения сообщения
   * Получатель может подтвердить, что расшифровал сообщение
   */
  socket.on('message_ack', (data) => {
    const { messageId, from } = data;
    console.log(`✅ Message ACK: ${messageId} from ${from}`);

    const sender = users.get(from);
    if (sender) {
      sender.socket.emit('message_acked', { messageId });
    }
  });

  /**
   * Событие: Отключение
   */
  socket.on('disconnect', () => {
    // Найти пользователя и удалить
    for (const [userId, user] of users.entries()) {
      if (user.socket.id === socket.id) {
        users.delete(userId);
        console.log(`👋 User offline: ${userId}`);
        io.emit('user_offline', { userId });
        break;
      }
    }
  });
});

// --- SERVER ---

const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
  console.log(`\n✅ E2EE Socket.io server running on http://localhost:${PORT}`);
  console.log(`🔐 Architecture: Browser(SDK) → {ciphertext} → Server(blind) → Browser(SDK)`);
  console.log(`📖 Open browser to see the chat demo\n`);
});

export { io, users };

/**
 * ============================================================
 * ВАЖНЫЕ ЗАМЕЧАНИЯ ПО АРХИТЕКТУРЕ
 * ============================================================
 *
 * ✅ ЧТО СЕРВЕР ДЕЛАЕТ:
 * - Регистрирует пользователей
 * - Хранит publicKey (нужны для других пользователей)
 * - Маршрутизирует зашифрованные сообщения
 * - Хранит offline messages (зашифрованные!)
 * - Не может прочитать ни одно сообщение
 *
 * ❌ ЧТО СЕРВЕР НЕ ДЕЛАЕТ:
 * - Не использует publicKey для шифрования/расшифровки
 * - Не видит plaintext
 * - Не имеет доступа к приватным ключам
 * - Не создаёт SDK экземпляры
 * - Не сохраняет plaintext в логи
 *
 * 🔐 БЕЗОПАСНОСТЬ:
 * - Если сервер скомпрометирован:
 *   ✅ Не может декриптить сообщения
 *   ✅ Не может читать истории
 *   ✅ Не может выдавать себя за других пользователей (нет приватных ключей)
 *   ❌ Может видеть кто с кем общается (metadata)
 *   ❌ Может удалять сообщения
 *   ❌ Может разорвать соединение
 *
 * 📊 МАСШТАБИРУЕМОСТЬ:
 * - На миллион пользователей сервер не замедлится (нет crypto)
 * - Можно кластеризировать redis для offline messages
 * - Нет нагрузки на CPU (весь crypto на браузерах)
 *
 * 🎯 ВСЕ СООБЩЕНИЯ ДОСТАВЛЯЮТСЯ ЗАШИФРОВАННЫМИ И ОСТАЮТСЯ ЗАШИФРОВАННЫМИ
 */
