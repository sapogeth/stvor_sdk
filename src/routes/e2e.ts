// import { FastifyInstance } from 'fastify';
import { webcrypto, randomBytes } from 'crypto';
import type { FastifyInstance } from 'fastify';
type NodeCryptoKey = typeof webcrypto extends { subtle: infer S } ? S extends { generateKey: any } ? Parameters<S['generateKey']>[2] extends Array<infer U> ? U : never : never : never;

type JWK = {
  kty: string;
  crv: string;
  x: string;
  y: string;
  [key: string]: any;
};

// New format for ratchet-based keys
type SerializedPublicKeys = {
  identityKey: string;
  signedPreKey: string;
  signedPreKeySignature: string;
  oneTimePreKey: string;
};

type UserKeys = {
  publicKey?: JWK; // Legacy format
  publicKeys?: SerializedPublicKeys; // New ratchet format
  privateKey?: webcrypto.CryptoKey;
};

const users = new Map<string, UserKeys>();
const messages = new Map<string, Array<{ 
  from: string; 
  ciphertext: string; 
  nonce?: string; // Legacy
  header?: { publicKey: string; nonce: string }; // New ratchet format
}>>();

let botIdentity: { publicKey: JWK; privateKey: webcrypto.CryptoKey } | undefined;

async function generateBotIdentity() {
  const keyPair = await webcrypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );
  const pubJwk = await webcrypto.subtle.exportKey('jwk', keyPair.publicKey);
  botIdentity = {
    publicKey: pubJwk as JWK,
    privateKey: keyPair.privateKey,
  };
  users.set('bot', { publicKey: pubJwk as JWK, privateKey: keyPair.privateKey });
}

// Error response factory
function errorResponse(reply: any, error: string, message: string) {
  return reply.status(400).send({ error, message });
}

export default async function e2eRoutes(app: FastifyInstance) {
  if (!users.has('bot')) await generateBotIdentity();

  // Support both legacy (publicKey) and new (publicKeys) format
  app.post('/register', async (req, reply) => {
    const body = req.body as any;
    const { user_id, publicKey, publicKeys } = body;

    if (!user_id || typeof user_id !== 'string') {
      return errorResponse(reply, 'INVALID_INPUT', 'user_id (string) required');
    }

    // New ratchet format
    if (publicKeys) {
      if (
        typeof publicKeys.identityKey !== 'string' ||
        typeof publicKeys.signedPreKey !== 'string' ||
        typeof publicKeys.signedPreKeySignature !== 'string' ||
        typeof publicKeys.oneTimePreKey !== 'string'
      ) {
        return errorResponse(reply, 'INVALID_INPUT', 'Invalid publicKeys format');
      }
      users.set(user_id, { publicKeys });
      return { ok: true };
    }

    // Legacy format (backward compatibility)
    if (publicKey) {
      if (
        typeof publicKey !== 'object' ||
        publicKey.kty !== 'EC' ||
        publicKey.crv !== 'P-256'
      ) {
        return errorResponse(reply, 'INVALID_INPUT', 'Invalid publicKey format (EC P-256 JWK)');
      }
      users.set(user_id, { publicKey });
      return { ok: true };
    }

    return errorResponse(reply, 'INVALID_INPUT', 'Either publicKey or publicKeys required');
  });

  app.get('/public-key/:user_id', async (req, reply) => {
    const { user_id } = req.params as { user_id: string };
    const user = users.get(user_id);
    if (!user) return reply.code(404).send({ error: 'NOT_FOUND', message: `User '${user_id}' not found` });
    
    // Return new format if available, otherwise legacy
    if (user.publicKeys) {
      return { user_id, publicKeys: user.publicKeys };
    }
    
    return { user_id, publicKey: user.publicKey };
  });

  app.post('/send', async (req, reply) => {
    const body = req.body as any;
    const { from, to, ciphertext, nonce, header } = body;
    
    if (
      typeof from !== 'string' ||
      typeof to !== 'string' ||
      typeof ciphertext !== 'string'
    ) {
      return errorResponse(reply, 'INVALID_INPUT', 'Invalid input: from, to, ciphertext (strings) required');
    }

    if (!messages.has(to)) messages.set(to, []);

    // Support both formats
    if (header) {
      // New ratchet format
      messages.get(to)!.push({ from, ciphertext, header });
    } else if (nonce) {
      // Legacy format
      messages.get(to)!.push({ from, ciphertext, nonce });
    } else {
      return errorResponse(reply, 'INVALID_INPUT', 'Either nonce or header required');
    }

    // Demo bot auto-reply (stable identity)
    if (to === 'bot') {
      try {
        const bot = users.get('bot');
        const user = users.get(from);
        if (!bot || !bot.privateKey || !user?.publicKey) return;
        const userPub = await webcrypto.subtle.importKey(
          'jwk',
          user.publicKey,
          { name: 'ECDH', namedCurve: 'P-256' },
          false,
          []
        );
        const sharedKey = await webcrypto.subtle.deriveKey(
          { name: 'ECDH', public: userPub },
          bot.privateKey,
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt']
        );
        const plaintext = new TextEncoder().encode('Hello! This is a demo E2E reply.');
        const iv = randomBytes(12);
        const encrypted = await webcrypto.subtle.encrypt(
          { name: 'AES-GCM', iv },
          sharedKey,
          plaintext
        );
        if (!messages.has(from)) messages.set(from, []);
        messages.get(from)!.push({
          from: 'bot',
          ciphertext: Buffer.from(encrypted).toString('base64'),
          nonce: iv.toString('base64'),
        });
      } catch {}
    }
    return { ok: true };
  });

  app.get('/messages/:user_id', async (req, reply) => {
    const { user_id } = req.params as { user_id: string };
    const msgs = messages.get(user_id) || [];
    messages.set(user_id, []);
    return { messages: msgs };
  });
}
