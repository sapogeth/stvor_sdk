import { createClient } from 'redis';

// Redis client setup
const redis = createClient({
  url: process.env.REDIS_URL, // Ensure REDIS_URL is set in the environment
});
redis.connect();

const REPLAY_CACHE_PREFIX = 'replay:';
const MESSAGE_EXPIRY_SECONDS = 300; // 5 minutes

/**
 * Check if a message is a replay.
 * @param userId - The user ID sending the message.
 * @param nonce - The unique nonce for the message.
 * @returns True if the message is a replay, false otherwise.
 */
export async function isReplay(userId: string, nonce: string): Promise<boolean> {
  const key = `${REPLAY_CACHE_PREFIX}${userId}:${nonce}`;
  const exists = await redis.exists(key);
  if (exists) {
    return true; // Replay detected
  }

  // Store the nonce with an expiry
  await redis.set(key, '1', {
    EX: MESSAGE_EXPIRY_SECONDS,
  });
  return false;
}

/**
 * Reject messages older than the allowed timestamp.
 * @param timestamp - The message timestamp.
 * @returns True if the message is too old, false otherwise.
 */
export function isTooOld(timestamp: number): boolean {
  const now = Math.floor(Date.now() / 1000); // Current time in seconds
  return now - timestamp > MESSAGE_EXPIRY_SECONDS;
}

/**
 * Validate a message for replay protection.
 * @param userId - The user ID sending the message.
 * @param nonce - The unique nonce for the message.
 * @param timestamp - The message timestamp.
 * @throws Error if the message is a replay or too old.
 */
export async function validateMessage(userId: string, nonce: string, timestamp: number): Promise<void> {
  if (isTooOld(timestamp)) {
    throw new Error('Message rejected: too old');
  }

  if (await isReplay(userId, nonce)) {
    throw new Error('Message rejected: replay detected');
  }
}