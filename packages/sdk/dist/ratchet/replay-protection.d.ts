/**
 * Check if a message is a replay.
 * @param userId - The user ID sending the message.
 * @param nonce - The unique nonce for the message.
 * @returns True if the message is a replay, false otherwise.
 */
export declare function isReplay(userId: string, nonce: string): Promise<boolean>;
/**
 * Reject messages older than the allowed timestamp.
 * @param timestamp - The message timestamp.
 * @returns True if the message is too old, false otherwise.
 */
export declare function isTooOld(timestamp: number): boolean;
/**
 * Validate a message for replay protection.
 * @param userId - The user ID sending the message.
 * @param nonce - The unique nonce for the message.
 * @param timestamp - The message timestamp.
 * @throws Error if the message is a replay or too old.
 */
export declare function validateMessage(userId: string, nonce: string, timestamp: number): Promise<void>;
