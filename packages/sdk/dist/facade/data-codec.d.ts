/**
 * STVOR Universal Data Codec
 *
 * Provides seamless support for any data type:
 * - Strings (UTF-8, base64, hex)
 * - Binary (Buffer, Uint8Array)
 * - JSON objects
 * - Files (as buffers)
 * - Numbers, booleans, etc.
 *
 * Automatic serialization/deserialization with type preservation
 * Zero overhead - encryption works directly with encoded binary
 */
export type StvorDataType = 'string' | 'json' | 'binary' | 'number' | 'boolean' | 'null' | 'date' | 'set' | 'map';
export interface StvorEncodedMessage {
    type: StvorDataType;
    data: string;
}
/**
 * Encode any data type to binary for encryption
 *
 * @param data - Any data type
 * @returns Buffer ready for encryption
 *
 * @example
 * const buf1 = encodeData('Hello');                    // String
 * const buf2 = encodeData({ user: 'alice', age: 30 }); // JSON
 * const buf3 = encodeData(Buffer.from([1, 2, 3]));     // Binary
 */
export declare function encodeData(data: unknown): Buffer;
/**
 * Decode binary data back to original type
 *
 * @param buffer - Encoded buffer
 * @returns Original data with correct type
 *
 * @example
 * const str = decodeData(buf1); // Returns string
 * const obj = decodeData(buf2); // Returns object (JSON)
 * const num = decodeData(buf3); // Returns number
 */
export declare function decodeData(buffer: Buffer): unknown;
/**
 * Encode data to base64url for transmission
 *
 * @param data - Any data type
 * @returns base64url string ready for API transport
 */
export declare function encodeToBase64Url(data: unknown): string;
/**
 * Decode base64url back to original data
 *
 * @param encoded - base64url string
 * @returns Original data with correct type
 */
export declare function decodeFromBase64Url(encoded: string): unknown;
/**
 * Safe encoding that never throws - returns best-effort encoding
 *
 * @param data - Any data type
 * @returns Buffer (worst case: string representation)
 */
export declare function encodeDataSafe(data: unknown): Buffer;
/**
 * Safe decoding that never throws - returns best-effort result
 *
 * @param buffer - Buffer to decode
 * @returns Decoded data or string representation
 */
export declare function decodeDataSafe(buffer: Buffer): unknown;
/**
 * Get the type of encoded data without fully decoding
 *
 * @param buffer - Encoded buffer
 * @returns Type string
 */
export declare function getEncodedDataType(buffer: Buffer): StvorDataType | 'unknown';
/**
 * Calculate overhead of encoding
 *
 * @param data - Data to encode
 * @returns Number of bytes added by encoding
 */
export declare function calculateEncodingOverhead(data: unknown): number;
