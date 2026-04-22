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
export function encodeData(data) {
    // Determine type and encode accordingly
    if (typeof data === 'string') {
        // String: UTF-8 encode with type marker
        const payload = Buffer.from(data, 'utf-8');
        return Buffer.concat([
            Buffer.from([0x01]), // Type marker: string
            payload,
        ]);
    }
    if (typeof data === 'number') {
        // Number: IEEE 754 double precision (8 bytes)
        const buf = Buffer.alloc(9);
        buf[0] = 0x02; // Type marker: number
        buf.writeDoubleBE(data, 1);
        return buf;
    }
    if (typeof data === 'boolean') {
        // Boolean: 1 byte (0x01 = true, 0x00 = false)
        const buf = Buffer.alloc(2);
        buf[0] = 0x03; // Type marker: boolean
        buf[1] = data ? 0x01 : 0x00;
        return buf;
    }
    if (data === null) {
        // Null: just type marker
        return Buffer.from([0x04]); // Type marker: null
    }
    if (Buffer.isBuffer(data)) {
        // Binary: directly
        return Buffer.concat([
            Buffer.from([0x05]), // Type marker: binary
            data,
        ]);
    }
    if (data instanceof Uint8Array) {
        const buf = Buffer.from(data);
        return Buffer.concat([Buffer.from([0x05]), buf]);
    }
    if (data instanceof Date) {
        const payload = Buffer.from(data.toISOString(), 'utf-8');
        return Buffer.concat([Buffer.from([0x07]), payload]);
    }
    if (data instanceof Set) {
        const payload = Buffer.from(JSON.stringify(Array.from(data)), 'utf-8');
        return Buffer.concat([Buffer.from([0x08]), payload]);
    }
    if (data instanceof Map) {
        const payload = Buffer.from(JSON.stringify(Array.from(data.entries())), 'utf-8');
        return Buffer.concat([Buffer.from([0x09]), payload]);
    }
    // Default: JSON
    try {
        const json = JSON.stringify(data);
        const payload = Buffer.from(json, 'utf-8');
        return Buffer.concat([
            Buffer.from([0x06]), // Type marker: json
            payload,
        ]);
    }
    catch (e) {
        throw new Error(`Cannot encode data: ${String(e)}`);
    }
}
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
export function decodeData(buffer) {
    if (buffer.length === 0) {
        throw new Error('Cannot decode empty buffer');
    }
    const typeMarker = buffer[0];
    switch (typeMarker) {
        case 0x01: {
            // String
            return buffer.subarray(1).toString('utf-8');
        }
        case 0x02: {
            // Number
            if (buffer.length !== 9) {
                throw new Error('Invalid number encoding: expected 9 bytes');
            }
            return buffer.readDoubleBE(1);
        }
        case 0x03: {
            // Boolean
            if (buffer.length !== 2) {
                throw new Error('Invalid boolean encoding: expected 2 bytes');
            }
            return buffer[1] === 0x01;
        }
        case 0x04: {
            // Null
            return null;
        }
        case 0x05: {
            // Binary
            return Buffer.from(buffer.subarray(1));
        }
        case 0x06: {
            const json = buffer.subarray(1).toString('utf-8');
            try {
                return JSON.parse(json);
            }
            catch (e) {
                throw new Error(`Invalid JSON in encoded data: ${String(e)}`);
            }
        }
        case 0x07: {
            // Date
            const iso = buffer.subarray(1).toString('utf-8');
            const d = new Date(iso);
            if (isNaN(d.getTime()))
                throw new Error(`Invalid Date: ${iso}`);
            return d;
        }
        case 0x08: {
            // Set
            const arr = JSON.parse(buffer.subarray(1).toString('utf-8'));
            return new Set(arr);
        }
        case 0x09: {
            // Map
            const entries = JSON.parse(buffer.subarray(1).toString('utf-8'));
            return new Map(entries);
        }
        default: {
            throw new Error(`Unknown type marker: 0x${typeMarker.toString(16)}`);
        }
    }
}
/**
 * Encode data to base64url for transmission
 *
 * @param data - Any data type
 * @returns base64url string ready for API transport
 */
export function encodeToBase64Url(data) {
    const buffer = encodeData(data);
    return buffer.toString('base64url');
}
/**
 * Decode base64url back to original data
 *
 * @param encoded - base64url string
 * @returns Original data with correct type
 */
export function decodeFromBase64Url(encoded) {
    try {
        const buffer = Buffer.from(encoded, 'base64url');
        return decodeData(buffer);
    }
    catch (e) {
        throw new Error(`Cannot decode base64url: ${String(e)}`);
    }
}
/**
 * Safe encoding that never throws - returns best-effort encoding
 *
 * @param data - Any data type
 * @returns Buffer (worst case: string representation)
 */
export function encodeDataSafe(data) {
    try {
        return encodeData(data);
    }
    catch {
        // Fallback: encode as string
        const str = String(data);
        return encodeData(str);
    }
}
/**
 * Safe decoding that never throws - returns best-effort result
 *
 * @param buffer - Buffer to decode
 * @returns Decoded data or string representation
 */
export function decodeDataSafe(buffer) {
    try {
        return decodeData(buffer);
    }
    catch {
        // Fallback: return as utf-8 string
        try {
            return buffer.toString('utf-8');
        }
        catch {
            // Last resort: return as hex string
            return `0x${buffer.toString('hex')}`;
        }
    }
}
/**
 * Get the type of encoded data without fully decoding
 *
 * @param buffer - Encoded buffer
 * @returns Type string
 */
export function getEncodedDataType(buffer) {
    if (buffer.length === 0)
        return 'unknown';
    const typeMarker = buffer[0];
    const typeMap = {
        0x01: 'string',
        0x02: 'number',
        0x03: 'boolean',
        0x04: 'null',
        0x05: 'binary',
        0x06: 'json',
    };
    return typeMap[typeMarker] || 'unknown';
}
/**
 * Calculate overhead of encoding
 *
 * @param data - Data to encode
 * @returns Number of bytes added by encoding
 */
export function calculateEncodingOverhead(data) {
    const encoded = encodeData(data);
    if (typeof data === 'string') {
        return Buffer.byteLength(data, 'utf-8') - encoded.length + 1; // +1 for type marker
    }
    return 1; // Minimum: just type marker
}
