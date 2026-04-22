/**
 * Universal Data API for STVOR SDK
 * 
 * Supports all data types with automatic encoding/decoding:
 * - Strings, Numbers, Booleans
 * - Objects, Arrays, JSON
 * - Binary data (Buffers, Uint8Array)
 * - Dates, Maps, Sets
 * - Custom serializable objects
 * - Files and Blobs (via Buffer)
 * 
 * Automatically handles type preservation and reconstruction
 */

export type StvorData =
  | string
  | number
  | boolean
  | null
  | Buffer
  | Uint8Array
  | object
  | Date
  | Map<string, any>
  | Set<any>
  | Array<any>;

export interface EncodedData {
  type: string;
  data: Buffer;
}

export interface DecodedData {
  type: string;
  value: StvorData;
}

/**
 * Comprehensive universal data encoder
 * Preserves type information for automatic reconstruction
 */
export class UniversalDataCodec {
  /**
   * Encode any data type to Buffer with type marker
   */
  static encode(data: StvorData): Buffer {
    try {
      // String
      if (typeof data === 'string') {
        const encoded = Buffer.from(data, 'utf8');
        const typeMarker = Buffer.from([0x01]); // 1 = string
        return Buffer.concat([typeMarker, encoded]);
      }

      // Number
      if (typeof data === 'number') {
        const numBuffer = Buffer.allocUnsafe(8);
        numBuffer.writeDoubleBE(data, 0);
        const typeMarker = Buffer.from([0x02]); // 2 = number
        return Buffer.concat([typeMarker, numBuffer]);
      }

      // Boolean
      if (typeof data === 'boolean') {
        const boolBuffer = Buffer.from([data ? 1 : 0]);
        const typeMarker = Buffer.from([0x03]); // 3 = boolean
        return Buffer.concat([typeMarker, boolBuffer]);
      }

      // Null
      if (data === null) {
        return Buffer.from([0x04]); // 4 = null
      }

      // Buffer/Uint8Array (binary)
      if (Buffer.isBuffer(data) || data instanceof Uint8Array) {
        const buffer = Buffer.from(data);
        const typeMarker = Buffer.from([0x05]); // 5 = binary
        const lengthBuffer = Buffer.allocUnsafe(4);
        lengthBuffer.writeUInt32BE(buffer.length, 0);
        return Buffer.concat([typeMarker, lengthBuffer, buffer]);
      }

      // Date
      if (data instanceof Date) {
        const timeBuffer = Buffer.allocUnsafe(8);
        timeBuffer.writeBigInt64BE(BigInt(data.getTime()), 0);
        const typeMarker = Buffer.from([0x06]); // 6 = date
        return Buffer.concat([typeMarker, timeBuffer]);
      }

      // Map
      if (data instanceof Map) {
        const json = JSON.stringify(
          Array.from(data.entries()),
        );
        const encoded = Buffer.from(json, 'utf8');
        const typeMarker = Buffer.from([0x07]); // 7 = map
        return Buffer.concat([typeMarker, encoded]);
      }

      // Set
      if (data instanceof Set) {
        const json = JSON.stringify(Array.from(data));
        const encoded = Buffer.from(json, 'utf8');
        const typeMarker = Buffer.from([0x08]); // 8 = set
        return Buffer.concat([typeMarker, encoded]);
      }

      // Array or Object (JSON)
      if (typeof data === 'object') {
        const json = JSON.stringify(data);
        const encoded = Buffer.from(json, 'utf8');
        
        // Distinguish between array and object
        if (Array.isArray(data)) {
          const typeMarker = Buffer.from([0x09]); // 9 = array
          return Buffer.concat([typeMarker, encoded]);
        } else {
          const typeMarker = Buffer.from([0x0a]); // 10 = object
          return Buffer.concat([typeMarker, encoded]);
        }
      }

      // Unknown type, treat as JSON
      const json = JSON.stringify(data);
      const encoded = Buffer.from(json, 'utf8');
      const typeMarker = Buffer.from([0x0b]); // 11 = unknown/json
      return Buffer.concat([typeMarker, encoded]);
    } catch (error) {
      throw new Error(`Failed to encode data: ${error}`);
    }
  }

  /**
   * Decode Buffer back to original data type
   */
  static decode(buffer: Buffer): StvorData {
    try {
      if (buffer.length === 0) {
        throw new Error('Empty buffer');
      }

      const typeMarker = buffer[0];
      const data = buffer.slice(1);

      switch (typeMarker) {
        case 0x01: // String
          return data.toString('utf8');

        case 0x02: // Number
          if (data.length < 8) throw new Error('Invalid number buffer');
          return data.readDoubleBE(0);

        case 0x03: // Boolean
          if (data.length < 1) throw new Error('Invalid boolean buffer');
          return data[0] === 1;

        case 0x04: // Null
          return null;

        case 0x05: // Binary
          if (data.length < 4) throw new Error('Invalid binary buffer');
          const length = data.readUInt32BE(0);
          return data.slice(4, 4 + length);

        case 0x06: // Date
          if (data.length < 8) throw new Error('Invalid date buffer');
          const timestamp = Number(data.readBigInt64BE(0));
          return new Date(timestamp);

        case 0x07: // Map
          const mapJson = data.toString('utf8');
          const mapEntries = JSON.parse(mapJson);
          return new Map(mapEntries);

        case 0x08: // Set
          const setText = data.toString('utf8');
          const setValues = JSON.parse(setText);
          return new Set(setValues);

        case 0x09: // Array
          const arrayJson = data.toString('utf8');
          return JSON.parse(arrayJson);

        case 0x0a: // Object
          const objJson = data.toString('utf8');
          return JSON.parse(objJson);

        case 0x0b: // Unknown/JSON
          const unknownJson = data.toString('utf8');
          return JSON.parse(unknownJson);

        default:
          throw new Error(`Unknown type marker: 0x${typeMarker.toString(16)}`);
      }
    } catch (error) {
      throw new Error(`Failed to decode data: ${error}`);
    }
  }

  /**
   * Encode data to base64url for safe transmission
   */
  static encodeToBase64Url(data: StvorData): string {
    const buffer = this.encode(data);
    return buffer.toString('base64url');
  }

  /**
   * Decode from base64url
   */
  static decodeFromBase64Url(encoded: string): StvorData {
    const buffer = Buffer.from(encoded, 'base64url');
    return this.decode(buffer);
  }

  /**
   * Get data type without decoding
   */
  static getType(buffer: Buffer): string {
    if (buffer.length === 0) return 'unknown';

    const typeMarker = buffer[0];
    const typeNames: Record<number, string> = {
      0x01: 'string',
      0x02: 'number',
      0x03: 'boolean',
      0x04: 'null',
      0x05: 'binary',
      0x06: 'date',
      0x07: 'map',
      0x08: 'set',
      0x09: 'array',
      0x0a: 'object',
      0x0b: 'json',
    };

    return typeNames[typeMarker] ?? 'unknown';
  }

  /**
   * Check if data is binary
   */
  static isBinary(data: StvorData): boolean {
    return Buffer.isBuffer(data) || data instanceof Uint8Array;
  }

  /**
   * Check if data is serializable
   */
  static isSerializable(data: any): boolean {
    try {
      this.encode(data);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Deep clone with type preservation
   */
  static clone(data: StvorData): StvorData {
    const encoded = this.encode(data);
    return this.decode(encoded);
  }

  /**
   * Convert to JSON-safe format
   */
  static toJSON(data: StvorData): any {
    if (data === null) return null;
    if (data === undefined) return undefined;
    if (typeof data === 'string') return data;
    if (typeof data === 'number') return data;
    if (typeof data === 'boolean') return data;
    if (data instanceof Date) return data.toISOString();
    if (Buffer.isBuffer(data)) return data.toString('base64');
    if (data instanceof Uint8Array) return Buffer.from(data).toString('base64');
    if (data instanceof Map) return Object.fromEntries(data);
    if (data instanceof Set) return Array.from(data);
    if (Array.isArray(data)) return data.map((item) => this.toJSON(item));
    if (typeof data === 'object') {
      const result: any = {};
      for (const [key, value] of Object.entries(data)) {
        result[key] = this.toJSON(value);
      }
      return result;
    }
    return data;
  }
}

/**
 * Helper function for quick encoding
 */
export function encodeData(data: StvorData): Buffer {
  return UniversalDataCodec.encode(data);
}

/**
 * Helper function for quick decoding
 */
export function decodeData(buffer: Buffer): StvorData {
  return UniversalDataCodec.decode(buffer);
}

/**
 * Helper for base64url encoding
 */
export function encodeToBase64Url(data: StvorData): string {
  return UniversalDataCodec.encodeToBase64Url(data);
}

/**
 * Helper for base64url decoding
 */
export function decodeFromBase64Url(encoded: string): StvorData {
  return UniversalDataCodec.decodeFromBase64Url(encoded);
}
