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
export type StvorData = string | number | boolean | null | Buffer | Uint8Array | object | Date | Map<string, any> | Set<any> | Array<any>;
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
export declare class UniversalDataCodec {
    /**
     * Encode any data type to Buffer with type marker
     */
    static encode(data: StvorData): Buffer;
    /**
     * Decode Buffer back to original data type
     */
    static decode(buffer: Buffer): StvorData;
    /**
     * Encode data to base64url for safe transmission
     */
    static encodeToBase64Url(data: StvorData): string;
    /**
     * Decode from base64url
     */
    static decodeFromBase64Url(encoded: string): StvorData;
    /**
     * Get data type without decoding
     */
    static getType(buffer: Buffer): string;
    /**
     * Check if data is binary
     */
    static isBinary(data: StvorData): boolean;
    /**
     * Check if data is serializable
     */
    static isSerializable(data: any): boolean;
    /**
     * Deep clone with type preservation
     */
    static clone(data: StvorData): StvorData;
    /**
     * Convert to JSON-safe format
     */
    static toJSON(data: StvorData): any;
}
/**
 * Helper function for quick encoding
 */
export declare function encodeData(data: StvorData): Buffer;
/**
 * Helper function for quick decoding
 */
export declare function decodeData(buffer: Buffer): StvorData;
/**
 * Helper for base64url encoding
 */
export declare function encodeToBase64Url(data: StvorData): string;
/**
 * Helper for base64url decoding
 */
export declare function decodeFromBase64Url(encoded: string): StvorData;
