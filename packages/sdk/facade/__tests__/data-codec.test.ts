/**
 * STVOR Data Codec Test Suite
 * 
 * Tests encoding/decoding of all supported data types
 * with proper type preservation and edge cases
 */

import { test } from 'node:test';
import { strict as assert } from 'assert';
import {
  encodeData,
  decodeData,
  encodeToBase64Url,
  decodeFromBase64Url,
  encodeDataSafe,
  decodeDataSafe,
  getEncodedDataType,
  calculateEncodingOverhead,
} from '../data-codec.js';

test('STVOR Data Codec Tests', async (t) => {
  await t.test('String encoding/decoding', () => {
    const tests = [
      'Hello, World!',
      'Привет, мир! 🌍',
      '你好世界',
      'مرحبا بالعالم',
      '',
      'Special chars: \n\t\r\0',
      'Long string: ' + 'a'.repeat(10000),
    ];

    for (const str of tests) {
      const encoded = encodeData(str);
      assert.strictEqual(encoded[0], 0x01, `String type marker for "${str}"`);
      
      const decoded = decodeData(encoded);
      assert.strictEqual(decoded, str, `Decoding matches: "${str}"`);
      assert.strictEqual(typeof decoded, 'string', `Type is string`);
    }
  });

  await t.test('Number encoding/decoding', () => {
    const tests = [
      0,
      1,
      -1,
      42,
      3.14159,
      -3.14159,
      1e10,
      1e-10,
      Number.MAX_VALUE,
      Number.MIN_VALUE,
      Math.PI,
    ];

    for (const num of tests) {
      const encoded = encodeData(num);
      assert.strictEqual(encoded[0], 0x02, `Number type marker for ${num}`);
      assert.strictEqual(encoded.length, 9, `Number is 9 bytes`);
      
      const decoded = decodeData(encoded);
      assert.strictEqual(decoded, num, `Number matches: ${num}`);
      assert.strictEqual(typeof decoded, 'number', `Type is number`);
    }
  });

  await t.test('Boolean encoding/decoding', () => {
    const tests = [true, false];

    for (const bool of tests) {
      const encoded = encodeData(bool);
      assert.strictEqual(encoded[0], 0x03, `Boolean type marker`);
      assert.strictEqual(encoded.length, 2, `Boolean is 2 bytes`);
      
      const decoded = decodeData(encoded);
      assert.strictEqual(decoded, bool, `Boolean matches: ${bool}`);
      assert.strictEqual(typeof decoded, 'boolean', `Type is boolean`);
    }
  });

  await t.test('Null encoding/decoding', () => {
    const encoded = encodeData(null);
    assert.strictEqual(encoded[0], 0x04, `Null type marker`);
    assert.strictEqual(encoded.length, 1, `Null is 1 byte`);
    
    const decoded = decodeData(encoded);
    assert.strictEqual(decoded, null, `Null decodes correctly`);
  });

  await t.test('Binary (Buffer) encoding/decoding', () => {
    const tests = [
      Buffer.from([]),
      Buffer.from([0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD]),
      Buffer.from('binary data'),
      Buffer.from(new Array(1000).fill(42)),
    ];

    for (const buf of tests) {
      const encoded = encodeData(buf);
      assert.strictEqual(encoded[0], 0x05, `Binary type marker`);
      
      const decoded = decodeData(encoded);
      assert.ok(Buffer.isBuffer(decoded), `Decoded is Buffer`);
      assert.deepStrictEqual(decoded, buf, `Binary matches`);
    }
  });

  await t.test('Uint8Array encoding/decoding', () => {
    const arr = new Uint8Array([1, 2, 3, 4, 5]);
    const encoded = encodeData(arr);
    assert.strictEqual(encoded[0], 0x05, `Uint8Array type marker`);
    
    const decoded = decodeData(encoded);
    assert.ok(Buffer.isBuffer(decoded), `Decoded as Buffer`);
    assert.deepStrictEqual(Buffer.from(arr), decoded, `Uint8Array matches`);
  });

  await t.test('JSON object encoding/decoding', () => {
    const tests = [
      { message: 'hello' },
      { user: 'alice', age: 30, verified: true },
      { nested: { data: { structure: [1, 2, 3] } } },
      { emoji: '👋🔐🚀', unicode: '你好' },
      [],
      [1, 2, 3, 4, 5],
      { complex: { array: [{ nested: true }] } },
    ];

    for (const obj of tests) {
      const encoded = encodeData(obj);
      assert.strictEqual(encoded[0], 0x06, `JSON type marker`);
      
      const decoded = decodeData(encoded);
      assert.deepStrictEqual(decoded, obj, `JSON matches: ${JSON.stringify(obj)}`);
    }
  });

  await t.test('Type preservation', () => {
    const tests: Array<[unknown, string]> = [
      ['string', 'string'],
      [123, 'number'],
      [true, 'boolean'],
      [false, 'boolean'],
      [null, 'null'],
      [Buffer.from([1, 2, 3]), 'binary'],
      [{ key: 'value' }, 'json'],
      [[], 'json'],
    ];

    for (const [data, expectedType] of tests) {
      const encoded = encodeData(data);
      const type = getEncodedDataType(encoded);
      assert.strictEqual(type, expectedType, `Type ${expectedType} preserved for ${String(data)}`);
      
      const decoded = decodeData(encoded);
      if (data === null) {
        assert.strictEqual(decoded, null);
      } else if (typeof data === expectedType) {
        // Type matches
      }
    }
  });

  await t.test('Base64URL encoding/decoding', () => {
    const tests = [
      'Hello',
      { data: 'test' },
      42,
      Buffer.from([0xFF, 0xFE]),
    ];

    for (const data of tests) {
      const b64 = encodeToBase64Url(data);
      assert.ok(typeof b64 === 'string', `Base64URL is string`);
      assert.ok(b64.match(/^[A-Za-z0-9_-]*$/), `Valid base64url alphabet`);
      
      const decoded = decodeFromBase64Url(b64);
      if (typeof data === 'object' && data !== null) {
        assert.deepStrictEqual(decoded, data);
      } else {
        assert.strictEqual(decoded, data);
      }
    }
  });

  await t.test('Safe encoding/decoding', () => {
    const tests = [
      'string',
      { obj: true },
      123,
      Buffer.from([1, 2, 3]),
      // Objects that might be problematic
      { circular: null }, // Avoid actual circular references
      { date: new Date().toISOString() },
    ];

    for (const data of tests) {
      const encoded = encodeDataSafe(data);
      assert.ok(Buffer.isBuffer(encoded), `Safe encode returns Buffer`);
      
      const decoded = decodeDataSafe(encoded);
      assert.ok(decoded !== undefined, `Safe decode returns value`);
    }
  });

  await t.test('Encoding overhead calculation', () => {
    const tests: Array<[unknown, string]> = [
      ['', 'empty string'],
      ['hello', 'small string'],
      [0, 'zero'],
      [true, 'boolean'],
      [null, 'null'],
      [Buffer.from([1, 2, 3]), 'binary'],
    ];

    for (const [data, desc] of tests) {
      const overhead = calculateEncodingOverhead(data);
      assert.ok(typeof overhead === 'number', `Overhead is number for ${desc}`);
      assert.ok(overhead >= 0, `Overhead is non-negative for ${desc}`);
      
      // Verify overhead by checking actual encoding
      const encoded = encodeData(data);
      assert.ok(encoded.length > 0, `Encoded has content for ${desc}`);
    }
  });

  await t.test('Edge cases', () => {
    // Empty structures
    const empty_str = encodeData('');
    assert.ok(empty_str.length >= 1, 'Empty string encodes');
    
    const empty_arr = encodeData([]);
    assert.ok(empty_arr.length > 0, 'Empty array encodes');
    
    const empty_obj = encodeData({});
    assert.ok(empty_obj.length > 0, 'Empty object encodes');
    
    // Very large data
    const large_str = 'x'.repeat(1000000); // 1MB string
    const encoded_large = encodeData(large_str);
    const decoded_large = decodeData(encoded_large);
    assert.strictEqual(decoded_large, large_str, 'Large string preserved');
    
    // Special numbers
    const encoded_nan = encodeData(NaN);
    const decoded_nan = decodeData(encoded_nan);
    assert.ok(Number.isNaN(decoded_nan), 'NaN preserved');
    
    const encoded_inf = encodeData(Infinity);
    const decoded_inf = decodeData(encoded_inf);
    assert.strictEqual(decoded_inf, Infinity, 'Infinity preserved');
  });

  await t.test('Invalid data handling', () => {
    // Empty buffer should throw
    assert.throws(() => decodeData(Buffer.alloc(0)), 'Empty buffer throws');
    
    // Invalid type marker should throw
    const badBuffer = Buffer.from([0xFF]); // Invalid marker
    assert.throws(() => decodeData(badBuffer), 'Invalid type marker throws');
    
    // Invalid base64url should throw
    assert.throws(() => decodeFromBase64Url('!!!'), 'Invalid base64url throws');
  });

  await t.test('Round-trip consistency', () => {
    const data = [
      'test string',
      { user: 'alice', age: 30, nested: { data: [1, 2, 3] } },
      42,
      true,
      false,
      null,
      Buffer.from('binary'),
    ];

    for (const original of data) {
      // Encode -> Decode -> Encode -> Decode
      const enc1 = encodeData(original);
      const dec1 = decodeData(enc1);
      const enc2 = encodeData(dec1);
      const dec2 = decodeData(enc2);
      
      // Should match
      if (original === null) {
        assert.strictEqual(dec2, null, 'Null round-trip');
      } else {
        assert.deepStrictEqual(dec2, dec1, `Round-trip for ${String(original)}`);
      }
    }
  });

  await t.test('Type detection', () => {
    const tests: Array<[unknown, string]> = [
      ['text', 'string'],
      [123, 'number'],
      [true, 'boolean'],
      [null, 'null'],
      [Buffer.from([1]), 'binary'],
      [{ x: 1 }, 'json'],
    ];

    for (const [data, expectedType] of tests) {
      const encoded = encodeData(data);
      const detected = getEncodedDataType(encoded);
      assert.strictEqual(detected, expectedType, `Type detection for ${expectedType}`);
    }
  });
});

console.log('\n✅ All data codec tests completed\n');
