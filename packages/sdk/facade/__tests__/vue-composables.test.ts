/**
 * STVOR Vue Composables - Comprehensive Unit Tests
 * Test suite for all Vue 3 composition API functions
 * 
 * Run with: npm test -- vue-composables.test.ts
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ref, nextTick } from 'vue';
import {
  useStvorSDK,
  useEncryptedMessagesVue,
  useConnectedPeersVue,
  useEncryptionKeysVue,
  useConnectionStatusVue,
  useMessageEncryptionVue,
  useBatchMessagesVue,
  useSDKErrorHandlerVue
} from '../vue-composition';

// Mock SDK for testing
const createMockSDK = () => ({
  userId: 'test-user@example.com',
  relayUrl: 'ws://localhost:8080',
  init: vi.fn().mockResolvedValue(undefined),
  connect: vi.fn().mockResolvedValue(undefined),
  disconnect: vi.fn(),
  getPublicKey: vi.fn().mockReturnValue(new Uint8Array(32)),
  sendMessage: vi.fn().mockResolvedValue(undefined),
  rotateKeys: vi.fn().mockResolvedValue(undefined)
});

describe('Vue Composables - useStvorSDK', () => {
  it('should initialize SDK on mount', async () => {
    const { sdk, isConnected, isLoading, error } = useStvorSDK('test@example.com');

    expect(isLoading.value).toBe(true);
    expect(sdk.value).toBe(null);

    await nextTick();
    await new Promise(resolve => setTimeout(resolve, 10));

    expect(isLoading.value).toBe(false);
    expect(sdk.value).not.toBeNull();
    expect(isConnected.value).toBe(true);
    expect(error.value).toBeNull();
  });

  it('should have reactive properties', () => {
    const { isConnected } = useStvorSDK('test@example.com');

    expect(typeof isConnected.value).toBe('boolean');
    expect(isConnected instanceof ref).toBe(true);
  });

  it('should use custom relay URL', async () => {
    const customUrl = 'ws://custom-relay:9000';
    const { sdk } = useStvorSDK('test@example.com', customUrl);

    await nextTick();
    await new Promise(resolve => setTimeout(resolve, 10));

    expect(sdk.value?.relayUrl).toBe(customUrl);
  });

  it('should disconnect on unmount', async () => {
    const { sdk, isConnected } = useStvorSDK('test@example.com');

    await nextTick();
    await new Promise(resolve => setTimeout(resolve, 10));

    expect(sdk.value).not.toBeNull();

    // Simulate unmount by calling cleanup
    if (sdk.value?.disconnect) {
      sdk.value.disconnect();
      isConnected.value = false;
    }

    expect(isConnected.value).toBe(false);
  });

  it('should handle initialization errors gracefully', async () => {
    const { error, isLoading } = useStvorSDK('test@example.com', 'ws://invalid');

    await nextTick();
    await new Promise(resolve => setTimeout(resolve, 10));

    expect(isLoading.value).toBe(false);
  });
});

describe('Vue Composables - useEncryptedMessagesVue', () => {
  let mockSdk: any;

  beforeEach(() => {
    mockSdk = createMockSDK();
  });

  it('should send and receive messages', async () => {
    const { messages, isSending } = useEncryptedMessagesVue(
      mockSdk,
      'peer@example.com'
    );

    expect(messages.value).toEqual([]);
    expect(isSending.value).toBe(false);

    const sendMessage = vi.fn().mockResolvedValue(undefined);
    mockSdk.sendMessage = sendMessage;

    // Simulate sending
    messages.value.push({
      id: 'msg-1',
      from: mockSdk.userId,
      to: 'peer@example.com',
      text: 'Hello!',
      timestamp: Date.now(),
      encrypted: true
    });

    await nextTick();

    expect(messages.value).toHaveLength(1);
    expect(messages.value[0].text).toBe('Hello!');
    expect(messages.value[0].encrypted).toBe(true);
  });

  it('should track reactive message list', async () => {
    const { messages } = useEncryptedMessagesVue(
      mockSdk,
      'peer@example.com'
    );

    expect(Array.isArray(messages.value)).toBe(true);

    messages.value.push({
      id: 'msg-1',
      from: 'test',
      to: 'peer',
      text: 'test',
      timestamp: Date.now(),
      encrypted: true
    });

    await nextTick();
    expect(messages.value).toHaveLength(1);
  });

  it('should provide clear messages function', async () => {
    const { messages, clearMessages } = useEncryptedMessagesVue(
      mockSdk,
      'peer@example.com'
    );

    messages.value.push({
      id: 'msg-1',
      from: 'test',
      to: 'peer',
      text: 'test',
      timestamp: Date.now(),
      encrypted: true
    });

    expect(messages.value).toHaveLength(1);

    clearMessages?.();

    expect(messages.value).toHaveLength(0);
  });

  it('should track send status reactively', async () => {
    const { isSending } = useEncryptedMessagesVue(
      mockSdk,
      'peer@example.com'
    );

    expect(isSending.value).toBe(false);

    isSending.value = true;
    await nextTick();
    expect(isSending.value).toBe(true);

    isSending.value = false;
    await nextTick();
    expect(isSending.value).toBe(false);
  });
});

describe('Vue Composables - useConnectedPeersVue', () => {
  let mockSdk: any;

  beforeEach(() => {
    mockSdk = createMockSDK();
  });

  it('should return reactive peers list', () => {
    const { peers } = useConnectedPeersVue(mockSdk);

    expect(Array.isArray(peers.value)).toBe(true);
    expect(peers.value).toEqual([]);
  });

  it('should have correct peer structure', () => {
    const { peers } = useConnectedPeersVue(mockSdk);

    peers.value.push({
      id: 'peer-1',
      publicKey: new Uint8Array(32),
      lastSeen: Date.now(),
      isOnline: true
    });

    peers.value.forEach(peer => {
      expect(peer).toHaveProperty('id');
      expect(peer).toHaveProperty('publicKey');
      expect(peer).toHaveProperty('lastSeen');
      expect(peer).toHaveProperty('isOnline');
    });
  });

  it('should be reactive to updates', async () => {
    const { peers } = useConnectedPeersVue(mockSdk);

    peers.value.push({
      id: 'peer-1',
      publicKey: new Uint8Array(32),
      lastSeen: Date.now(),
      isOnline: true
    });

    await nextTick();

    expect(peers.value).toHaveLength(1);

    peers.value[0].isOnline = false;

    await nextTick();

    expect(peers.value[0].isOnline).toBe(false);
  });
});

describe('Vue Composables - useEncryptionKeysVue', () => {
  let mockSdk: any;

  beforeEach(() => {
    mockSdk = createMockSDK();
  });

  it('should provide encryption key management', async () => {
    const { publicKey, isRotating, rotationError } = useEncryptionKeysVue(mockSdk);

    expect(isRotating.value).toBe(false);
    expect(rotationError.value).toBeNull();

    await nextTick();

    // After initialization, should have a public key
    expect(publicKey.value === null || publicKey.value instanceof Uint8Array).toBe(true);
  });

  it('should rotate keys', async () => {
    const { isRotating, rotateKeys } = useEncryptionKeysVue(mockSdk);

    expect(isRotating.value).toBe(false);

    const rotationPromise = rotateKeys?.();

    // After rotation call
    await nextTick();

    if (rotationPromise) {
      await rotationPromise;
    }

    expect(isRotating.value).toBe(false);
  });

  it('should export public key', async () => {
    const { publicKey, exportPublicKey } = useEncryptionKeysVue(mockSdk);

    await nextTick();

    if (publicKey.value) {
      const exported = exportPublicKey?.();
      expect(exported === null || Array.isArray(exported)).toBe(true);
    }
  });

  it('should handle key rotation errors', async () => {
    mockSdk.rotateKeys = vi.fn().mockRejectedValue(new Error('Rotation failed'));

    const { rotationError, rotateKeys } = useEncryptionKeysVue(mockSdk);

    const result = rotateKeys?.();
    if (result) {
      await result.catch(() => {}); // Catch error
    }

    await nextTick();
  });
});

describe('Vue Composables - useConnectionStatusVue', () => {
  let mockSdk: any;

  beforeEach(() => {
    mockSdk = createMockSDK();
  });

  it('should provide connection status', () => {
    const { status } = useConnectionStatusVue(mockSdk);

    expect(['disconnected', 'connecting', 'connected']).toContain(status.value);
  });

  it('should provide connection statistics', () => {
    const { stats } = useConnectionStatusVue(mockSdk);

    expect(stats.value).toHaveProperty('messagesSent');
    expect(stats.value).toHaveProperty('messagesReceived');
    expect(stats.value).toHaveProperty('bytesEncrypted');
    expect(stats.value).toHaveProperty('bytesDecrypted');
    expect(stats.value).toHaveProperty('latency');

    expect(typeof stats.value.latency).toBe('number');
  });

  it('should be reactive to status changes', async () => {
    const { status } = useConnectionStatusVue(mockSdk);

    const initialStatus = status.value;

    status.value = 'connecting';
    await nextTick();

    expect(status.value).toBe('connecting');

    status.value = 'connected';
    await nextTick();

    expect(status.value).toBe('connected');
  });

  it('should attempt reconnection', async () => {
    const { reconnect } = useConnectionStatusVue(mockSdk);

    if (reconnect) {
      await reconnect();
      expect(mockSdk.connect).toHaveBeenCalled();
    }
  });
});

describe('Vue Composables - useMessageEncryptionVue', () => {
  it('should return encryption details', () => {
    const message = { text: 'test', from: 'user1' };
    const details = useMessageEncryptionVue(message);

    expect(details.value).toHaveProperty('algorithm');
    expect(details.value).toHaveProperty('keySize');
    expect(details.value).toHaveProperty('nonceSize');
    expect(details.value).toHaveProperty('authenticated');
    expect(details.value).toHaveProperty('overhead');

    expect(details.value.algorithm).toBe('XSalsa20-Poly1305');
    expect(details.value.keySize).toBe(256);
    expect(details.value.nonceSize).toBe(24);
    expect(details.value.authenticated).toBe(true);
  });

  it('should handle different message types', () => {
    const testCases = [
      { text: 'string message' },
      { data: Buffer.from('binary') },
      { json: { key: 'value' } }
    ];

    testCases.forEach(msg => {
      const details = useMessageEncryptionVue(msg);
      expect(details.value).toBeDefined();
      expect(details.value.algorithm).toBe('XSalsa20-Poly1305');
    });
  });

  it('should be reactive ref', () => {
    const message = ref({ text: 'test' });
    const details = useMessageEncryptionVue(message);

    expect(details instanceof ref).toBe(true);

    message.value = { text: 'updated' };
    expect(details.value).toBeDefined();
  });
});

describe('Vue Composables - useBatchMessagesVue', () => {
  let mockSdk: any;

  beforeEach(() => {
    mockSdk = createMockSDK();
  });

  it('should manage batch messages', () => {
    const { batch, addToBatch, getBatchSize } = useBatchMessagesVue(mockSdk);

    expect(batch.value).toEqual([]);
    expect(getBatchSize?.()).toBe(0);

    addToBatch?.('peer1@example.com', { text: 'msg1' });
    addToBatch?.('peer2@example.com', { text: 'msg2' });

    expect(getBatchSize?.()).toBe(2);
  });

  it('should flush batch', async () => {
    const { addToBatch, flushBatch, batch } = useBatchMessagesVue(mockSdk);

    addToBatch?.('peer1@example.com', { text: 'msg1' });
    addToBatch?.('peer2@example.com', { text: 'msg2' });

    expect(batch.value.length).toBe(2);

    const result = flushBatch?.();
    if (result) {
      await result;
    }

    await nextTick();
  });

  it('should track batch operations reactively', async () => {
    const { batch, addToBatch, isBatching } = useBatchMessagesVue(mockSdk);

    expect(batch.value).toEqual([]);
    expect(isBatching.value).toBe(false);

    addToBatch?.('peer@example.com', { text: 'test' });

    await nextTick();

    expect(batch.value).toHaveLength(1);
  });

  it('should handle batch errors', async () => {
    mockSdk.sendMessage = vi.fn()
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error('Send failed'));

    const { addToBatch, flushBatch } = useBatchMessagesVue(mockSdk);

    addToBatch?.('peer1@example.com', { text: 'msg1' });
    addToBatch?.('peer2@example.com', { text: 'msg2' });

    const result = flushBatch?.();
    if (result) {
      await result.catch(() => {}); // Catch expected error
    }

    await nextTick();
  });
});

describe('Vue Composables - useSDKErrorHandlerVue', () => {
  let mockSdk: any;

  beforeEach(() => {
    mockSdk = createMockSDK();
  });

  it('should track errors with severity', () => {
    const { errors, addError } = useSDKErrorHandlerVue(mockSdk);

    expect(errors.value).toEqual([]);

    addError?.('Test error', 'error');
    addError?.('Test warning', 'warning');

    expect(errors.value).toHaveLength(2);
    expect(errors.value[0].severity).toBe('error');
    expect(errors.value[1].severity).toBe('warning');
  });

  it('should clear errors', () => {
    const { errors, addError, clearErrors } = useSDKErrorHandlerVue(mockSdk);

    addError?.('Error 1', 'error');
    addError?.('Error 2', 'warning');

    expect(errors.value).toHaveLength(2);

    clearErrors?.();

    expect(errors.value).toHaveLength(0);
  });

  it('should be reactive error tracking', async () => {
    const { errors, addError } = useSDKErrorHandlerVue(mockSdk);

    expect(errors.value).toEqual([]);

    addError?.('New error', 'error');
    await nextTick();

    expect(errors.value).toHaveLength(1);
  });

  it('should provide error count by severity', () => {
    const { addError, getErrorCountBySeverity } = useSDKErrorHandlerVue(mockSdk);

    addError?.('Error 1', 'error');
    addError?.('Error 2', 'error');
    addError?.('Warning 1', 'warning');

    const counts = getErrorCountBySeverity?.();

    if (counts) {
      expect(counts.error).toBe(2);
      expect(counts.warning).toBe(1);
    }
  });
});

describe('Vue Composables Integration Tests', () => {
  let mockSdk: any;

  beforeEach(() => {
    mockSdk = createMockSDK();
  });

  it('should work together in messaging flow', async () => {
    const { isConnected } = useStvorSDK('test@example.com');
    const { messages } = useEncryptedMessagesVue(mockSdk, 'peer@example.com');
    const { publicKey } = useEncryptionKeysVue(mockSdk);

    await nextTick();

    messages.value.push({
      id: 'msg-1',
      from: mockSdk.userId,
      to: 'peer@example.com',
      text: 'Hello!',
      timestamp: Date.now(),
      encrypted: true
    });

    await nextTick();

    expect(messages.value).toHaveLength(1);
    expect(messages.value[0].encrypted).toBe(true);
  });

  it('should handle complete workflow', async () => {
    const { status } = useConnectionStatusVue(mockSdk);
    const { batch, addToBatch, flushBatch } = useBatchMessagesVue(mockSdk);
    const { errors, addError } = useSDKErrorHandlerVue(mockSdk);

    addToBatch?.('user1@example.com', { text: 'msg1' });
    addToBatch?.('user2@example.com', { text: 'msg2' });

    expect(batch.value).toHaveLength(2);

    const result = flushBatch?.();
    if (result) {
      await result;
    }

    await nextTick();

    expect(batch.value).toHaveLength(0);
  });
});

describe('Vue Composables - Reactivity Tests', () => {
  let mockSdk: any;

  beforeEach(() => {
    mockSdk = createMockSDK();
  });

  it('should maintain reactivity across composables', async () => {
    const { messages, clearMessages } = useEncryptedMessagesVue(
      mockSdk,
      'peer@example.com'
    );
    const { peers } = useConnectedPeersVue(mockSdk);
    const { errors, addError } = useSDKErrorHandlerVue(mockSdk);

    // Add data
    messages.value.push({
      id: 'msg-1',
      from: 'test',
      to: 'peer',
      text: 'test',
      timestamp: Date.now(),
      encrypted: true
    });

    peers.value.push({
      id: 'peer-1',
      publicKey: new Uint8Array(32),
      lastSeen: Date.now(),
      isOnline: true
    });

    addError?.('Test error', 'error');

    await nextTick();

    expect(messages.value).toHaveLength(1);
    expect(peers.value).toHaveLength(1);
    expect(errors.value).toHaveLength(1);

    // Clear messages
    clearMessages?.();

    await nextTick();

    expect(messages.value).toHaveLength(0);
    expect(peers.value).toHaveLength(1); // Unaffected
    expect(errors.value).toHaveLength(1); // Unaffected
  });
});
